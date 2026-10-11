"""MCP consent 会话：Agent 调用前的授权闸门。

设计目标：让 MCP server 在「用户显式授权」之前什么都做不了。授权是**一次性
落盘**的会话，包含三样东西：

* **目标白名单** —— 允许操作哪些进程（PID 列表 或 进程名通配符）；
* **能力分档** —— 允许哪些类别的操作（``read`` / ``write`` / ``dangerous``）；
* **过期时间** —— 默认 30 分钟，超时视为无效，需重新授权。

安全模型的边界（写清楚避免误解）：

* 这**不是**密钥级防护。签名只是「防手改」—— 拿 ``platform.node()`` + 用户名
  算一个机器盐，对会话内容做 SHA256，文件被人手工编辑字段后签名对不上，
  于是 ``is_valid`` 返回 False。**不引密钥管理、不做加密、不做反调试**。
* 会话文件是明文 JSON（``%LOCALAPPDATA%/SuperInject/mcp_consent.json``，
  非 Windows 是 ``~/.local/share/SuperInject/mcp_consent.json``）。能读写
  该文件的人本来就能起同权限的进程，所以加密只会带来「以为自己安全」的错觉。
* 项目定位是「开发调试工具」不是「安全产品」，这条边界在 SECURITY.md 里也写明。

依赖：仅标准库（hashlib / json / hmac / platform / fnmatch / time / pathlib）。
"""

from __future__ import annotations

import fnmatch
import getpass
import hashlib
import hmac
import json
import os
import platform
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set

# 能力分档：read 自动放行；write / dangerous 需要用户勾选。
CAPABILITIES = ("read", "write", "dangerous")

# 默认会话有效期（秒）。
DEFAULT_TTL_SECONDS = 30 * 60

_WEB_DIR = Path(__file__).resolve().parent / "web"


class ConsentError(RuntimeError):
    """consent 配置解析 / 校验失败。调用方负责转成用户可读的错误。"""


# --------------------------------------------------------------------------- 路径


def consent_path() -> Path:
    """consent 会话文件的落盘路径。

    * ``SUPERINJECT_CONSENT_PATH`` 环境变量优先（测试与自定义部署用）；
    * Windows：``%LOCALAPPDATA%\\SuperInject\\mcp_consent.json``（缺省回退
      ``~/AppData/Local``）；
    * 非 Windows：``~/.local/share/SuperInject/mcp_consent.json``。
    """
    override = os.environ.get("SUPERINJECT_CONSENT_PATH", "").strip()
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA", "").strip()
        if not base:
            base = str(Path.home() / "AppData" / "Local")
        return Path(base) / "SuperInject" / "mcp_consent.json"
    return Path.home() / ".local" / "share" / "SuperInject" / "mcp_consent.json"


def consent_html_path() -> Path:
    """独立 consent 页面（GUI 模态框用，P5 接线）。"""
    return _WEB_DIR / "consent.html"


# --------------------------------------------------------------------------- 签名


def _machine_salt() -> str:
    """机器 + 用户指纹，作为签名盐。**不是密钥**，只防手改。"""
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - 极端环境无用户名
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    return f"{platform.node()}::{user}"


def _sign_payload(payload: Dict[str, Any]) -> str:
    """对规范化 payload 做 SHA256（机器盐拼接），返回 hex。"""
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))
    material = blob + "::" + _machine_salt()
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _canonical_payload(pid_allowlist: Iterable[int], name_glob: Iterable[str],
                       capabilities: Iterable[str], created_at: float,
                       expires_at: float) -> Dict[str, Any]:
    """签名 / 存盘用的规范化字典（集合排好序，保证确定性）。"""
    return {
        "pid_allowlist": sorted(int(p) for p in pid_allowlist),
        "name_glob": [str(g) for g in name_glob],
        "capabilities": sorted(str(c) for c in capabilities),
        "created_at": float(created_at),
        "expires_at": float(expires_at),
    }


# --------------------------------------------------------------------------- 数据类


@dataclass
class ConsentSession:
    """一次 MCP 授权会话。

    * ``pid_allowlist``：允许的 PID 白名单；空集合表示「不靠 PID 限定」，
      改由 ``name_glob`` 判定。两者都空 = 任何目标都不放行（安全默认）。
    * ``name_glob``：进程名通配符白名单，如 ``["notepad*", "mytool.exe"]``，
      大小写不敏感匹配。
    * ``capabilities``：授权的能力分档，取值来自 :data:`CAPABILITIES`。
    * ``created_at`` / ``expires_at``：Unix 秒。
    * ``signature``：机器盐 + 内容 的 SHA256，防手改。
    """

    pid_allowlist: Set[int] = field(default_factory=set)
    name_glob: List[str] = field(default_factory=list)
    capabilities: Set[str] = field(default_factory=set)
    created_at: float = 0.0
    expires_at: float = 0.0
    signature: str = ""

    # ---------------------------------------------------------------- 序列化

    def to_dict(self) -> Dict[str, Any]:
        data = _canonical_payload(self.pid_allowlist, self.name_glob,
                                  self.capabilities, self.created_at,
                                  self.expires_at)
        data["version"] = 1
        data["signature"] = self.signature
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConsentSession":
        return cls(
            pid_allowlist={int(p) for p in (data.get("pid_allowlist") or [])},
            name_glob=[str(g) for g in (data.get("name_glob") or [])],
            capabilities={str(c) for c in (data.get("capabilities") or [])},
            created_at=float(data.get("created_at") or 0.0),
            expires_at=float(data.get("expires_at") or 0.0),
            signature=str(data.get("signature") or ""),
        )

    # ---------------------------------------------------------------- 签名

    def compute_signature(self) -> str:
        return _sign_payload(_canonical_payload(
            self.pid_allowlist, self.name_glob, self.capabilities,
            self.created_at, self.expires_at))

    def sign(self) -> "ConsentSession":
        """按当前字段重算并写入签名，返回自身（便于链式）。"""
        self.signature = self.compute_signature()
        return self

    def targets_summary(self) -> str:
        """人类可读的目标白名单摘要（CLI / 前端提示用）。"""
        pids = ",".join(str(p) for p in sorted(self.pid_allowlist)) or "-"
        names = ",".join(self.name_glob) or "-"
        caps = ",".join(sorted(self.capabilities)) or "-"
        return f"pids={pids} names={names} capabilities={caps}"


# --------------------------------------------------------------------------- 构造


def _coerce_pids(value: Any) -> Set[int]:
    """把 ``"1234,5678"`` / ``[1234, 5678]`` / 单值 归一成 int 集合。"""
    out: Set[int] = set()
    if value is None:
        return out
    if isinstance(value, (list, tuple, set)):
        chunks = list(value)
    else:
        chunks = str(value).split(",")
    for chunk in chunks:
        text = str(chunk).strip()
        if not text:
            continue
        try:
            out.add(int(text, 0))
        except ValueError as exc:
            raise ConsentError(f"无效 PID: {text!r}") from exc
    return out


def _coerce_names(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        chunks = [str(v) for v in value]
    else:
        chunks = str(value).split(",")
    return [c.strip() for c in chunks if c.strip()]


def _coerce_capabilities(value: Any) -> Set[str]:
    if value is None:
        raise ConsentError("缺少 capabilities（至少需要一项）")
    if isinstance(value, str):
        chunks = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        chunks = list(value)
    else:
        raise ConsentError(f"无法解析 capabilities: {value!r}")
    out: Set[str] = set()
    for chunk in chunks:
        cap = str(chunk).strip().lower()
        if not cap:
            continue
        if cap not in CAPABILITIES:
            raise ConsentError(f"未知能力分档: {cap!r}（可选 {CAPABILITIES}）")
        out.add(cap)
    if not out:
        raise ConsentError("capabilities 至少需要一项")
    return out


def build_session(pids: Any = None, names: Any = None,
                  capabilities: Any = None, ttl: Optional[float] = None,
                  now: Optional[float] = None) -> ConsentSession:
    """从原始输入构造并签名一个 ConsentSession。"""
    now = time.time() if now is None else float(now)
    ttl = DEFAULT_TTL_SECONDS if ttl is None else float(ttl)
    session = ConsentSession(
        pid_allowlist=_coerce_pids(pids),
        name_glob=_coerce_names(names),
        capabilities=_coerce_capabilities(capabilities),
        created_at=now,
        expires_at=now + ttl,
        signature="",
    )
    return session.sign()


# --------------------------------------------------------------------------- 校验


def is_valid(session: Optional[ConsentSession],
             now: Optional[float] = None) -> bool:
    """会话是否仍有效：未过期 **且** 签名对得上。"""
    if session is None:
        return False
    if not session.signature:
        return False
    now = time.time() if now is None else float(now)
    if now >= float(session.expires_at):
        return False
    expected = session.compute_signature()
    return hmac.compare_digest(expected, session.signature)


def check_target(session: Optional[ConsentSession], pid: Any,
                 proc_name: str = "") -> bool:
    """目标进程是否在白名单内。

    PID 命中 ``pid_allowlist``，或进程名命中任一 ``name_glob``（大小写不敏感），
    即放行。两者都空 → 一律拒绝（安全默认，避免「无授权即全放行」）。
    """
    if session is None:
        return False
    try:
        pid_i = int(pid)
    except (TypeError, ValueError):
        pid_i = 0
    if pid_i and pid_i in session.pid_allowlist:
        return True
    name = (proc_name or "").strip().lower()
    if name:
        for pattern in session.name_glob:
            if fnmatch.fnmatch(name, str(pattern).lower()):
                return True
    return False


def check_capability(session: Optional[ConsentSession], capability: str) -> bool:
    """会话是否授权了某个能力分档。"""
    if session is None:
        return False
    return str(capability) in session.capabilities


# --------------------------------------------------------------------------- 落盘


def load_consent(path: Optional[os.PathLike | str] = None
                 ) -> Optional[ConsentSession]:
    """读会话文件；缺失 / 损坏 / 结构不对一律返回 ``None``（不抛）。"""
    target = Path(path) if path else consent_path()
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    # 「结构不对就拒绝」不能只靠 from_dict 抛异常 —— 它对每个字段都用
    # ``data.get(...) or 默认值``，任何 dict 都能构造出一个空 session，
    # 于是调用方拿到一个 non-None 却毫无授权的对象。这里显式要求两个
    # 「没有就不算授权」的键存在。
    if "capabilities" not in data or "signature" not in data:
        return None
    try:
        return ConsentSession.from_dict(data)
    except (TypeError, ValueError, KeyError):
        return None


def save_consent(session: ConsentSession,
                 path: Optional[os.PathLike | str] = None) -> Path:
    """原子写会话文件（先写临时再 ``os.replace``），返回落盘路径。"""
    target = Path(path) if path else consent_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    session.sign()
    tmp = target.with_name(target.name + f".tmp{os.getpid()}")
    tmp.write_text(json.dumps(session.to_dict(), ensure_ascii=False, indent=2),
                   encoding="utf-8")
    os.replace(tmp, target)
    return target


# --------------------------------------------------------------------------- CLI 授权


def request_consent_cli(stream_in: Any,
                        ttl: Optional[float] = None) -> ConsentSession:
    """从 ``stream_in`` **一次性**读完整份授权配置，构造并签名会话。

    格式（首行必须是大写 ``YES`` 才算确认）::

        YES
        pids=1234,5678
        names=notepad*,mytool.exe
        capabilities=read,write

    规则：

    * 不做交互式 prompt 循环 —— 直接把 ``stream_in`` 读到 EOF 再解析；
    * 首行非 ``YES`` → :class:`ConsentError`；
    * 缺 ``capabilities`` / 未知字段 / 无法解析的 PID → :class:`ConsentError`。
    """
    data = stream_in.read() if hasattr(stream_in, "read") else stream_in
    lines = [ln.strip() for ln in str(data or "").splitlines() if ln.strip()]
    if not lines:
        raise ConsentError("consent 配置为空")
    if lines[0] != "YES":
        raise ConsentError("首行必须是 YES 以确认授权")

    values: Dict[str, str] = {}
    for line in lines[1:]:
        if "=" not in line:
            raise ConsentError(f"无法解析的行: {line!r}（应为 key=value）")
        key, _, val = line.partition("=")
        key = key.strip().lower()
        if key not in {"pids", "names", "capabilities"}:
            raise ConsentError(f"未知字段: {key!r}（可用 pids/names/capabilities）")
        values[key] = val.strip()

    if "capabilities" not in values:
        raise ConsentError("缺少 capabilities 行")
    return build_session(
        pids=values.get("pids", ""),
        names=values.get("names", ""),
        capabilities=values["capabilities"],
        ttl=ttl,
    )


# --------------------------------------------------------------------------- GUI 授权


def request_consent_gui(parent: Any = None,
                        existing: Optional[ConsentSession] = None
                        ) -> Optional[ConsentSession]:
    """GUI 场景的授权入口。

    真正的弹窗在 P5 接线：``superinject/web/consent.html`` 是一份独立页面，
    主窗口以模态框形式加载它；用户在页面里勾选后，前端调
    ``window.pywebview.api.submit_consent(payload)`` 把配置回传，由
    :func:`superinject.gui.Api.submit_consent` 构造并落盘会话。

    本函数负责「先看有没有有效会话」这一步：

    * ``existing`` 仍有效 → 直接返回，不弹窗；
    * 否则，若给了 ``parent``（pywebview 窗口）→ 触发前端打开模态框，并
      返回 ``None``（会话由 ``submit_consent`` 异步产生）；
    * 没有任何可取到的会话 → 返回 ``None``。
    """
    if existing is not None and is_valid(existing):
        return existing
    if parent is not None:
        _open_consent_modal(parent)
    return None


def _open_consent_modal(parent: Any) -> None:
    """尽力让前端打开 consent 模态框；任何异常都吞掉（GUI 是可选路径）。"""
    script = ("window.SIConsent && window.SIConsent.open && "
              "window.SIConsent.open();")
    try:
        parent.evaluate_js(script)
    except Exception:  # pragma: no cover - 窗口/桥不可用
        pass


def session_from_form(payload: Dict[str, Any],
                      ttl: Optional[float] = None) -> ConsentSession:
    """把前端 ``submit_consent`` 回传的表单字典转成已签名会话。"""
    if not isinstance(payload, dict):
        raise ConsentError("consent 表单必须是对象")
    ttl_value = payload.get("ttl_seconds", ttl)
    return build_session(
        pids=payload.get("pids", ""),
        names=payload.get("names", payload.get("name_glob", "")),
        capabilities=payload.get("capabilities", []),
        ttl=ttl_value,
    )
