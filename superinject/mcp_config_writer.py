"""一键把 SuperInject 的 MCP 条目写进 Agent 端配置文件（v1.3.0 P7）。

给谁用：GUI 的「写入 Agent 配置」按钮。用户点确认后，把
``mcpServers.superinject`` 写进 Claude Desktop / Cursor 的配置文件。

硬约束（违反就是数据事故）：

* **合并，不覆盖** —— 只改 ``mcpServers.superinject`` 这一个键，其余键
  （含别人的 ``mcpServers`` 条目）原样保留。
* **写前备份** —— 已有文件先 ``copy2`` 成 ``<名字>.bak-<时间戳>``，路径回给调用方。
* **原子写** —— 临时文件 + ``os.replace``（同
  :func:`superinject.mcp_consent.save_consent`）。
* **坏 JSON 不动原文件** —— 解析失败 / 顶层非对象 / ``mcpServers`` 非对象，
  一律报错返回，绝不覆盖。
* **幂等** —— 内容完全一致 → ``action="unchanged"``，不写、不备份。
* **不静默** —— 本模块只提供能力；写动作只能由用户在 GUI 里点确认后触发，
  没有任何「启动时自动写」的路径。

路径探测只在**调用时**读环境变量（``HOME`` / ``USERPROFILE`` / ``APPDATA`` 或
``SUPERINJECT_CLAUDE_DIR`` / ``SUPERINJECT_CURSOR_DIR`` 覆盖），因此测试可以用
``monkeypatch`` 把目标目录指到 ``tmp_path``，跨平台可跑。

依赖：仅标准库（json / os / shutil / sys / time / pathlib）。条目的
``command`` / ``args`` 复用 :func:`superinject.cli.mcp_config_snippet`，
不重复一套「打包 vs 源码」的判定。
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# 我们的键名：mcpServers.<ENTRY_KEY>
ENTRY_KEY = "superinject"

_CLAUDE_FILENAME = "claude_desktop_config.json"
_CURSOR_FILENAME = "mcp.json"


# --------------------------------------------------------------------------- 路径


def _claude_dir() -> Path:
    """Claude Desktop 配置目录。

    * ``SUPERINJECT_CLAUDE_DIR`` 环境变量优先（测试 / 自定义部署）；
    * Windows：``%APPDATA%\\Claude``（缺 ``APPDATA`` 回退 ``~/AppData/Roaming``）；
    * macOS：``~/Library/Application Support/Claude``；
    * 其他：``~/.config/Claude``。
    """
    override = os.environ.get("SUPERINJECT_CLAUDE_DIR", "").strip()
    if override:
        return Path(override)
    if os.name == "nt":
        base = os.environ.get("APPDATA", "").strip()
        if not base:
            base = str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "Claude"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Claude"
    return Path.home() / ".config" / "Claude"


def _cursor_dir() -> Path:
    """Cursor 配置目录（``SUPERINJECT_CURSOR_DIR`` 可覆盖，默认 ``~/.cursor``）。"""
    override = os.environ.get("SUPERINJECT_CURSOR_DIR", "").strip()
    if override:
        return Path(override)
    return Path.home() / ".cursor"


def claude_config_path() -> Path:
    """Claude Desktop 配置文件完整路径。"""
    return _claude_dir() / _CLAUDE_FILENAME


def cursor_config_path() -> Path:
    """Cursor MCP 配置文件完整路径。"""
    return _cursor_dir() / _CURSOR_FILENAME


_TARGETS: List[Dict[str, Any]] = [
    {"id": "claude-desktop", "label": "Claude Desktop",
     "path_fn": claude_config_path},
    {"id": "cursor", "label": "Cursor", "path_fn": cursor_config_path},
]


def _target_by_id(target_id: str) -> Optional[Dict[str, Any]]:
    for spec in _TARGETS:
        if spec["id"] == target_id:
            return spec
    return None


# --------------------------------------------------------------------------- 探测


def targets() -> List[Dict[str, Any]]:
    """列出可写入的 Agent 目标：``[{id, label, path, exists}]``。

    **只探测、不创建任何目录** —— ``exists`` 表示「配置文件是否已存在」，
    不代表 Agent 是否安装。文件/目录不存在时不报错，只是 ``exists=False``。
    """
    out: List[Dict[str, Any]] = []
    for spec in _TARGETS:
        path = Path(spec["path_fn"]())
        out.append({
            "id": spec["id"],
            "label": spec["label"],
            "path": str(path),
            "exists": path.exists(),
        })
    return out


# --------------------------------------------------------------------------- 条目


def _superinject_entry(mode: str = "launcher",
                       launcher_path: Optional[str] = None) -> Dict[str, Any]:
    """构造 ``mcpServers.superinject`` 条目（复用 cli 的配置片段生成）。"""
    from .cli import mcp_config_snippet

    text = mcp_config_snippet(
        launcher_path, mode="direct" if mode == "direct" else "launcher")
    data = json.loads(text)
    return data["mcpServers"][ENTRY_KEY]


# --------------------------------------------------------------------------- 读写


def _load_existing(
        path: Path) -> tuple[dict[str, Any] | None, str | None]:
    """读现有配置，返回 ``(data, error)``。

    * 文件不存在 → ``({}, None)``；
    * 空文件 → ``({}, None)``（当作空对象继续合并）；
    * 坏 JSON / 顶层非对象 → ``(None, 错误串)``（调用方据此中止，不动原文件）。
    """
    if not path.exists():
        return {}, None
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"读取现有配置失败: {exc}"
    if not raw.strip():
        return {}, None
    try:
        data = json.loads(raw)
    except ValueError as exc:
        return None, f"现有配置不是合法 JSON（{exc}）；已中止，未改动原文件"
    if not isinstance(data, dict):
        return None, "现有配置顶层不是 JSON 对象；已中止，未改动原文件"
    return data, None


def _backup_path(path: Path) -> Path:
    """``<名字>.bak-<时间戳>``；同名已存在时加序号，避免覆盖旧备份。"""
    stamp = time.strftime("%Y%m%d-%H%M%S")
    candidate = path.with_name(f"{path.name}.bak-{stamp}")
    seq = 1
    while candidate.exists():
        candidate = path.with_name(f"{path.name}.bak-{stamp}-{seq}")
        seq += 1
    return candidate


def _atomic_write_json(path: Path, data: Dict[str, Any]) -> None:
    """临时文件 + ``os.replace`` 原子写；失败时清掉临时文件再抛。"""
    text = json.dumps(data, ensure_ascii=False, indent=2)
    tmp = path.with_name(f"{path.name}.tmp{os.getpid()}")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------- 写入


def write_config(target_id: str, *, mode: str = "launcher",
                 launcher_path: Optional[str] = None,
                 dry_run: bool = False) -> Dict[str, Any]:
    """把 SuperInject 条目合并进目标 Agent 配置。

    返回::

        {ok, path, action: "created"|"updated"|"unchanged", backup, entry, error?}

    * ``backup``：写前备份的路径（未备份时为 ``None``）；
    * ``dry_run=True``：只计算将要写入什么，不落盘、不备份，``action`` 仍是
      会发生的动作。

    **合并语义**：读现有 JSON → 只在 ``mcpServers`` 下改 ``superinject`` 一个键
    → 原样写回。内容完全一致时返回 ``unchanged`` 且 **不写、不备份**。任何
    「读不懂现有文件」的情况都返回 ``ok=False`` 且 **不碰原文件**。
    """
    spec = _target_by_id(target_id)
    if spec is None:
        return {"ok": False, "path": None, "action": None, "backup": None,
                "entry": None, "dry_run": bool(dry_run),
                "error": f"未知目标: {target_id!r}"}

    path = Path(spec["path_fn"]())
    try:
        entry = _superinject_entry(mode, launcher_path)
    except Exception as exc:  # noqa: BLE001 - 生成条目失败统一报错
        return {"ok": False, "path": str(path), "action": None, "backup": None,
                "entry": None, "dry_run": bool(dry_run),
                "error": f"生成配置条目失败: {exc}"}

    existed = path.exists()
    data, error = _load_existing(path)
    if error:
        return {"ok": False, "path": str(path), "action": None, "backup": None,
                "entry": entry, "dry_run": bool(dry_run), "error": error}

    servers = data.get("mcpServers")
    if servers is not None and not isinstance(servers, dict):
        return {"ok": False, "path": str(path), "action": None, "backup": None,
                "entry": entry, "dry_run": bool(dry_run),
                "error": "现有 mcpServers 不是 JSON 对象；已中止，未改动原文件"}

    merged: Dict[str, Any] = dict(data)
    merged_servers: Dict[str, Any] = {}
    for key, value in (servers or {}).items():
        merged_servers[str(key)] = value
    if merged_servers.get(ENTRY_KEY) == entry:
        return {"ok": True, "path": str(path), "action": "unchanged",
                "backup": None, "entry": entry, "dry_run": bool(dry_run)}

    merged_servers[ENTRY_KEY] = entry
    merged["mcpServers"] = merged_servers

    action = "updated" if existed else "created"
    if dry_run:
        return {"ok": True, "path": str(path), "action": action,
                "backup": None, "entry": entry, "dry_run": True}

    backup: Optional[str] = None
    if existed:
        backup_path = _backup_path(path)
        try:
            shutil.copy2(path, backup_path)
        except OSError as exc:
            return {"ok": False, "path": str(path), "action": None, "backup": None,
                    "entry": entry, "dry_run": False,
                    "error": f"备份现有配置失败: {exc}"}
        backup = str(backup_path)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(path, merged)
    except OSError as exc:
        return {"ok": False, "path": str(path), "action": None,
                "backup": backup, "entry": entry, "dry_run": False,
                "error": f"写入配置失败: {exc}"}

    return {"ok": True, "path": str(path), "action": action, "backup": backup,
            "entry": entry, "dry_run": False}
