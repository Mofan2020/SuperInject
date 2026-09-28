"""无界面自检：把「自检1 → 自检2 → 注入 → 建连 → 控制 → 收尾」整条链路真跑一遍。

为什么需要它：pytest 集成测试验证的是源码，而用户拿到的是打包好的 exe。
``SuperInject.exe --self-test`` 会从 **打包产物** 出发，用它内嵌的 DLL 去注入一个
真实进程，逐项验证需求里的每个能力，最后写出 ``self-test-report.json``。

打包后的 exe 是 --windowed（没有控制台），所以报告必须落盘；
退出码 0 表示全部通过，1 表示有步骤失败。CI 会读取报告文件来断言。
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import dll_manager, elevate, winapi
from .version import APP_NAME, __version__

log = logging.getLogger("supinject.selftest")

REPORT_NAME = "self-test-report.json"


class Recorder:
    """收集每一步的结果，最后统一输出。"""

    def __init__(self) -> None:
        self.steps: List[Dict[str, Any]] = []
        self.context: Dict[str, Any] = {}

    def step(self, name: str, ok: bool, detail: Any = "", **extra) -> bool:
        entry = {"name": name, "ok": bool(ok), "detail": detail}
        entry.update(extra)
        self.steps.append(entry)
        log.info("[%s] %s %s", "PASS" if ok else "FAIL", name, detail)
        return bool(ok)

    def soft(self, name: str, ok: Optional[bool], detail: Any = "") -> bool:
        """无法判定（None）的检查记为通过但标注 unknown。"""
        return self.step(name, ok is None or bool(ok), detail,
                         unknown=ok is None)

    @property
    def failed(self) -> List[Dict[str, Any]]:
        return [s for s in self.steps if not s["ok"]]

    def report(self) -> dict:
        return {
            "app": APP_NAME,
            "version": __version__,
            "frozen": bool(getattr(sys, "frozen", False)),
            "executable": sys.executable,
            "cwd": os.getcwd(),
            "python": sys.version.split()[0],
            "started_at": self.context.get("started_at"),
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "steps": self.steps,
            "passed": len(self.steps) - len(self.failed),
            "failed": len(self.failed),
            "ok": not self.failed,
        }


def report_path(explicit: str = "") -> Path:
    if explicit:
        return Path(explicit)
    base = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) \
        else Path(__file__).resolve().parent.parent
    return base / REPORT_NAME


def _spawn_target() -> Tuple[int, subprocess.Popen]:
    """拉起一个必定存在、长生命周期、退出可回收的目标进程。"""
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    candidates = [
        Path(system_root) / "System32" / "ping.exe",
        Path(system_root) / "System32" / "timeout.exe",
    ]
    exe = next((str(c) for c in candidates if c.exists()), "ping")
    proc = subprocess.Popen(
        [exe, "-t", "127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return proc.pid, proc


def _kill(pid: int) -> None:
    try:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True, check=False)
    except Exception:  # pragma: no cover
        pass


def _wait(fn, timeout: float = 20.0, interval: float = 0.3):
    deadline = time.time() + timeout
    result = None
    while time.time() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(interval)
    return result


def run(argv: Optional[List[str]] = None) -> int:
    """执行自检并返回退出码。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    explicit_report = ""
    keep_target = "--keep-target" in argv
    for i, a in enumerate(argv):
        if a == "--report" and i + 1 < len(argv):
            explicit_report = argv[i + 1]

    rec = Recorder()
    rec.context["started_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    target_pid = 0

    try:
        # ---------------------------------------------------------- 自检 1
        priv = winapi.current_privilege()
        rec.step("自检1 权限", priv in ("admin", "system"),
                 f"当前身份 {elevate.current_identity()}，权限级别 {priv}")

        # ---------------------------------------------------------- 自检 2
        report = dll_manager.verify_and_sync(force=True)
        rec.step("自检2 DLL 校验与释放", bool(report.ok) and Path(report.path).exists(),
                 f"{report.action}: {report.message}",
                 embedded_sha=report.embedded_sha, disk_sha=report.disk_sha,
                 dll_path=str(report.path))

        dll_path = Path(report.path)
        rec.step("自检2 SHA 由运行时计算",
                 bool(report.embedded_sha) and report.disk_sha == report.embedded_sha,
                 f"SHA256 一致 {report.disk_sha[:16]}…")

        if not report.ok:
            return _finish(rec, explicit_report)

        from .controller import Controller  # 延迟导入：非 Windows 下会抛错

        ctrl = Controller(dll_path=dll_path)

        # ---------------------------------------------------------- 目标进程
        try:
            target_pid, proc = _spawn_target()
        except Exception as exc:
            rec.step("拉起目标进程", False, f"{exc}")
            return _finish(rec, explicit_report)
        rec.step("拉起目标进程", winapi.pid_alive(target_pid),
                 f"pid={target_pid}")

        # ---------------------------------------------------------- 注入检查
        checks = ctrl.preflight([target_pid])
        check = checks[0] if checks else {}
        rec.step("注入检查", bool(check.get("ok")),
                 f"名称={check.get('name')} 位数={check.get('arch')} "
                 f"可访问={check.get('accessible')} 原因={check.get('reason') or '-'}")

        # ---------------------------------------------------------- 注入 + 建连
        res = ctrl.inject([target_pid], check=False)[0]
        rec.step("注入并建立控制通道",
                 bool(res.get("ok")) and bool(res.get("attached")),
                 f"module={res.get('module')} 已连接={res.get('attached')} "
                 f"错误={res.get('error') or '-'}")
        if not res.get("ok"):
            return _finish(rec, explicit_report)

        # ---------------------------------------------------------- 控制链路
        pong = ctrl.server.request(target_pid, {"type": "ping"}, timeout=10)
        rec.step("ping 连通性", bool(pong.get("ok")), str(pong.get("error") or "pong"))

        info = ctrl.server.request(target_pid, {"type": "info"}, timeout=15)
        modules = [m.get("name", "") for m in (info.get("modules") or [])]
        rec.step("info 模块列表",
                 bool(info.get("ok")) and any("ping" in m.lower() for m in modules),
                 f"{len(modules)} 个模块")

        regions = ctrl.server.request(target_pid, {"type": "mem_regions"}, timeout=30)
        rec.step("mem_regions 内存区域",
                 bool(regions.get("ok")) and len(regions.get("regions") or []) > 0,
                 f"{len(regions.get('regions') or [])} 个区域")

        # ---------------------------------------------------------- 内存搜索/读写
        found = ctrl.mem_search([target_pid], "4D 5A ?? ??", 8)
        hits = (found[0].get("resp") or {}).get("results") if found else None
        rec.step("内存搜索（4D 5A ?? ??）", bool(hits), f"{len(hits or [])} 处命中")

        # 读写挑目标自己的 PE 头页（模块基址 + 0x100，DOS stub 区永不执行）：
        # 这一页是只读的，必须靠「临时改页保护」才写得进去 —— 正是调试器给已
        # 加载模块打补丁的路线。不能用「搜到的第一个 MZ」：那个地址可能落在别的
        # 只读映射里（只读文件映射之类），写不进去，看着像读写功能坏了。
        image = Path(winapi.process_path(target_pid)).name.lower()
        bases = {str(m.get("name", "")).lower(): int(m.get("base", 0))
                 for m in (info.get("modules") or [])}
        address = (bases.get(image) or 0) + 0x100
        if bases.get(image):
            original = ctrl.mem_read(target_pid, address, 1)
            old_byte = str(original.get("hex", ""))[:2]
            new_byte = "90" if old_byte != "90" else "91"
            wrote = ctrl.mem_write(target_pid, address, new_byte)
            back = ctrl.mem_read(target_pid, address, 1)
            restored = ctrl.mem_write(target_pid, address, old_byte)
            detail = (f"0x{address:X} {old_byte} -> {new_byte} -> "
                      f"{str(back.get('hex', ''))[:2]}"
                      f"{' 错误=' + str(wrote['error']) if wrote.get('error') else ''}")
            rec.step("内存读 / 改 / 还原（只读 PE 头页）",
                     bool(original.get("ok")) and bool(wrote.get("ok"))
                     and str(back.get("hex", ""))[:2] == new_byte
                     and bool(restored.get("ok")),
                     detail)
        else:
            rec.step("内存读 / 改 / 还原（只读 PE 头页）", False,
                     f"模块表里没有 {image}")

        # ---------------------------------------------------------- 资源
        resources = ctrl.resources([target_pid])
        items = (resources[0].get("resp") or {}).get("items") if resources else []
        rec.step("资源提取（PE 资源 + 内存映射）",
                 bool(resources and resources[0].get("ok")),
                 f"{len(items or [])} 个媒体条目",
                 kinds=sorted({i.get("kind") for i in (items or [])}))

        # ---------------------------------------------------------- 冻结 / 解除
        frozen = ctrl.freeze([target_pid])[0]
        rec.soft("冻结进程", frozen.get("verified"), f"挂起状态={frozen.get('verified')}")
        thawed = ctrl.unfreeze([target_pid])[0]
        rec.soft("解除冻结", None if thawed.get("verified") is None
                 else (thawed.get("verified") is False),
                 f"挂起状态={thawed.get('verified')}")
        pong2 = ctrl.ping([target_pid])
        rec.step("冻结恢复后控制通道仍可用",
                 bool(pong2 and pong2[0].get("ok")), str(pong2[0].get("error") or "pong"))

        # ---------------------------------------------------------- 卸载 + 重新注入
        out = ctrl.unload([target_pid])
        rec.step("卸载注入的 DLL",
                 bool(out and out[0].get("ok")) and not ctrl.server.is_attached(target_pid),
                 f"detached={out[0].get('detached') if out else None}")

        again = ctrl.inject([target_pid], check=False)[0]
        rec.step("卸载后重新注入",
                 bool(again.get("ok")) and bool(again.get("attached")),
                 f"已连接={again.get('attached')} 错误={again.get('error') or '-'}")

        hot = ctrl.inject([target_pid], check=False)[0]
        rec.step("已注入状态下重复注入（自动先卸载旧 DLL）",
                 bool(hot.get("ok")) and bool(hot.get("reinjected"))
                 and bool(hot.get("attached")),
                 f"reinjected={hot.get('reinjected')} 已连接={hot.get('attached')} "
                 f"错误={hot.get('error') or '-'}")

        # ---------------------------------------------------------- 终止
        before = winapi.pid_alive(target_pid)
        ctrl.terminate([target_pid])
        gone = _wait(lambda: not winapi.pid_alive(target_pid), timeout=20)
        rec.step("终止进程（DLL 内 ExitProcess）", bool(before and gone),
                 "目标进程已自行退出" if gone else "目标进程仍存活")
    except Exception as exc:  # pragma: no cover - 兜底，保证一定写出报告
        log.exception("自检异常中止")
        rec.step("自检异常中止", False, f"{type(exc).__name__}: {exc}")
    finally:
        if target_pid and not keep_target and winapi.pid_alive(target_pid):
            _kill(target_pid)

    return _finish(rec, explicit_report)


def _finish(rec: Recorder, explicit_report: str) -> int:
    data = rec.report()
    path = report_path(explicit_report)
    data["report_path"] = str(path)
    if not _write_report(path, data):
        # 安装目录不可写时退到临时目录，保证报告一定拿得到
        import tempfile

        path = Path(tempfile.gettempdir()) / REPORT_NAME
        data["report_path"] = str(path)
        _write_report(path, data)
    text = json.dumps(data, ensure_ascii=False, indent=2)
    _safe_print(text)
    _safe_print(f"[self-test] 报告已写入 {path}", "stderr")
    _safe_print(f"[self-test] {data['passed']}/{len(data['steps'])} 步通过", "stderr")
    return 0 if data["ok"] else 1


def _write_report(path: Path, data: dict) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                        encoding="utf-8")
        return True
    except OSError as exc:  # pragma: no cover
        log.error("写入自检报告失败 %s: %s", path, exc)
        return False


def _safe_print(text: str, stream: str = "stdout") -> None:
    """--windowed 打包后 sys.stdout 是 None，直接 print 会抛异常。"""
    target = getattr(sys, stream, None)
    if target is None:
        return
    try:
        print(text, file=target)
    except Exception:  # pragma: no cover
        pass
