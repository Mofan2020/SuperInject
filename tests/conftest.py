"""pytest 全局夹具与清理。

Windows 11 上像 notepad.exe 这样的应用是「常驻宿主」进程，即使窗口关闭、
`terminate()` 成功也可能继续存活，导致 CI 步骤迟迟不结束。这里统一在会话
结束时强制回收本文件启动过的所有目标进程。
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

_TRACKED: list[int] = []


def _setup_debug_logging():
    """设置 SUPERINJECT_DEBUG=1 时把 IPC 调试日志写到文件，便于 CI 排查。"""
    import logging
    import os

    if not os.environ.get("SUPERINJECT_DEBUG"):
        return
    path = Path(__file__).resolve().parent.parent / "supinject-debug.log"
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)


_setup_debug_logging()


def track(pid: int) -> int:
    """登记一个由测试创建的目标进程 PID。"""
    _TRACKED.append(pid)
    return pid


def spawn(argv: list[str]) -> int:
    """启动一个长期存活的目标进程并登记，返回 PID。

    故意使用 ping.exe 而不是 notepad.exe：Windows 11 的 notepad 是常驻宿主
    进程，测试结束后仍会存活并让 CI 步骤挂起。
    """
    proc = subprocess.Popen(
        argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return track(proc.pid)


def _force_kill(pid: int) -> None:
    if sys.platform.startswith("win"):
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                       capture_output=True, check=False)
    else:
        try:
            import os
            import signal

            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass


@pytest.fixture
def stub_winapi(monkeypatch):
    """把 Win32 层打桩，让控制器逻辑可以在任意平台测试。"""
    from superinject import controller as ctl_mod

    table = [(100, "notepad.exe"), (200, "chrome.exe"), (300, "thing.exe")]
    opened: list[int] = []

    monkeypatch.setattr(ctl_mod.winapi, "enum_processes", lambda: list(table))
    monkeypatch.setattr(ctl_mod.winapi, "process_path", lambda pid: f"C:\\{pid}.exe")
    monkeypatch.setattr(ctl_mod.winapi, "process_memory_mb", lambda pid: 12.5)
    monkeypatch.setattr(ctl_mod.winapi, "is_wow64", lambda pid: None)
    monkeypatch.setattr(ctl_mod.winapi, "module_loaded", lambda pid, name: False)
    monkeypatch.setattr(ctl_mod.winapi, "close_handle", lambda h: None)
    monkeypatch.setattr(ctl_mod.winapi, "current_privilege", lambda: "admin")
    monkeypatch.setattr(ctl_mod.winapi, "process_suspend_state", lambda pid: None)

    def fake_open(pid, access=None):
        opened.append(pid)
        return 0x1234

    monkeypatch.setattr(ctl_mod.winapi, "open_process", fake_open)
    return {"table": table, "opened": opened}


@pytest.fixture
def fast_inject(monkeypatch):
    """让注入等待/握手不真的睡满超时。"""
    from superinject import controller as ctl_mod

    monkeypatch.setattr(ctl_mod, "ATTACH_TIMEOUT", 0.0)
    monkeypatch.setattr(ctl_mod, "DETACH_TIMEOUT", 0.0)


@pytest.fixture(autouse=True)
def _noop_hook():
    """占位：保持钩子结构，实际清理由各用例的 finally 与会话结束钩子负责。

    注意不要在这里回收被 module 级 fixture 复用的进程，否则会导致
    后续用例拿到一个已经被杀掉的 PID。
    """
    yield


@pytest.fixture(scope="session", autouse=True)
def _final_cleanup():
    yield
    for pid in list(_TRACKED):
        _force_kill(pid)
    _TRACKED.clear()
