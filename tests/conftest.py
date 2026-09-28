"""pytest 全局清理：确保测试启动的目标进程不会残留。

Windows 11 上像 notepad.exe 这样的应用是「常驻宿主」进程，即使窗口关闭、
`terminate()` 成功也可能继续存活，导致 CI 步骤迟迟不结束。这里统一在会话
结束时强制回收本文件启动过的所有目标进程。
"""

from __future__ import annotations

import subprocess
import sys

import pytest

_TRACKED: list[int] = []


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


@pytest.fixture(autouse=True)
def _cleanup_after_test():
    yield
    # 每个用例结束后，把本用例启动但可能仍存活的进程清掉
    while _TRACKED:
        pid = _TRACKED.pop()
        _force_kill(pid)


@pytest.fixture(scope="session", autouse=True)
def _final_cleanup():
    yield
    for pid in list(_TRACKED):
        _force_kill(pid)
    _TRACKED.clear()
