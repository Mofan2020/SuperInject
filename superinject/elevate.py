"""自检1：权限自检与 UAC 提权。

启动流程：检测当前是否为管理员（SYSTEM）权限，若不是则用 ShellExecuteW(runas)
重新以管理员身份拉起自身，成功后退出当前进程。
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


@dataclass
class ElevationResult:
    ok: bool
    is_admin: bool
    relaunched: bool = False
    message: str = ""
    identity: str = ""


def current_identity() -> str:
    """尽力返回当前账户名，用于界面展示。"""
    try:
        import ctypes
        import ctypes.wintypes as wt

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        buf = ctypes.create_unicode_buffer(256)
        size = wt.DWORD(256)
        if advapi.GetUserNameW(buf, ctypes.byref(size)):
            return f"{buf.value} (elevated={is_admin()})"
    except Exception:
        pass
    return "unknown"


def is_admin() -> bool:
    try:
        from . import winapi

        return winapi.is_elevated()
    except Exception:
        return False


def _relaunch_as_admin() -> tuple[bool, str]:
    import ctypes

    if getattr(sys, "frozen", False):
        exe = sys.executable
        args = ""
    else:
        exe = sys.executable
        script = os.path.abspath(sys.argv[0])
        args = subprocess_quote(script)

    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
        # ShellExecuteW 返回 > 32 表示成功
        return rc > 32, ""
    except Exception as exc:  # pragma: no cover
        return False, str(exc)


def subprocess_quote(s: str) -> str:
    if not s or any(c in s for c in ' "'):
        return '"' + s.replace('"', '\\"') + '"'
    return s


def ensure_admin(auto_relaunch: bool = True) -> ElevationResult:
    """自检1。已是管理员则直接放行。"""
    identity = current_identity()
    if is_admin():
        return ElevationResult(True, True, False, "权限自检通过", identity)

    if not auto_relaunch:
        return ElevationResult(
            False, False, False,
            "当前不是管理员权限，无法注入/冻结进程。请右键以管理员身份运行。",
            identity,
        )

    ok, err = _relaunch_as_admin()
    if ok:
        return ElevationResult(True, True, True, "已请求 UAC 提权，正在重新启动", identity)
    return ElevationResult(
        False, False, False,
        f"提权失败（{err or '用户取消了 UAC 提示'}）。请右键『以管理员身份运行』。",
        identity,
    )
