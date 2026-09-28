"""自检1：权限自检与 UAC 提权。

启动流程：检测当前身份（SYSTEM / 管理员 / 普通用户）。不是 SYSTEM 也不是管理员时，
用 ShellExecuteW(runas) 重新以管理员身份拉起自身，成功后退出当前进程。

说明：UAC 只能把进程提到「管理员」，无法直接得到 SYSTEM —— 需要 SYSTEM 时请用
计划任务或 PsExec 以 SYSTEM 身份启动，本工具的权限自检会把实际级别如实显示出来。
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

PRIVILEGE_LABELS = {
    "system": "SYSTEM",
    "admin": "管理员（已提权）",
    "user": "普通用户（未提权）",
}


@dataclass
class ElevationResult:
    ok: bool
    is_admin: bool
    relaunched: bool = False
    message: str = ""
    identity: str = ""
    privilege: str = "user"


def current_privilege() -> str:
    """返回 'system' / 'admin' / 'user'。"""
    try:
        from . import winapi

        return winapi.current_privilege()
    except Exception:  # pragma: no cover - 非 Windows
        return "user"


def privilege_label(privilege: str = "") -> str:
    return PRIVILEGE_LABELS.get(privilege or current_privilege(), "未知")


def current_identity() -> str:
    """返回「账户名 @ 计算机名（权限级别）」用于界面展示与自检报告。"""
    user = "unknown"
    try:
        import ctypes
        import ctypes.wintypes as wt

        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        buf = ctypes.create_unicode_buffer(256)
        size = wt.DWORD(256)
        if advapi.GetUserNameW(buf, ctypes.byref(size)):
            user = buf.value
    except Exception:  # pragma: no cover - 非 Windows
        user = os.environ.get("USERNAME", "unknown")
    return f"{user} / {privilege_label()}"


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
    """自检1。已是管理员或 SYSTEM 则直接放行。"""
    identity = current_identity()
    privilege = current_privilege()
    if privilege in ("admin", "system"):
        return ElevationResult(True, True, False,
                               f"权限自检通过（{privilege_label(privilege)}）",
                               identity, privilege)

    if not auto_relaunch:
        return ElevationResult(
            False, False, False,
            "当前不是管理员权限，无法注入/冻结进程。请右键以管理员身份运行。",
            identity, privilege,
        )

    ok, err = _relaunch_as_admin()
    if ok:
        return ElevationResult(True, True, True, "已请求 UAC 提权，正在重新启动",
                               identity, privilege)
    return ElevationResult(
        False, False, False,
        f"提权失败（{err or '用户取消了 UAC 提示'}）。请右键『以管理员身份运行』。",
        identity, privilege,
    )
