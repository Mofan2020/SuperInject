"""自检1：权限自检、UAC 提权、以及提权到 SYSTEM。

三级权限与对应的启动流程：

* 普通用户 → ``ShellExecuteW(runas)`` 走 UAC 提到管理员，然后退出当前进程；
* 管理员 → 复制一个 SYSTEM 进程的令牌，用 ``CreateProcessAsUserW`` 把自己
  以 SYSTEM 重新拉起（GUI 仍在当前桌面），然后退出当前进程；
* SYSTEM → 直接放行。

SYSTEM 提权的实现在 ``system_token.py``；本模块只负责「要不要提、提到哪、
失败了怎么办」的策略，以及在非 Windows 上保持可导入、可测试。

降级原则：SYSTEM 提权失败不硬性终止程序 —— 普通进程调试用管理员权限就够，
所以会带着明确原因降级为管理员运行，并在界面与日志里如实说明。
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from typing import Optional

PRIVILEGE_LABELS = {
    "system": "SYSTEM",
    "admin": "管理员（已提权）",
    "user": "普通用户（未提权）",
}

# 关掉 SYSTEM 提权的开关（两个都接受，写在帮助里）
NO_SYSTEM_FLAGS = ("--as-admin", "--no-system")


@dataclass
class ElevationResult:
    ok: bool
    is_admin: bool
    relaunched: bool = False
    message: str = ""
    identity: str = ""
    privilege: str = "user"
    system: bool = False                  # 当前（或即将）以 SYSTEM 运行
    degraded: bool = False                # 想要 SYSTEM，实际只能管理员
    reason: str = ""                      # 降级/失败的原因
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok, "privilege": self.privilege, "system": self.system,
            "is_admin": self.is_admin, "degraded": self.degraded,
            "relaunched": self.relaunched, "message": self.message,
            "reason": self.reason, "identity": self.identity,
            "details": self.details,
        }


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


def is_system() -> bool:
    return current_privilege() == "system"


# ---------------------------------------------------------------- 策略（纯逻辑）


def system_requested(argv: Optional[list] = None) -> bool:
    """默认要 SYSTEM 提权；显式给了 --as-admin / --no-system 才跳过。"""
    return not any(a in NO_SYSTEM_FLAGS for a in (argv or []))


def decide(privilege: str, argv: Optional[list] = None,
           want_system: bool = True,
           already_relaunched: bool = False) -> str:
    """纯函数：返回下一步动作。

    ``'pass'``   已经是目标权限，直接启动 GUI
    ``'uac'``    需要 UAC 提到管理员
    ``'system'`` 需要用 SYSTEM 令牌重新拉起自身
    ``'admin'``  不再提权，以管理员身份继续（系统不允许时降级）
    """
    if privilege == "system":
        return "pass"
    if privilege == "user":
        return "admin" if already_relaunched else "uac"
    # privilege == "admin"
    if not (want_system and system_requested(argv)):
        return "admin"
    if already_relaunched:
        # 已经以 SYSTEM 重新拉起过一次却仍是管理员 —— 不再反复重启
        return "admin"
    return "system"


# ---------------------------------------------------------------- 提权动作


def subprocess_quote(s: str) -> str:
    if not s or any(c in s for c in ' "'):
        return '"' + s.replace('"', '\\"') + '"'
    return s


def _relaunch_as_admin(argv: Optional[list] = None) -> tuple[bool, str]:
    import ctypes

    if getattr(sys, "frozen", False):
        exe = sys.executable
        args = " ".join(subprocess_quote(a) for a in (argv or []))
    else:
        exe = sys.executable
        parts = [os.path.abspath(sys.argv[0])] + list(argv or [])
        args = " ".join(subprocess_quote(a) for a in parts)

    try:
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, args, None, 1)
        # ShellExecuteW 返回 > 32 表示成功
        return rc > 32, ""
    except Exception as exc:  # pragma: no cover
        return False, str(exc)


def elevate_to_system(argv: Optional[list] = None,
                      timeout: float = 30.0) -> ElevationResult:
    """复制 SYSTEM 令牌并以 SYSTEM 重新拉起自身。"""
    from . import system_token

    if not sys.platform.startswith("win"):
        return ElevationResult(
            False, False, False, "仅支持 Windows", current_identity(),
            "user", degraded=True, reason="非 Windows 平台")

    res = system_token.launch_as_system(list(argv or []), timeout=timeout)
    if res.ok:
        return ElevationResult(
            True, True, True,
            f"已以 SYSTEM 重新启动（{res.method}，令牌来源 "
            f"{res.source_name} pid={res.source_pid}）",
            current_identity(), current_privilege(), system=True,
            details={"method": res.method, "child_pid": res.pid,
                     "source_pid": res.source_pid, "source_name": res.source_name,
                     "sid": res.sid})
    return ElevationResult(
        True, True, False,
        "SYSTEM 提权失败，已降级为管理员运行（普通进程调试不受影响）",
        current_identity(), current_privilege(), degraded=True,
        reason=res.message)


def ensure_privilege(argv: Optional[list] = None, auto_relaunch: bool = True,
                     want_system: bool = True) -> ElevationResult:
    """自检1 主入口：按需提权，返回最终应如何继续。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    identity = current_identity()
    priv = current_privilege()

    from . import system_token

    already = system_token.is_launched_child()
    action = decide(priv, argv, want_system, already)

    if action == "pass":
        return ElevationResult(True, True, False,
                               f"权限自检通过（{privilege_label(priv)}）",
                               identity, priv, system=(priv == "system"))

    if action == "admin":
        if priv == "user":
            return ElevationResult(
                False, False, False,
                "当前不是管理员权限，无法注入/冻结进程。请右键以管理员身份运行。",
                identity, priv)
        degraded = want_system and system_requested(argv)
        reason = ""
        if degraded and already:
            reason = "SYSTEM 提权已经尝试过一次，本次不再重复重启"
        elif degraded:
            reason = "已按参数跳过 SYSTEM 提权"
        return ElevationResult(True, True, False,
                               f"权限自检通过（{privilege_label(priv)}）",
                               identity, priv, degraded=degraded, reason=reason)

    if action == "uac":
        if not auto_relaunch:
            return ElevationResult(
                False, False, False,
                "当前不是管理员权限，无法注入/冻结进程。请右键以管理员身份运行。",
                identity, priv)
        ok, err = _relaunch_as_admin(argv)
        if ok:
            return ElevationResult(True, True, True,
                                   "已请求 UAC 提权，正在重新启动", identity, priv)
        return ElevationResult(
            False, False, False,
            f"提权失败（{err or '用户取消了 UAC 提示'}）。请右键『以管理员身份运行』。",
            identity, priv)

    # action == "system"
    res = elevate_to_system(argv)
    res.identity = identity
    res.privilege = priv
    return res


def ensure_admin(auto_relaunch: bool = True) -> ElevationResult:
    """兼容旧接口：只要「管理员或 SYSTEM」即可继续（不提 SYSTEM）。"""
    return ensure_privilege(auto_relaunch=auto_relaunch, want_system=False)
