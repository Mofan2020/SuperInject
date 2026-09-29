"""把自身提升到 SYSTEM 权限（用于调试高权限进程）。

原理（与 PsExec -s 同路线，不依赖任何外部程序 / 服务）：

1. 当前进程已是管理员 → 打开 SeDebugPrivilege；
2. 在本会话里找一个以 SYSTEM 运行的普通进程（首选 winlogon.exe，它没有被
   PPL 保护，管理员可以打开它的令牌；lsass/csrss 在 Win10+ 是受保护进程，
   打开会 ACCESS_DENIED，所以只作候选）；
3. ``OpenProcessToken`` + ``DuplicateTokenEx`` 复制成一个**主令牌**；
4. ``CreateProcessAsUserW`` 用这个主令牌把自己重新拉起 —— 新进程即 SYSTEM，
   并且仍在**当前会话/桌面**上，所以 GUI 正常显示（不像计划任务那样掉进
   session 0 看不见）。

为什么候选必须限定在「本会话」：用别的会话的令牌创建进程需要 SeTcbPrivilege
（只有 SYSTEM 才有），限定同会话就完全用不到它。

为什么用「复制令牌」而不是自己造令牌：``CreateProcessAsUserW`` 需要
SeAssignPrimaryTokenPrivilege + SeIncreaseQuotaPrivilege，管理员默认就有；
失败时自动回退 ``CreateProcessWithTokenW``（需要 SeImpersonatePrivilege，
管理员同样默认具备），两条路互为备份。

本模块只做「取令牌 + 拉起」，是否要提权、失败后怎么办由 ``elevate.py`` 决定。
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from . import winapi

log = logging.getLogger("supinject.system_token")

# ---------------------------------------------------------------- 常量
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATE = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
MAXIMUM_ALLOWED = 0x02000000

SE_PRIVILEGE_ENABLED = 0x00000002
ERROR_NOT_ALL_ASSIGNED = 1300

SecurityImpersonation = 2
TokenPrimary = 1

CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_NEW_PROCESS_GROUP = 0x00000200
LOGON_WITH_PROFILE = 0x00000001
LOGON_NETCREDENTIALS_ONLY = 0x00000002

INFINITE = 0xFFFFFFFF
WAIT_TIMEOUT = 0x00000102
WAIT_OBJECT_0 = 0x00000000

# 优先尝试的 SYSTEM 进程（不区分大小写）。
# winlogon.exe 排在第一位：它是 SYSTEM、每个交互会话都有、且未被 PPL 保护，
# 管理员开它的令牌是允许的 —— 这正是 PsExec 用它做跳板的原因。
PREFERRED_NAMES = (
    "winlogon.exe",
    "services.exe",
    "wininit.exe",
    "lsass.exe",
    "smss.exe",
    "csrss.exe",
    "svchost.exe",
)

# 非优先名单里最多再试这么多个进程，避免在几百个进程上白耗时间
MAX_FALLBACK_TRIES = 60

# 重新拉起时写进环境变量的标记：子进程看到它就知道「已经提过权了」，
# 不再重复提权，避免自我启动的死循环。
LAUNCH_MARKER_ENV = "SUPERINJECT_SYSTEM_LAUNCH"

# PyInstaller onefile 运行时塞进环境的私有变量（见 child_environment 的说明）。
# 名字取自 pyinstaller 自己的 bootloader；将来它改名的话这里会「静默失效」，
# 所以 tests/test_system_token.py 里锁了「父进程环境里有它们时子进程必须没有」。
_PYI_PRIVATE_ENV = (
    "_MEIPASS2",
    "_MEIPASS",
    "_PYI_APPLICATION_HOME_DIR",
    "_PYI_ARCHIVE_FILE",
    "_PYI_PARENT_PROCESS_LEVEL",
    "_PYI_SPLASH_IPC",
)


# ---------------------------------------------------------------- 纯逻辑


def ordered_candidates(processes: Iterable[dict],
                       session: Optional[int] = None,
                       preferred: tuple = PREFERRED_NAMES) -> list[dict]:
    """把进程列表排成「值得先试」的顺序（纯函数，方便脱离 Windows 测试）。

    排序键：① 同会话优先（跨会话创建进程需要 SeTcbPrivilege，尽量不用）
           ② 名单内的按名单顺序，名单外的垫底
           ③ 同分时新进程优先（PID 大的更可能是活跃的 SYSTEM 进程）
    """
    rank = {name: i for i, name in enumerate(preferred)}

    def key(p: dict):
        name = str(p.get("name") or "").lower()
        cross = 0 if (session is None or p.get("session") == session) else 1
        return (cross, rank.get(name, len(rank)), -int(p.get("pid") or 0))

    return sorted((dict(p) for p in processes), key=key)


def build_environment_block(env: dict) -> ctypes.Array:
    """把 dict 编成 Windows 需要的 ``k=v\\0k=v\\0\\0`` 环境块。"""
    items = [f"{k}={v}" for k, v in env.items() if k]
    items.sort(key=lambda s: s.upper())
    text = "\0".join(items) + "\0\0"
    return ctypes.create_unicode_buffer(text)


def child_environment(extra: Optional[dict] = None) -> dict:
    """子进程环境：完整继承当前环境（务必保留 TEMP —— 控制器与注入端靠
    ``%TEMP%\\SuperInject\\port-<PID>.txt`` 会合，TEMP 变了就连不上）。"""
    env = dict(os.environ)
    env[LAUNCH_MARKER_ENV] = "1"
    # 必须清掉 PyInstaller onefile 的私有环境变量：宿主进程里它们指向**父进程**
    # 解包出来的 _MEIxxxx 目录，子进程照抄就会去用父进程那份解包结果（本地实测：
    # 子进程 sys._MEIPASS 与父进程完全相同），于是子进程退出时清理动作会动到父
    # 进程正在用的目录 —— 表现就是打包产物的自检卡死不返回。清掉后子进程会自己
    # 解包一份（本机验证：两边 _MEIPASS 不同）。
    for var in _PYI_PRIVATE_ENV:
        env.pop(var, None)
    if not getattr(sys, "frozen", False):
        # 源码运行：子进程的 cwd 未必在仓库里，靠 PYTHONPATH 才能
        # `python -m superinject`。
        root = str(Path(__file__).resolve().parent.parent)
        cur = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = root + (os.pathsep + cur if cur else "")
    if extra:
        env.update({k: str(v) for k, v in extra.items()})
    return env


def relaunch_argv(extra: Optional[list] = None) -> tuple[str, str]:
    """返回 ``(exe, 命令行)``：把当前程序原样重新拉起。

    * 打包后（frozen）：就是 exe 自己；
    * 源码运行：``python -m superinject``，**不要**用 ``sys.argv[0]`` ——
      从 pytest / ``python -c`` 里被拉起时它是别人的入口，照抄会把参数喂给
      错误的程序（CI 上真的踩过：重启出来的其实是 pytest 进程，于是探针
      参数被当成未知选项，什么都没写）。
    """
    exe = sys.executable
    extra = list(extra or [])
    if getattr(sys, "frozen", False):
        parts = [exe] + extra
    else:
        parts = [exe, "-m", "superinject"] + extra
    # CreateProcess 的命令行是单个字符串，含空格的路径要自己加引号
    return exe, " ".join(_quote(p) for p in parts)


def is_launched_child() -> bool:
    """本进程是不是「已被提升为 SYSTEM 的那次重启」。"""
    return os.environ.get(LAUNCH_MARKER_ENV) == "1"


def _quote(s: str) -> str:
    s = str(s)
    return f'"{s}"' if (not s or " " in s or "\t" in s) else s


# ---------------------------------------------------------------- Win32 结构
#
# 刻意使用定宽类型（c_uint32 / c_int32 / c_uint16）而不是 ctypes.wintypes 里
# 的 DWORD / LONG：后者是 c_ulong，在 Windows 上是 4 字节、在 macOS/Linux 上是
# 8 字节，会导致结构体在开发机上「看起来是对的、到 Windows 上布局就不对」。
# 用定宽类型后，Windows 上的 ABI 与 DWORD 完全一致，同时这些结构在本机也能
# 被断言校验（tests/test_system_token.py 会校验 sizeof）。

DWORD32 = ctypes.c_uint32
LONG32 = ctypes.c_int32
WORD16 = ctypes.c_uint16
HANDLE_T = ctypes.c_void_p
WSTR = ctypes.c_wchar_p


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", DWORD32), ("HighPart", LONG32)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", DWORD32)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", DWORD32),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD32),
        ("lpReserved", WSTR),
        ("lpDesktop", WSTR),
        ("lpTitle", WSTR),
        ("dwX", DWORD32), ("dwY", DWORD32),
        ("dwXSize", DWORD32), ("dwYSize", DWORD32),
        ("dwXCountChars", DWORD32), ("dwYCountChars", DWORD32),
        ("dwFillAttribute", DWORD32),
        ("dwFlags", DWORD32), ("wShowWindow", WORD16),
        ("cbReserved2", WORD16), ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", HANDLE_T), ("hStdOutput", HANDLE_T),
        ("hStdError", HANDLE_T),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", HANDLE_T), ("hThread", HANDLE_T),
                ("dwProcessId", DWORD32), ("dwThreadId", DWORD32)]


# ---------------------------------------------------------------- Win32 调用


def _kernel32():
    k = winapi.kernel32()
    if not getattr(k, "_si_bound", False):
        # 必须显式声明：ctypes 默认把 Python int 当 32 位 C int 传，
        # 64 位下句柄会被截断 —— 这类错误在 Windows 上表现为随机失败。
        k.WaitForSingleObject.restype = DWORD32
        k.WaitForSingleObject.argtypes = [HANDLE_T, DWORD32]
        k.GetExitCodeProcess.restype = ctypes.c_int
        k.GetExitCodeProcess.argtypes = [HANDLE_T, ctypes.POINTER(DWORD32)]
        k.ProcessIdToSessionId.restype = ctypes.c_int
        k.ProcessIdToSessionId.argtypes = [DWORD32,
                                          ctypes.POINTER(DWORD32)]
        k._si_bound = True
    return k


def _handle_value(handle) -> int:
    """取句柄的整数值（ctypes 的 HANDLE 是 c_void_p 子类）。"""
    value = getattr(handle, "value", None)
    return int(value) if value else 0


def _advapi32():
    a = winapi.advapi32()
    if not getattr(a, "_si_bound", False):
        a.LookupPrivilegeValueW.restype = ctypes.c_int
        a.LookupPrivilegeValueW.argtypes = [
            WSTR, WSTR, ctypes.POINTER(LUID)]
        a.AdjustTokenPrivileges.restype = ctypes.c_int
        a.AdjustTokenPrivileges.argtypes = [
            HANDLE_T, ctypes.c_int, ctypes.POINTER(TOKEN_PRIVILEGES), DWORD32,
            ctypes.c_void_p, ctypes.c_void_p]
        a.DuplicateTokenEx.restype = ctypes.c_int
        a.DuplicateTokenEx.argtypes = [
            HANDLE_T, DWORD32, ctypes.c_void_p, ctypes.c_int, ctypes.c_int,
            ctypes.POINTER(HANDLE_T)]
        a.CreateProcessAsUserW.restype = ctypes.c_int
        a.CreateProcessAsUserW.argtypes = [
            HANDLE_T, WSTR, ctypes.c_wchar_p, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_int, DWORD32, ctypes.c_void_p,
            WSTR, ctypes.POINTER(STARTUPINFOW),
            ctypes.POINTER(PROCESS_INFORMATION)]
        a.CreateProcessWithTokenW.restype = ctypes.c_int
        a.CreateProcessWithTokenW.argtypes = [
            HANDLE_T, DWORD32, WSTR, ctypes.c_wchar_p, DWORD32,
            ctypes.c_void_p, WSTR, ctypes.POINTER(STARTUPINFOW),
            ctypes.POINTER(PROCESS_INFORMATION)]
        a._si_bound = True
    return a


def enable_privilege(name: str) -> bool:
    """打开当前进程令牌里的某个特权（如 SeDebugPrivilege）。"""
    a, k = _advapi32(), _kernel32()
    token = HANDLE_T()
    if not a.OpenProcessToken(k.GetCurrentProcess(),
                              TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                              ctypes.byref(token)):
        return False
    try:
        luid = LUID()
        if not a.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
            return False
        state = TOKEN_PRIVILEGES()
        state.PrivilegeCount = 1
        state.Privileges[0].Luid = luid
        state.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        ctypes.set_last_error(0)
        if not a.AdjustTokenPrivileges(token, False, ctypes.byref(state), 0,
                                       None, None):
            return False
        # AdjustTokenPrivileges 即使没成功打开也会返回 TRUE，必须查 last error
        return winapi.last_error() != ERROR_NOT_ALL_ASSIGNED
    finally:
        k.CloseHandle(token)


def process_session_id(pid: int) -> Optional[int]:
    if not winapi.IS_WINDOWS:
        return None
    k = _kernel32()
    sid = DWORD32()
    if k.ProcessIdToSessionId(DWORD32(pid), ctypes.byref(sid)):
        return int(sid.value)
    return None


def current_session_id() -> Optional[int]:
    return process_session_id(os.getpid())


def _token_user_sid(token) -> str:
    a, k = _advapi32(), _kernel32()
    need = DWORD32(0)
    a.GetTokenInformation(token, winapi.TOKEN_USER, None, 0, ctypes.byref(need))
    if not need.value:
        return ""
    buf = ctypes.create_string_buffer(need.value)
    if not a.GetTokenInformation(token, winapi.TOKEN_USER, buf, need.value,
                                 ctypes.byref(need)):
        return ""
    sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
    out = WSTR()
    if not a.ConvertSidToStringSidW(ctypes.c_void_p(sid_ptr), ctypes.byref(out)):
        return ""
    try:
        return out.value or ""
    finally:
        k.LocalFree(out)


def _system_primary_token(pid: int) -> Optional[tuple]:
    """尝试把 ``pid`` 的 SYSTEM 令牌复制成主令牌。

    返回 ``(token_handle, sid)``；不是 SYSTEM 或打不开则返回 None。
    """
    a, k = _advapi32(), _kernel32()
    handle = k.OpenProcess(winapi.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        handle = k.OpenProcess(winapi.PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None
    token = HANDLE_T()
    try:
        if not a.OpenProcessToken(handle, TOKEN_QUERY | TOKEN_DUPLICATE,
                                  ctypes.byref(token)):
            return None
        sid = _token_user_sid(token)
        if sid != winapi.LOCAL_SYSTEM_SID:
            return None
        primary = HANDLE_T()
        if not a.DuplicateTokenEx(
                token, MAXIMUM_ALLOWED, None,
                SecurityImpersonation, TokenPrimary, ctypes.byref(primary)):
            return None
        return _handle_value(primary), sid
    finally:
        if _handle_value(token):
            k.CloseHandle(token)
        k.CloseHandle(handle)


@dataclass
class TokenSearch:
    """找 SYSTEM 令牌的结果（含诊断信息）。"""

    token: Optional[int] = None
    sid: str = ""
    pid: int = 0
    name: str = ""
    reason: str = ""
    tried: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.token)


def acquire_system_token() -> TokenSearch:
    """在当前会话里找一个可用的 SYSTEM 进程并复制其主令牌。"""
    result = TokenSearch()
    if not winapi.IS_WINDOWS:
        result.reason = "仅支持 Windows"
        return result
    try:
        return _acquire_system_token()
    except Exception as exc:  # pragma: no cover - 平台/权限异常兜底
        log.debug("获取 SYSTEM 令牌异常", exc_info=True)
        result.reason = f"获取 SYSTEM 令牌异常: {type(exc).__name__}: {exc}"
        return result


def _acquire_system_token() -> TokenSearch:
    result = TokenSearch()
    if not enable_privilege("SeDebugPrivilege"):
        result.reason = "无法打开 SeDebugPrivilege（需要管理员权限）"
        return result

    my_session = current_session_id()
    try:
        procs = [{"pid": pid, "name": name,
                  "session": process_session_id(pid)}
                 for pid, name in winapi.enum_processes()]
    except OSError as exc:
        result.reason = f"枚举进程失败: {exc}"
        return result

    candidates = ordered_candidates(procs, my_session)
    preferred = {n for n in PREFERRED_NAMES}
    fallback_tries = 0
    for cand in candidates:
        if cand["name"].lower() not in preferred:
            if fallback_tries >= MAX_FALLBACK_TRIES:
                break
            fallback_tries += 1
        got = _system_primary_token(int(cand["pid"]))
        if not got:
            result.tried.append(f"{cand['name']}#{cand['pid']}")
            continue
        token, sid = got
        result.token = token
        result.sid, result.pid, result.name = sid, int(cand["pid"]), cand["name"]
        log.info("已从 %s (pid=%s, session=%s) 复制到 SYSTEM 主令牌",
                 result.name, result.pid, cand.get("session"))
        return result
    result.reason = ("本会话没有可用的 SYSTEM 进程令牌"
                     f"（已试 {len(result.tried)} 个进程）")
    return result


@dataclass
class LaunchResult:
    ok: bool
    message: str
    method: str = ""
    pid: int = 0
    sid: str = ""
    source_pid: int = 0
    source_name: str = ""
    exit_code: Optional[int] = None


def _spawn_with_token(token, exe: str, cmdline: str, env: dict,
                      desktop: Optional[str], cwd: Optional[str],
                      wait: bool, timeout: float) -> tuple:
    """用给定令牌创建进程：先 CreateProcessAsUserW，失败回退 WithTokenW。"""
    a, k = _advapi32(), _kernel32()
    env_buf = build_environment_block(env)
    flags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP

    errors: list[str] = []
    cmd_buf = ctypes.create_unicode_buffer(cmdline)
    exe_buf = ctypes.create_unicode_buffer(exe)
    for method in ("CreateProcessAsUserW", "CreateProcessWithTokenW"):
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(STARTUPINFOW)
        si.lpDesktop = desktop
        pi = PROCESS_INFORMATION()
        ctypes.set_last_error(0)
        if method == "CreateProcessAsUserW":
            ok = a.CreateProcessAsUserW(
                token, exe_buf, cmd_buf, None, None, False, flags,
                ctypes.cast(env_buf, ctypes.c_void_p), cwd,
                ctypes.byref(si), ctypes.byref(pi))
        else:
            ok = a.CreateProcessWithTokenW(
                token, 0, exe_buf, cmd_buf, flags,
                ctypes.cast(env_buf, ctypes.c_void_p), cwd,
                ctypes.byref(si), ctypes.byref(pi))
        if ok:
            pid = int(pi.dwProcessId)
            code = None
            if wait and pi.hProcess:
                k.WaitForSingleObject(pi.hProcess, int(timeout * 1000))
                tmp = DWORD32()
                if k.GetExitCodeProcess(pi.hProcess, ctypes.byref(tmp)):
                    code = int(tmp.value)
            for h in (pi.hThread, pi.hProcess):
                if h:
                    k.CloseHandle(h)
            return True, method, pid, "", code
        errors.append(f"{method}: {winapi.format_error()}")
    return False, "", 0, "；".join(errors), None


def launch_as_system(extra_args: Optional[list] = None,
                     env_extra: Optional[dict] = None,
                     cwd: Optional[str] = None,
                     wait: bool = False,
                     timeout: float = 30.0) -> LaunchResult:
    """把当前程序以 SYSTEM 身份重新拉起（GUI 仍在当前桌面）。"""
    if not winapi.IS_WINDOWS:
        return LaunchResult(False, "仅支持 Windows")

    search = acquire_system_token()
    if not search.ok:
        return LaunchResult(False, search.reason or "未能取得 SYSTEM 令牌")

    k = _kernel32()
    token = HANDLE_T(search.token)
    exe, cmdline = relaunch_argv(extra_args)
    env = child_environment(env_extra)
    if not cwd:
        cwd = (str(Path(exe).resolve().parent)
               if getattr(sys, "frozen", False) else os.getcwd())

    try:
        # lpDesktop 先留空 = 继承父进程的窗口站/桌面（同会话下最稳），
        # 万一失败再显式指定交互桌面 winsta0\default 重试一次。
        for desktop in (None, "winsta0\\default"):
            ok, method, pid, err, code = _spawn_with_token(
                token, exe, cmdline, env, desktop, cwd, wait, timeout)
            if ok:
                log.info("已用 %s 以 SYSTEM 拉起自身, pid=%s（桌面=%s）",
                         method, pid, desktop or "继承")
                return LaunchResult(True, f"{method} 成功", method, pid,
                                    search.sid, search.pid, search.name,
                                    exit_code=code)
            if desktop is not None:
                return LaunchResult(False, err, "", 0, search.sid,
                                    search.pid, search.name)
            log.debug("继承桌面失败，改用 winsta0\\default 重试: %s", err)
        return LaunchResult(False, "创建进程失败", "", 0, search.sid,
                            search.pid, search.name)
    finally:
        k.CloseHandle(token)


def probe_identity() -> dict:
    """返回当前进程的身份信息（供 ``--system-probe`` 落盘用）。"""
    import getpass

    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - 极少数环境下取不到
        user = os.environ.get("USERNAME", "")
    return {
        "pid": os.getpid(),
        "privilege": winapi.current_privilege(),
        "sid": winapi.current_sid(),
        "user": user,
        "session": current_session_id(),
        "marker": is_launched_child(),
        "exe": sys.executable,
        "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
