"""Win32 / NT API 的 ctypes 封装。

所有与系统相关的原语都集中在这里，便于在其他平台安全导入做单元测试。
本模块只做「薄封装」：参数校验、业务判定一律放在 controller 里。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import sys
from typing import Optional

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------- 权限常量
PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000

PROCESS_ALL_ACCESS = 0x1F0FFF

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPTHREAD = 0x00000004
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

THREAD_QUERY_INFORMATION = 0x0040
THREAD_SUSPEND_COUNT = 35           # THREADINFOCLASS.ThreadSuspendCount

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04

TOKEN_QUERY = 0x0008
TOKEN_USER = 1

INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
LOCAL_SYSTEM_SID = "S-1-5-18"

# 绝不允许注入的系统关键进程：注入它们会直接蓝屏
CRITICAL_PROCESSES = {
    "system",
    "registry",
    "idle",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "fontdrvhost.exe",
    "dwm.exe",
    "sihost.exe",
    "wudfhost.exe",
    "memory compression",
}
CRITICAL_PIDS = {0, 4}


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ThreadID", wt.DWORD),
        ("th32OwnerProcessID", wt.DWORD),
        ("tpBasePri", wt.LONG),
        ("tpDeltaPri", wt.LONG),
        ("dwFlags", wt.DWORD),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wt.DWORD),
        ("hModule", wt.HMODULE),
        ("szModule", wt.WCHAR * 256),
        ("szExePath", wt.WCHAR * 260),
    ]


class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("PageFaultCount", wt.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


_kernel32 = None
_ntdll = None
_advapi32 = None


def kernel32():
    global _kernel32
    if _kernel32 is None:
        if not IS_WINDOWS:
            raise RuntimeError("SuperInject 仅支持 Windows")
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _kernel32.GetCurrentProcess.restype = wt.HANDLE
        _kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
        _kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
        _kernel32.CloseHandle.argtypes = [wt.HANDLE]
        _kernel32.OpenProcess.restype = wt.HANDLE
        _kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
        _kernel32.LoadLibraryW.restype = wt.HMODULE
        _kernel32.LoadLibraryW.argtypes = [wt.LPCWSTR]
        _kernel32.LocalFree.restype = wt.HLOCAL
        _kernel32.LocalFree.argtypes = [wt.HLOCAL]
        _kernel32.IsWow64Process.restype = wt.BOOL
        _kernel32.IsWow64Process.argtypes = [wt.HANDLE, ctypes.POINTER(wt.BOOL)]
    return _kernel32


def ntdll():
    global _ntdll
    if _ntdll is None:
        if not IS_WINDOWS:
            raise RuntimeError("SuperInject 仅支持 Windows")
        _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    return _ntdll


def advapi32():
    global _advapi32
    if _advapi32 is None:
        if not IS_WINDOWS:
            raise RuntimeError("SuperInject 仅支持 Windows")
        _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        _advapi32.OpenProcessToken.restype = wt.BOOL
        _advapi32.OpenProcessToken.argtypes = [
            wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
        _advapi32.GetTokenInformation.restype = wt.BOOL
        _advapi32.GetTokenInformation.argtypes = [
            wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD,
            ctypes.POINTER(wt.DWORD)]
        _advapi32.ConvertSidToStringSidW.restype = wt.BOOL
        _advapi32.ConvertSidToStringSidW.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(wt.LPWSTR)]
    return _advapi32


def last_error() -> int:
    return ctypes.get_last_error()


def format_error(code: Optional[int] = None) -> str:
    code = last_error() if code is None else code
    try:
        return ctypes.FormatError(code).strip()
    except Exception:  # pragma: no cover - 平台差异
        return f"Win32 error {code}"


def screen_work_area() -> Optional[tuple[int, int]]:
    """主屏可用区域（已去掉任务栏）的宽高；失败返回 None。

    用途：按屏幕算 GUI 初始尺寸 —— 早期版本把窗口写死成 1280x820 且
    min_size 1040x640，在小屏/高缩放的机器上窗口比屏幕还大，底部功能区
    永远露不出来。
    """
    if not IS_WINDOWS:
        return None
    try:
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        rect = wt.RECT()
        # SPI_GETWORKAREA = 0x0030
        if not user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0):
            return None
        w, h = int(rect.right - rect.left), int(rect.bottom - rect.top)
        if w <= 0 or h <= 0:
            return None
        return w, h
    except Exception:  # pragma: no cover - 老系统或非 Windows
        return None


# ---------------------------------------------------------------- 权限判定


def current_sid() -> str:
    """当前进程令牌的用户 SID 字符串（失败返回空串）。"""
    if not IS_WINDOWS:
        return ""
    a = advapi32()
    k = kernel32()
    token = wt.HANDLE()
    if not a.OpenProcessToken(k.GetCurrentProcess(), TOKEN_QUERY,
                              ctypes.byref(token)):
        return ""
    try:
        need = wt.DWORD(0)
        a.GetTokenInformation(token, TOKEN_USER, None, 0, ctypes.byref(need))
        if not need.value:
            return ""
        buf = ctypes.create_string_buffer(need.value)
        if not a.GetTokenInformation(token, TOKEN_USER, buf, need.value,
                                     ctypes.byref(need)):
            return ""
        sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        out = wt.LPWSTR()
        if not a.ConvertSidToStringSidW(ctypes.c_void_p(sid_ptr),
                                        ctypes.byref(out)):
            return ""
        try:
            return out.value or ""
        finally:
            k.LocalFree(out)
    finally:
        k.CloseHandle(token)


def is_system() -> bool:
    """当前是否以 SYSTEM（LocalSystem）身份运行。"""
    return current_sid() == LOCAL_SYSTEM_SID


def is_admin() -> bool:
    """当前令牌是否已提权（管理员或 SYSTEM）。"""
    if not IS_WINDOWS:
        return False
    try:
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        shell.IsUserAnAdmin.restype = wt.BOOL
        if shell.IsUserAnAdmin():
            return True
    except Exception:  # pragma: no cover
        pass
    return is_system()


def current_privilege() -> str:
    """返回 'system' / 'admin' / 'user'。"""
    if not IS_WINDOWS:
        return "user"
    if is_system():
        return "system"
    return "admin" if is_admin() else "user"


def is_elevated() -> bool:
    """当前进程是否具备管理员/SYSTEM 权限。"""
    return current_privilege() in ("admin", "system")


# ---------------------------------------------------------------- 进程枚举


def enum_processes() -> list[tuple[int, str]]:
    """返回 [(pid, exe_name)]，不含当前进程。"""
    k = kernel32()
    k.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]

    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (0, INVALID_HANDLE_VALUE):
        raise OSError(format_error(), "CreateToolhelp32Snapshot")

    out: list[tuple[int, str]] = []
    me = os_getpid()
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if k.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                pid = int(pe.th32ProcessID)
                if pid != me:
                    out.append((pid, pe.szExeFile))
                if not k.Process32NextW(snap, ctypes.byref(pe)):
                    break
    finally:
        k.CloseHandle(snap)
    return out


def enum_thread_ids(pid: int) -> list[int]:
    """枚举某个进程的全部线程 ID。"""
    k = kernel32()
    k.Thread32First.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
    k.Thread32Next.argtypes = [wt.HANDLE, ctypes.POINTER(THREADENTRY32)]
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
    if snap in (0, INVALID_HANDLE_VALUE):
        return []
    out: list[int] = []
    try:
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(THREADENTRY32)
        if k.Thread32First(snap, ctypes.byref(te)):
            while True:
                if int(te.th32OwnerProcessID) == int(pid):
                    out.append(int(te.th32ThreadID))
                if not k.Thread32Next(snap, ctypes.byref(te)):
                    break
    finally:
        k.CloseHandle(snap)
    return out


def enum_remote_modules(pid: int) -> list[dict]:
    """枚举目标进程已加载的模块（跨位数可能失败，返回空列表）。"""
    k = kernel32()
    k.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    k.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                      pid)
    if snap in (0, INVALID_HANDLE_VALUE):
        return []
    out: list[dict] = []
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if k.Module32FirstW(snap, ctypes.byref(me)):
            while True:
                out.append({
                    "name": me.szModule,
                    "path": me.szExePath,
                    "base": int(ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value or 0),
                    "size": int(me.modBaseSize),
                })
                if not k.Module32NextW(snap, ctypes.byref(me)):
                    break
    finally:
        k.CloseHandle(snap)
    return out


def module_loaded(pid: int, module_name: str) -> bool:
    """目标进程内是否已加载同名模块（用于识别「已注入」）。"""
    want = str(module_name).lower()
    try:
        return any(m["name"].lower() == want for m in enum_remote_modules(pid))
    except Exception:  # pragma: no cover
        return False


def os_getpid() -> int:
    import os

    return os.getpid()


def process_path(pid: int) -> str:
    """查询进程完整路径，失败返回空串。"""
    k = kernel32()
    k.QueryFullProcessImageNameW.argtypes = [
        wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD),
    ]
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        size = wt.DWORD(1024)
        buf = ctypes.create_unicode_buffer(size.value)
        if k.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        k.CloseHandle(h)


def pid_alive(pid: int) -> bool:
    """进程是否仍然存活。

    不能用「能拿到查询句柄就算存活」：目标退出后，只要还有别的进程/本进程
    持有它的句柄（例如 subprocess.Popen 对象尚未回收），内核里那个进程对象
    就不会销毁，OpenProcess 依然成功 —— selftest 里就因此把「DLL 成功
    ExitProcess 自杀」误判成「目标进程仍存活」（19 步里唯一的红）。
    改用 GetExitCodeProcess：只要不等于 STILL_ACTIVE 就是已退出。
    """
    STILL_ACTIVE = 259
    try:
        h = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)
    except Exception:  # pragma: no cover
        return False
    if not h:
        return False
    try:
        code = wt.DWORD(0)
        k = kernel32()
        k.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]
        k.GetExitCodeProcess.restype = wt.BOOL
        if not k.GetExitCodeProcess(h, ctypes.byref(code)):
            return False
        return code.value == STILL_ACTIVE
    finally:
        kernel32().CloseHandle(h)


def process_name(pid: int) -> str:
    """按 PID 查进程名，失败返回空串。"""
    for p, name in enum_processes():
        if p == pid:
            return name
    return ""


def is_wow64(pid: int) -> Optional[bool]:
    """目标进程是否为 32 位（在 64 位系统上运行）。无法判定返回 None。"""
    if not IS_WINDOWS:
        return None
    k = kernel32()
    h = k.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        wow = wt.BOOL(0)
        if not k.IsWow64Process(h, ctypes.byref(wow)):
            return None
        return bool(wow.value)
    finally:
        k.CloseHandle(h)


def _get_process_memory_info():
    """定位 GetProcessMemoryInfo：Win10+ 在 kernel32(K32…)，旧系统在 psapi。"""
    k = kernel32()
    for name in ("K32GetProcessMemoryInfo", "GetProcessMemoryInfo"):
        if hasattr(k, name):
            fn = getattr(k, name)
            fn.restype = wt.BOOL
            fn.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wt.DWORD]
            return fn
    try:
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        fn = psapi.GetProcessMemoryInfo
        fn.restype = wt.BOOL
        fn.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wt.DWORD]
        return fn
    except (OSError, AttributeError):  # pragma: no cover
        return None


def process_memory_mb(pid: int) -> float:
    """进程工作集大小（MB）。任何失败都返回 0，不影响进程列表渲染。"""
    try:
        k = kernel32()
        fn = _get_process_memory_info()
        if fn is None:
            return 0.0
        h = open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        if not h:
            return 0.0
        try:
            c = PROCESS_MEMORY_COUNTERS()
            c.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if not fn(h, ctypes.byref(c), ctypes.sizeof(c)):
                return 0.0
            return round(c.WorkingSetSize / (1024 * 1024), 1)
        finally:
            k.CloseHandle(h)
    except Exception:  # pragma: no cover - 任何异常都不应中断列表
        return 0.0


# ---------------------------------------------------------------- 进程控制


def open_process(pid: int, access: int = PROCESS_ALL_ACCESS) -> wt.HANDLE:
    return kernel32().OpenProcess(access, False, pid)


def close_handle(handle) -> None:
    """关闭句柄，失败不抛异常（句柄无效/句柄为 0 都不该影响主流程）。"""
    if not handle:
        return
    try:
        kernel32().CloseHandle(handle)
    except Exception:  # pragma: no cover - 非 Windows 或已关闭
        pass


def terminate_process(pid: int) -> bool:
    k = kernel32()
    k.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]
    h = open_process(pid, PROCESS_TERMINATE)
    if not h:
        return False
    try:
        return bool(k.TerminateProcess(h, 0))
    finally:
        k.CloseHandle(h)


def suspend_process(pid: int) -> bool:
    """冻结进程（挂起全部线程），使其完全无响应。"""
    n = ntdll()
    n.NtSuspendProcess.restype = wt.LONG
    n.NtSuspendProcess.argtypes = [wt.HANDLE]
    h = open_process(pid, PROCESS_SUSPEND_RESUME)
    if not h:
        return False
    try:
        return n.NtSuspendProcess(h) == 0
    finally:
        kernel32().CloseHandle(h)


def resume_process(pid: int) -> bool:
    """恢复被冻结的进程。"""
    n = ntdll()
    n.NtResumeProcess.restype = wt.LONG
    n.NtResumeProcess.argtypes = [wt.HANDLE]
    h = open_process(pid, PROCESS_SUSPEND_RESUME)
    if not h:
        return False
    try:
        return n.NtResumeProcess(h) == 0
    finally:
        kernel32().CloseHandle(h)


def thread_suspend_count(tid: int) -> Optional[int]:
    """查询线程的挂起计数（>0 表示被挂起）。失败返回 None。"""
    if not IS_WINDOWS:
        return None
    k = kernel32()
    n = ntdll()
    k.OpenThread.restype = wt.HANDLE
    k.OpenThread.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    n.NtQueryInformationThread.restype = wt.LONG
    n.NtQueryInformationThread.argtypes = [
        wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.ULONG,
        ctypes.POINTER(wt.ULONG)]
    h = k.OpenThread(THREAD_QUERY_INFORMATION, False, tid)
    if not h:
        return None
    try:
        count = wt.ULONG(0)
        ret_len = wt.ULONG(0)
        status = n.NtQueryInformationThread(
            h, THREAD_SUSPEND_COUNT, ctypes.byref(count),
            ctypes.sizeof(count), ctypes.byref(ret_len))
        return int(count.value) if status == 0 else None
    finally:
        k.CloseHandle(h)


def process_suspend_state(pid: int) -> Optional[bool]:
    """判断进程是否处于「全部线程被挂起」状态。

    返回 True=已冻结 / False=运行中 / None=无法判定（权限或平台限制）。
    """
    if not IS_WINDOWS:
        return None
    tids = enum_thread_ids(pid)
    if not tids:
        return None
    counts: list[int] = []
    for tid in tids:
        c = thread_suspend_count(tid)
        if c is not None:
            counts.append(c)
    if not counts:
        return None
    return all(c > 0 for c in counts)


# ---------------------------------------------------------------- 注入


def _loadlibrary_address(pid: int) -> int:
    """取得**目标进程内**的 ``kernel32!LoadLibraryW`` 地址。

    跨位数注入的关键：kernel32 在同登录会话的同位数进程中加载于相同基址，
    但 x86/x64 两套 kernel32 的基址不同 —— 直接用本进程 (controller) 的
    kernel32 地址给 32 位目标用，会跳到错误的代码（LoadLibraryW 看似返回 0，
    实际上根本没有执行到目标进程的代码里）。

    取地址的标准做法：枚举目标进程已加载模块，找到 ``kernel32.dll``，
    再根据其导出表解析 ``LoadLibraryW``。失败时返回 0（让 caller 报「位数不匹配」）。
    """
    import logging
    k = kernel32()
    k.GetModuleHandleW.argtypes = [wt.LPCWSTR]
    k.GetModuleHandleW.restype = wt.HMODULE
    k.GetProcAddress.argtypes = [wt.HMODULE, wt.LPCSTR]
    k.GetProcAddress.restype = ctypes.c_void_p

    # 1) 目标进程里的 kernel32.dll 基址
    try:
        mods = enum_remote_modules(pid)
    except Exception as exc:  # pragma: no cover
        logging.getLogger("supinject.winapi").warning(
            "枚举目标 %d 模块失败: %s", pid, exc)
        mods = []
    logging.getLogger("supinject.winapi").debug(
        "目标 %d 模块枚举: %d 条 (含 %s)",
        pid, len(mods), [m["name"] for m in mods[:5]])
    base = 0
    for m in mods:
        if m["name"].lower() in ("kernel32.dll", "kernelbase.dll"):
            base = m["base"]
            break
    if not base:
        # fallback：本进程（同位数时是正确的）
        return int(ctypes.cast(k.LoadLibraryW, ctypes.c_void_p).value or 0)

    # 2) 用 ReadProcessMemory 解析 PE 导出表，拿 LoadLibraryW 的 RVA。
    # 关键：导出表地址字段在可选头里，PE32 (x86) 偏移 0x60，PE32+ (x64) 偏移 0x78，
    # 通用做法是从 ``IMAGE_OPTIONAL_HEADER.Magic`` 判断（PE32=0x10b / PE32+=0x20b）。
    log = logging.getLogger("supinject.winapi")
    try:
        pe_offset = int(_read_remote_u32(pid, base + 0x3C))
        opt_magic = int(_read_remote_u16(pid, base + pe_offset + 0x18))
        export_table_offset = 0x78 if opt_magic == 0x20b else 0x60
        export_rva = int(_read_remote_u32(pid, base + pe_offset + export_table_offset))
        log.debug("目标 %d kernel32 base=%#x pe=%#x magic=0x%x export_rva=%#x",
                  pid, base, pe_offset, opt_magic, export_rva)
        number_of_names = int(_read_remote_u32(pid, base + export_rva + 0x18))
        names_rva = int(_read_remote_u32(pid, base + export_rva + 0x20))
        ordinals_rva = int(_read_remote_u32(pid, base + export_rva + 0x24))
        functions_rva = int(_read_remote_u32(pid, base + export_rva + 0x1C))
        for i in range(number_of_names):
            name_rva = int(_read_remote_u32(pid, base + names_rva + i * 4))
            name_buf = _read_remote_bytes(pid, base + name_rva, 32)
            if not name_buf:
                continue
            try:
                end = name_buf.index(0)
            except ValueError:
                end = name_buf.index(b"\x00\x00\x00\x00") if b"\x00\x00\x00\x00" in name_buf else len(name_buf)
            name = bytes(name_buf[:end]).decode("ascii", errors="replace")
            if name == "LoadLibraryW":
                ordinal = int(_read_remote_u16(pid, base + ordinals_rva + i * 2))
                func_rva = int(_read_remote_u32(pid, base + functions_rva + ordinal * 4))
                addr = base + func_rva
                log.debug("目标 %d LoadLibraryW = %#x", pid, addr)
                return addr
        log.warning("目标 %d kernel32 导出表未找到 LoadLibraryW（共 %d 个名字）",
                    pid, number_of_names)
    except Exception as exc:  # pragma: no cover - 任何解析失败都退回到本进程地址
        log.warning("目标 %d 解析 LoadLibraryW 失败: %s", pid, exc)
    return int(ctypes.cast(k.LoadLibraryW, ctypes.c_void_p).value or 0)


def _read_remote_u32(pid: int, addr: int) -> int:
    return struct.unpack_from("<I", read_process_memory(pid, addr, 4), 0)[0]


def _read_remote_u16(pid: int, addr: int) -> int:
    return struct.unpack_from("<H", read_process_memory(pid, addr, 2), 0)[0]


def _read_remote_bytes(pid: int, addr: int, n: int) -> bytes:
    return read_process_memory(pid, addr, n)


def inject_dll(pid: int, dll_path: str, timeout: float = 15.0) -> int:
    """通过 CreateRemoteThread + LoadLibraryW 把 DLL 注入目标进程。

    返回远程线程的退出码（DLL 的 HMODULE，失败为 0）。
    """
    import os

    k = kernel32()
    k.VirtualAllocEx.restype = wt.LPVOID
    k.VirtualAllocEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t,
                                 wt.DWORD, wt.DWORD]
    k.WriteProcessMemory.restype = wt.BOOL
    k.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID,
                                     ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k.CreateRemoteThread.restype = wt.HANDLE
    k.CreateRemoteThread.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t,
                                     wt.LPVOID, wt.LPVOID, wt.DWORD,
                                     ctypes.POINTER(wt.DWORD)]
    k.VirtualFreeEx.restype = wt.BOOL
    k.VirtualFreeEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD]
    k.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    k.GetExitCodeThread.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]

    dll_path = os.path.abspath(dll_path)
    data = (dll_path + "\0").encode("utf-16-le")
    size = len(data)

    h = open_process(
        pid,
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION
        | PROCESS_VM_WRITE | PROCESS_VM_READ,
    )
    if not h:
        raise OSError(format_error(), f"OpenProcess({pid}) 失败，请确认已提权")

    # 关键：用目标进程内的 LoadLibraryW 地址（跨位数时本进程地址无效）
    target_loadlibrary = _loadlibrary_address(pid)
    if not target_loadlibrary:
        k.CloseHandle(h)
        raise OSError("无法解析目标进程内 kernel32!LoadLibraryW 的地址")

    remote = k.VirtualAllocEx(h, None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not remote:
        err = last_error()
        k.CloseHandle(h)
        raise OSError(format_error(err), "VirtualAllocEx 失败")

    try:
        written = ctypes.c_size_t(0)
        if not k.WriteProcessMemory(h, remote, data, size, ctypes.byref(written)):
            err = last_error()
            raise OSError(format_error(err), "WriteProcessMemory 失败")
        if written.value != size:
            raise OSError("WriteProcessMemory 写入长度不符")

        tid = wt.DWORD(0)
        t = k.CreateRemoteThread(h, None, 0,
                                 ctypes.c_void_p(target_loadlibrary),
                                 remote, 0, ctypes.byref(tid))
        if not t:
            err = last_error()
            raise OSError(format_error(err), "CreateRemoteThread 失败")

        k.WaitForSingleObject(t, int(timeout * 1000))
        exit_code = wt.DWORD(0)
        k.GetExitCodeThread(t, ctypes.byref(exit_code))
        k.CloseHandle(t)
        return int(exit_code.value)
    finally:
        k.VirtualFreeEx(h, remote, 0, MEM_RELEASE)
        k.CloseHandle(h)


def read_process_memory(pid: int, address: int, size: int) -> bytes:
    """读目标进程内存；优先 ``ReadProcessMemory``，失败时回退 ``NtReadVirtualMemory``。

    跨位数（x64 controller 读 x86 进程）时 ``ReadProcessMemory`` 偶尔会因
    ctypes 的 argtype 设置在单测 ``monkeypatch`` 下被洗掉 / 函数指针查错
    而 False（Function/Program）。``NtReadVirtualMemory`` 是 ntdll 的原生入口，
    不走 LPCVOID 自动转换这一层，更稳；这里就把它当 fallback 用。
    """
    k = kernel32()
    k.ReadProcessMemory.restype = wt.BOOL
    k.ReadProcessMemory.argtypes = [wt.HANDLE, wt.LPCVOID, wt.LPVOID,
                                    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    h = open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
    if not h:
        raise OSError(format_error(), "OpenProcess 读取内存失败")
    try:
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t(0)
        if k.ReadProcessMemory(h, wt.LPVOID(address), buf, size, ctypes.byref(got)) \
                and got.value == size:
            return bytes(bytearray(buf[: got.value]))
    finally:
        k.CloseHandle(h)

    # Fallback: NtReadVirtualMemory
    h2 = open_process(pid, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
    if not h2:
        return b""
    try:
        n = ntdll()
        n.NtReadVirtualMemory.restype = wt.LONG
        n.NtReadVirtualMemory.argtypes = [
            wt.HANDLE, wt.LPCVOID, wt.LPVOID,
            ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t(0)
        status = n.NtReadVirtualMemory(h2, wt.LPVOID(address), buf, size, ctypes.byref(got))
        if status == 0 and got.value == size:
            return bytes(bytearray(buf[: got.value]))
        return b""
    finally:
        k.CloseHandle(h2)


def write_process_memory(pid: int, address: int, data: bytes) -> int:
    k = kernel32()
    k.WriteProcessMemory.restype = wt.BOOL
    k.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID,
                                     ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    h = open_process(
        pid, PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION
    )
    if not h:
        raise OSError(format_error(), "OpenProcess 写入内存失败")
    try:
        buf = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        put = ctypes.c_size_t(0)
        if not k.WriteProcessMemory(h, wt.LPVOID(address), buf, len(data), ctypes.byref(put)):
            return 0
        return int(put.value)
    finally:
        k.CloseHandle(h)
