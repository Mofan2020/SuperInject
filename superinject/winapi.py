"""Win32 / NT API 的 ctypes 封装。

所有与系统相关的原语都集中在这里，便于在其他平台安全导入做单元测试。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import sys
from typing import Optional

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------- 权限常量
PROCESS_TERMINATE = 0x0001
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_CREATE_THREAD = 0x0002
PROCESS_SUSPEND_RESUME = 0x0800
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
SYNCHRONIZE = 0x00100000

PROCESS_ALL_ACCESS = 0x1F0FFF

TH32CS_SNAPPROCESS = 0x00000002

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04


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


def kernel32():
    global _kernel32
    if _kernel32 is None:
        if not IS_WINDOWS:
            raise RuntimeError("SuperInject 仅支持 Windows")
        _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return _kernel32


def ntdll():
    global _ntdll
    if _ntdll is None:
        if not IS_WINDOWS:
            raise RuntimeError("SuperInject 仅支持 Windows")
        _ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    return _ntdll


def last_error() -> int:
    return ctypes.get_last_error()


def format_error(code: Optional[int] = None) -> str:
    code = last_error() if code is None else code
    try:
        return ctypes.FormatError(code).strip()
    except Exception:  # pragma: no cover - 平台差异
        return f"Win32 error {code}"


# ---------------------------------------------------------------- 进程枚举


def enum_processes() -> list[tuple[int, str]]:
    """返回 [(pid, exe_name)]，不含当前进程。"""
    k = kernel32()
    k.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]

    snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1 or snap == 0xFFFFFFFFFFFFFFFF:
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


def process_memory_mb(pid: int) -> float:
    k = kernel32()
    k.GetProcessMemoryInfo.argtypes = [
        wt.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wt.DWORD,
    ]
    h = k.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        return 0.0
    try:
        c = PROCESS_MEMORY_COUNTERS()
        c.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
        if not k.GetProcessMemoryInfo(h, ctypes.byref(c), ctypes.sizeof(c)):
            return 0.0
        return round(c.WorkingSetSize / (1024 * 1024), 1)
    finally:
        k.CloseHandle(h)


def is_elevated() -> bool:
    """当前进程是否以管理员/SYSTEM 身份运行。"""
    if not IS_WINDOWS:
        return False
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    advapi.OpenProcessToken.restype = wt.HANDLE
    advapi.OpenProcessToken.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.HANDLE)]
    advapi.GetTokenInformation.restype = wt.BOOL
    advapi.GetTokenInformation.argtypes = [
        wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD),
    ]

    class TOKEN_ELEVATION(ctypes.Structure):
        _fields_ = [("TokenIsElevated", wt.DWORD)]

    # 直接使用 Shell32 的 IsUserAnAdmin 简单可靠
    shell.IsUserAnAdmin.restype = wt.BOOL
    return bool(shell.IsUserAnAdmin())


# ---------------------------------------------------------------- 进程控制


def open_process(pid: int, access: int = PROCESS_ALL_ACCESS) -> wt.HANDLE:
    k = kernel32()
    k.OpenProcess.restype = wt.HANDLE
    k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    return k.OpenProcess(access, False, pid)


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
        k = kernel32()
        k.CloseHandle(h)


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
        k = kernel32()
        k.CloseHandle(h)


def is_suspended(pid: int) -> bool:
    """占位：Windows 未提供公开的「进程是否被挂起」查询。

    实际使用中由 Controller 自行记录冻结状态（见 Controller._frozen），
    因此这里不做猜测性实现。
    """
    return False


# ---------------------------------------------------------------- 注入


def _loadlibrary_address() -> int:
    """取得 kernel32!LoadLibraryW 地址（同一架构下所有进程地址一致）。"""
    k = kernel32()
    k.LoadLibraryW.restype = wt.HMODULE
    k.LoadLibraryW.argtypes = [wt.LPCWSTR]
    # 用一个必定存在的模块取地址，避免真的加载
    addr = ctypes.cast(k.LoadLibraryW, ctypes.c_void_p).value
    return int(addr or 0)


def inject_dll(pid: int, dll_path: str, timeout: float = 15.0) -> int:
    """通过 CreateRemoteThread + LoadLibraryW 把 DLL 注入目标进程。

    返回远程线程的退出码（DLL 的 HMODULE，失败为 0）。
    """
    import os
    import time

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
        t = k.CreateRemoteThread(h, None, 0, ctypes.c_void_p(_loadlibrary_address()),
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
        if not k.ReadProcessMemory(h, wt.LPVOID(address), buf, size, ctypes.byref(got)):
            return b""
        return bytes(bytearray(buf[: got.value]))
    finally:
        k.CloseHandle(h)


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
