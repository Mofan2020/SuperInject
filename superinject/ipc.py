"""注入端 DLL 与控制器之间的命名管道 IPC。

协议（纯 Python 部分与 Windows 解耦，便于单测）：

    帧 = 4 字节小端长度 + UTF-8 JSON

控制器为每个目标进程预先创建 ``\\\\.\\pipe\\SuperInject-<控制器PID>-<目标PID>``，
注入端 DLL 启动后主动连接，形成反向控制通道。
"""

from __future__ import annotations

import ctypes
import json
import logging
import queue
import struct
import threading
import time
from typing import Any, Callable, Dict, Optional

from .version import pipe_name

log = logging.getLogger("supinject.ipc")

MAX_FRAME = 64 * 1024 * 1024

# ------------------------------------------------------------- 帧编解码


def encode_frame(payload: dict) -> bytes:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def decode_frames(buffer: bytearray) -> tuple[list[dict], bytearray]:
    """从缓冲区中解析出所有完整帧，返回 (帧列表, 剩余缓冲)。"""
    out: list[dict] = []
    while True:
        if len(buffer) < 4:
            break
        (size,) = struct.unpack_from("<I", buffer, 0)
        if size == 0 or size > MAX_FRAME:
            raise ValueError(f"非法帧长度: {size}")
        if len(buffer) < 4 + size:
            break
        body = bytes(buffer[4:4 + size])
        del buffer[: 4 + size]
        out.append(json.loads(body.decode("utf-8")))
    return out, buffer


# ------------------------------------------------------------- Windows 管道


def _win_pipes():
    import ctypes
    from ctypes import wintypes as wt

    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateNamedPipeW.restype = wt.HANDLE
    k.CreateNamedPipeW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
        ctypes.c_void_p,
    ]
    k.ConnectNamedPipe.restype = wt.BOOL
    k.ConnectNamedPipe.argtypes = [wt.HANDLE, ctypes.c_void_p]
    k.DisconnectNamedPipe.restype = wt.BOOL
    k.DisconnectNamedPipe.argtypes = [wt.HANDLE]
    k.CloseHandle.argtypes = [wt.HANDLE]
    k.CreateFileW.restype = wt.HANDLE
    k.CreateFileW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE,
    ]
    return k


PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_UNLIMITED_INSTANCES = 255
ERROR_PIPE_CONNECTED = 535
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class Connection:
    """单个目标进程的管道连接。"""

    def __init__(self, handle: int, pid: int):
        self.handle = handle
        self.pid = pid
        self.info: dict = {}
        self.alive = True
        self._write_lock = threading.Lock()

    def send(self, payload: dict) -> None:
        data = encode_frame(payload)
        k = _win_pipes()
        with self._write_lock:
            sent = 0
            total = len(data)
            buf = (ctypes.c_ubyte * total).from_buffer_copy(data)
            while sent < total:
                n = ctypes.c_ulong(0)
                if not k.WriteFile(self.handle, ctypes.byref(buf, sent),
                                   total - sent, ctypes.byref(n), None):
                    raise OSError(ctypes.get_last_error(), "WriteFile")
                if n.value == 0:
                    raise OSError("管道已断开")
                sent += n.value

    def close(self) -> None:
        if self.handle:
            try:
                _win_pipes().CloseHandle(self.handle)
            except Exception:  # pragma: no cover
                pass
        self.handle = 0
        self.alive = False


class PipeServer:
    """为多个目标进程维护反向管道连接，并提供请求/响应匹配。"""

    def __init__(self, controller_pid: Optional[int] = None):
        import os

        self.controller_pid = controller_pid or os.getpid()
        self._conns: Dict[int, Connection] = {}
        self._waiters: Dict[int, queue.Queue] = {}
        self._targets: set[int] = set()
        self._threads: Dict[int, threading.Thread] = {}
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._seq = 0
        self.on_attach: Optional[Callable[[int, dict], None]] = None
        self.on_detach: Optional[Callable[[int], None]] = None

    # -------------------------------------------------- 公共 API

    def register(self, pid: int) -> None:
        """为目标进程创建监听管道并启动接收线程。"""
        with self._lock:
            if pid in self._targets:
                return
            self._targets.add(pid)
        t = threading.Thread(target=self._serve, args=(pid,),
                             name=f"si-pipe-{pid}", daemon=True)
        with self._lock:
            self._threads[pid] = t
        t.start()

    def unregister(self, pid: int) -> None:
        with self._lock:
            self._targets.discard(pid)
            conn = self._conns.pop(pid, None)
        if conn:
            conn.close()

    def is_attached(self, pid: int) -> bool:
        with self._lock:
            conn = self._conns.get(pid)
        return bool(conn and conn.alive)

    def targets(self) -> set[int]:
        return set(self._targets)

    def request(self, pid: int, cmd: dict, timeout: float = 20.0) -> dict:
        """向目标进程发送一条命令并等待响应。"""
        with self._lock:
            conn = self._conns.get(pid)
            self._seq += 1
            mid = self._seq
        if not conn or not conn.alive:
            return {"ok": False, "error": "目标进程未连接（DLL 未注入或已卸载）"}
        q: queue.Queue = queue.Queue(maxsize=1)
        with self._lock:
            self._waiters[mid] = q
        payload = dict(cmd)
        payload["id"] = mid
        try:
            conn.send(payload)
        except Exception as exc:  # pragma: no cover - 管道断开
            with self._lock:
                self._waiters.pop(mid, None)
            return {"ok": False, "error": f"发送失败: {exc}"}
        try:
            resp = q.get(timeout=timeout)
        except queue.Empty:
            return {"ok": False, "error": f"命令超时 ({timeout}s)"}
        finally:
            with self._lock:
                self._waiters.pop(mid, None)
        return resp

    def broadcast(self, pids: list[int], cmd: dict, timeout: float = 20.0
                  ) -> Dict[int, dict]:
        """批量向多个已注入进程发送同一条命令。"""
        return {pid: self.request(pid, cmd, timeout) for pid in pids}

    def shutdown(self) -> None:
        self._stop.set()
        with self._lock:
            conns = list(self._conns.values())
            self._conns.clear()
        for c in conns:
            c.close()

    # -------------------------------------------------- 内部实现

    def _create_pipe(self, pid: int) -> int:
        k = _win_pipes()
        name = pipe_name(self.controller_pid, pid)
        handle = k.CreateNamedPipeW(
            name, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            1 << 20, 1 << 20, 5000, None,
        )
        if handle in (0, INVALID_HANDLE_VALUE):
            raise OSError(ctypes.get_last_error(), f"CreateNamedPipe {name}")
        return handle

    def _serve(self, pid: int) -> None:
        while not self._stop.is_set() and pid in self._targets:
            try:
                handle = self._create_pipe(pid)
            except OSError:
                log.exception("创建管道失败 pid=%s", pid)
                return
            k = _win_pipes()
            try:
                ok = k.ConnectNamedPipe(handle, None)
                if not ok and ctypes.get_last_error() != ERROR_PIPE_CONNECTED:
                    raise OSError(ctypes.get_last_error(), "ConnectNamedPipe")
                self._handle_connection(pid, handle)
            except Exception:
                log.debug("连接结束 pid=%s", pid, exc_info=True)
            finally:
                try:
                    k.DisconnectNamedPipe(handle)
                    k.CloseHandle(handle)
                except Exception:  # pragma: no cover
                    pass
        with self._lock:
            self._threads.pop(pid, None)

    def _handle_connection(self, pid: int, handle: int) -> None:
        conn = Connection(handle, pid)
        with self._lock:
            self._conns[pid] = conn
        buf = bytearray()
        try:
            while not self._stop.is_set():
                chunk = self._read_exact_chunk(handle)
                if not chunk:
                    break
                buf.extend(chunk)
                frames, buf = decode_frames(buf)
                for msg in frames:
                    self._dispatch(pid, conn, msg)
        finally:
            conn.close()
            with self._lock:
                if self._conns.get(pid) is conn:
                    self._conns.pop(pid, None)
            if self.on_detach:
                try:
                    self.on_detach(pid)
                except Exception:  # pragma: no cover
                    pass

    def _read_exact_chunk(self, handle: int) -> bytes:
        import ctypes.wintypes as wt

        k = _win_pipes()
        k.ReadFile.restype = wt.BOOL
        k.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                               ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
        size = 65536
        buf = (ctypes.c_ubyte * size)()
        n = ctypes.c_ulong(0)
        if not k.ReadFile(ctypes.c_void_p(handle), buf, size, ctypes.byref(n), None):
            return b""
        if n.value == 0:
            return b""
        return bytes(bytearray(buf[: n.value]))

    def _dispatch(self, pid: int, conn: Connection, msg: dict) -> None:
        mtype = msg.get("type")
        if mtype == "hello":
            conn.info = msg
            if self.on_attach:
                try:
                    self.on_attach(pid, msg)
                except Exception:  # pragma: no cover
                    log.exception("on_attach 回调失败")
            return
        mid = msg.get("id")
        with self._lock:
            q = self._waiters.get(mid)
        if q is not None:
            try:
                q.put_nowait(msg)
            except queue.Full:  # pragma: no cover
                pass


# ------------------------------------------------------------- 纯逻辑辅助


def normalize_hex(text: str) -> tuple[str, str]:
    """把用户输入的十六进制模式串规范化为 (pattern, mask)。

    支持形如 ``4D 5A ?? ??`` 的通配写法，``?`` 表示任意字节（mask 为 0）。
    """
    pattern: list[str] = []
    mask: list[str] = []
    for token in str(text).replace(",", " ").split():
        t = token.strip().lower()
        if not t:
            continue
        if t in {"??", "?", "..", "*"}:
            pattern.append("00")
            mask.append("00")
            continue
        if t in {"???", "???"}:
            raise ValueError(f"无法解析的字节: {token}")
        if len(t) % 2 == 0 and all(c in "0123456789abcdef" for c in t):
            for i in range(0, len(t), 2):
                pattern.append(t[i:i + 2])
                mask.append("ff")
            continue
        raise ValueError(f"无法解析的字节: {token}")
    if not pattern:
        raise ValueError("模式为空")
    return "".join(pattern), "".join(mask)


def parse_int(text: str, default: int = 0) -> int:
    t = str(text).strip().lower().replace("_", "")
    try:
        if t.startswith("0x"):
            return int(t, 16)
        return int(t, 10)
    except ValueError:
        return default


def now_ms() -> int:
    return int(time.time() * 1000)
