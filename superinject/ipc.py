"""注入端 DLL 与控制器之间的命名管道 IPC。

协议（纯 Python 部分与 Windows 解耦，便于单测）：

    帧 = 4 字节小端长度 + UTF-8 JSON

控制器为每个目标进程预先创建 ``\\\\.\\pipe\\SuperInject-<控制器PID>-<目标PID>``，
注入端 DLL 启动后主动连接，形成反向控制通道。
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import json
import logging
import queue
import struct
import threading
import time
from typing import Callable, Dict, Optional

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
    k.FlushFileBuffers.restype = wt.BOOL
    k.FlushFileBuffers.argtypes = [wt.HANDLE]
    k.CloseHandle.restype = wt.BOOL
    k.CloseHandle.argtypes = [wt.HANDLE]
    k.CreateFileW.restype = wt.HANDLE
    k.CreateFileW.argtypes = [
        wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE,
    ]
    # 读写必须显式声明签名：否则 64 位 HANDLE 会被按 32 位 int 传参
    k.WriteFile.restype = wt.BOOL
    k.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                            ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
    k.ReadFile.restype = wt.BOOL
    k.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                           ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
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

    def send(self, payload: dict, timeout: float = 10.0) -> None:
        """把一帧写进管道。

        写入放在独立线程里做并设上限：如果目标进程的注入端卡住（例如它自己
        阻塞在别的地方），内核里的 WriteFile 会一直不返回，整个界面/测试就
        会跟着卡死。超时后主动关闭连接，让阻塞的调用立刻返回错误。
        """
        data = encode_frame(payload)
        box: dict = {}

        def worker() -> None:
            try:
                self._send_blocking(data)
                box["ok"] = True
            except Exception as exc:      # pragma: no cover - 依赖真实管道
                box["error"] = exc

        t = threading.Thread(target=worker, name=f"si-send-{self.pid}",
                             daemon=True)
        t.start()
        t.join(timeout)
        if t.is_alive():
            log.warning("写入管道超时 %ss (pid=%s)，关闭连接", timeout, self.pid)
            self.close()
            raise TimeoutError(f"写入管道超时（{timeout}s），目标进程可能已无响应")
        if "error" in box:
            raise box["error"]

    def _send_blocking(self, data: bytes) -> None:
        k = _win_pipes()
        with self._write_lock:
            sent = 0
            total = len(data)
            buf = (ctypes.c_ubyte * total).from_buffer_copy(data)
            while sent < total:
                n = ctypes.c_ulong(0)
                if not k.WriteFile(ctypes.c_void_p(self.handle),
                                   ctypes.byref(buf, sent),
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

    def attached_pids(self) -> set[int]:
        """当前已建立控制通道的目标 PID 集合。"""
        with self._lock:
            return {pid for pid, c in self._conns.items() if c.alive}

    def wait_attach(self, pid: int, timeout: float = 10.0,
                    interval: float = 0.05) -> bool:
        """等待注入端建立连接（注入后确认控制通道真的通了）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_attached(pid):
                return True
            if pid not in self._targets:
                return False
            time.sleep(interval)
        return self.is_attached(pid)

    def wait_detach(self, pid: int, timeout: float = 8.0,
                    interval: float = 0.05) -> bool:
        """等待目标进程断开（卸载 DLL / 进程退出后使用）。"""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.is_attached(pid):
                return True
            time.sleep(interval)
        return not self.is_attached(pid)

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
        log.debug("发送命令 pid=%s type=%s id=%s", pid, cmd.get("type"), mid)
        try:
            conn.send(payload, timeout=max(2.0, min(timeout, 10.0)))
            log.debug("命令已写入 pid=%s id=%s bytes=%s", pid, mid,
                      len(payload) and len(encode_frame(payload)))
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
        log.debug("管道已创建 pid=%s name=%s handle=%s", pid, name, handle)
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
        log.debug("管道已连接 pid=%s", pid)
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
        """读一大块原始数据（帧的切分交给 decode_frames）。

        缓冲必须够大：管道两端阻塞读写时，接收方挂着的读请求缓冲过小会让
        对端的写入迟迟完不成（注入端按 4 字节读帧头时实测会双方死等）。
        """
        k = _win_pipes()
        k.ReadFile.restype = wt.BOOL
        k.ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
                               ctypes.POINTER(ctypes.c_ulong), ctypes.c_void_p]
        size = 1 << 20
        buf = (ctypes.c_ubyte * size)()
        n = ctypes.c_ulong(0)
        if not k.ReadFile(ctypes.c_void_p(handle), buf, size, ctypes.byref(n), None):
            return b""
        if n.value == 0:
            return b""
        return bytes(bytearray(buf[: n.value]))

    def _dispatch(self, pid: int, conn: Connection, msg: dict) -> None:
        mtype = msg.get("type")
        log.debug("收到消息 pid=%s type=%s id=%s", pid, mtype, msg.get("id"))
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
