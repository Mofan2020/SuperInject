r"""命名管道桥：把 MCP 请求从「无权限 launcher」转交给已提权的主进程执行。

为什么需要它：Agent（Claude Desktop / Cursor）以 ``SuperInject.exe mcp`` 拉起
server 时，因为要注入目标进程需要管理员/SYSTEM，于是每次都会弹 UAC。若 GUI 已经
以 SYSTEM 跑着，就让一个**不要求权限**的 launcher 进程（``SuperInject.exe
mcp-launcher``）把 MCP 请求经**命名管道**转交给主进程执行（它已有权限）——Agent
侧只看到一个普通的 stdio server，全程无 UAC。

传输：命名管道 ``\\.\pipe\SuperInjectMCP``（:data:`PIPE_NAME`）。每条消息是一帧
（4 字节长度 + JSON），复用 :func:`superinject.ipc.encode_frame` /
:func:`superinject.ipc.decode_frames`。

可测性（硬约束）：所有 Win32 管道调用都包在 :class:`PipeBackend` 抽象里；POSIX 上
用 AF_UNIX socket 实现 :class:`SocketPipeBackend` 跑同一套逻辑，所以 macOS 上也能
完整单测 ``PipeBridgeServer`` 与 launcher 的转发路径。

线程模型：:class:`PipeBridgeServer` 的接受连接、每个连接的服务循环都在后台线程里，
**绝不阻塞 GUI 主线程**。
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Optional

from . import ipc

log = logging.getLogger("supinject.mcp_pipe")

# 固定的命名管道名（Windows）。POSIX 上 SocketPipeBackend 把它映射成一个
# 确定性的 AF_UNIX socket 路径，用于本地测试。
PIPE_NAME = r"\\.\pipe\SuperInjectMCP"

RECV_CHUNK = 1 << 16
READ_TIMEOUT = 0.2          # socket 后端读超时（秒），保证 stop 能及时打断
LAUNCHER_GRACE = 0.4        # stdin EOF 后给在途响应留的排空时间（秒）

# CPython 在 Windows 上对 socket.AF_UNIX 的处理：3.9 起 hasattr 返回 True 但
# 取出来是 None（或 0），socket.socket(AF_UNIX, ...) 直接 AttributeError 或
# TypeError。所以**不能**只信 hasattr —— 必须真把值取出来非 None 才能用。
# 这条踩过两次：第一次用 hasattr 让 windows runner 全红；第二次把值取出后
# 还是不行，因为某些 Windows + Python 版本里 getattr 返回的是 Enum 单例
# 但 socket() 构造抛 ValueError。所以这里加一道 try/except 兜底，让
# SocketPipeBackend 在 Windows 上**一定**走 TCP 回退路径。
try:
    _AF_UNIX = getattr(socket, "AF_UNIX", None)
    if _AF_UNIX is not None:
        # 试探构造一次 —— 这是 truthy 检验，唯一可靠
        socket.socket(_AF_UNIX, socket.SOCK_STREAM).close()
    _HAS_AF_UNIX = _AF_UNIX is not None
except (AttributeError, OSError, ValueError):
    _HAS_AF_UNIX = False


# --------------------------------------------------------------------------- 后端抽象


class PipeBackend:
    """命名管道 / socket 的最小抽象。

    业务逻辑只依赖这几个方法，因此 Windows 上走 Win32 管道、POSIX 上走
    AF_UNIX socket，测试与生产共用同一套 :class:`PipeBridgeServer` 代码。

    约定：

    * :meth:`accept` 阻塞等待连接；无连接到达时返回 ``None``（调用方据 stop 轮询）；
      服务器已关闭时抛 :class:`OSError` 或返回 ``None``。
    * :meth:`read` 返回一段数据；连接关闭返回 ``b""``；读超时抛 :class:`TimeoutError`。
    * :meth:`connect` 作为客户端连接管道；失败抛 :class:`ConnectionError`。
    """

    def create_server(self, name: str) -> Any:
        raise NotImplementedError

    def accept(self) -> Any:
        raise NotImplementedError

    def read(self, handle: Any) -> bytes:
        raise NotImplementedError

    def write(self, handle: Any, data: bytes) -> None:
        raise NotImplementedError

    def close_conn(self, handle: Any) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def connect(self, name: str) -> Any:
        raise NotImplementedError


class SocketPipeBackend(PipeBackend):
    """用 socket 模拟命名管道（供测试与本地开发，跨平台）。

    ``name`` 被哈希成一个确定性的地址（名字相同 → 地址相同），这样 server 与
    client 用同一个 ``name`` 就能对上，而无需传递真实地址。

    两种底层：

    * POSIX 有 ``socket.AF_UNIX`` → 用 AF_UNIX stream socket，地址是文件路径；
    * Windows 的 ``socket`` 模块**没有 AF_UNIX**（Windows 10+ 内核支持，
      但 CPython 在 Windows 上不暴露该常量）→ 退回 ``127.0.0.1`` 上的 TCP
      loopback，端口不固定，所以把端口写进一个按 ``name`` 推导的端口文件，
      客户端读它拿端口。这样「同名可推导」的语义在两种底层下都成立，
      同一套测试可以在任意平台跑。
    """

    def __init__(self, base_dir: Optional[os.PathLike | str] = None):
        self.base_dir = (Path(base_dir) if base_dir
                         else Path(tempfile.gettempdir()) / "SuperInject")
        self._server: Optional[socket.socket] = None
        self._path: Optional[str] = None
        self._conns: set = set()
        self._lock = threading.Lock()
        # 客户端用来解析地址；create_server 时补齐实际端口
        self._tcp_port: Optional[int] = None

    # -------------------------------------------------- 路径映射

    def path_for(self, name: str) -> str:
        """把管道名映射成一个确定性地址。

        POSIX 下是 socket 文件路径；Windows（TCP 回退）下是**端口文件**路径。
        """
        digest = hashlib.sha256(str(name).encode("utf-8")).hexdigest()[:16]
        self.base_dir.mkdir(parents=True, exist_ok=True)
        suffix = ".sock" if _HAS_AF_UNIX else ".port"
        return str(self.base_dir / f".si-mcp-{digest}{suffix}")

    # -------------------------------------------------- 服务端

    def create_server(self, name: str) -> socket.socket:
        path = self.path_for(name)
        try:
            os.unlink(path)
        except OSError:
            pass
        if _HAS_AF_UNIX:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(path)
        else:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            self._tcp_port = srv.getsockname()[1]
            # 客户端要读这个文件才知道端口 —— 写完再 listen，避免竞态
            Path(path).write_text(str(self._tcp_port), encoding="utf-8")
        srv.listen(16)
        srv.settimeout(READ_TIMEOUT)
        self._server = srv
        self._path = path
        return srv

    def accept(self):
        srv = self._server
        if srv is None:
            return None
        try:
            conn, _ = srv.accept()
        except socket.timeout:
            return None
        except OSError:
            return None
        with self._lock:
            self._conns.add(conn)
        return conn

    # -------------------------------------------------- 收发

    def read(self, handle: socket.socket) -> bytes:
        handle.settimeout(READ_TIMEOUT)
        try:
            return handle.recv(RECV_CHUNK)
        except socket.timeout as exc:  # 无数据：交给调用方轮询 stop
            raise TimeoutError("pipe read timeout") from exc

    def write(self, handle: socket.socket, data: bytes) -> None:
        handle.sendall(data)

    # -------------------------------------------------- 关闭

    def close_conn(self, handle) -> None:
        try:
            handle.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            handle.close()
        except OSError:
            pass
        with self._lock:
            self._conns.discard(handle)

    def close(self) -> None:
        with self._lock:
            conns = list(self._conns)
            self._conns.clear()
        for conn in conns:
            self.close_conn(conn)
        srv, self._server = self._server, None
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass
        if self._path:
            try:
                os.unlink(self._path)
            except OSError:
                pass
            self._path = None

    # -------------------------------------------------- 客户端

    def connect(self, name: str) -> socket.socket:
        path = self.path_for(name)
        if _HAS_AF_UNIX:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            try:
                sock.connect(path)
            except OSError as exc:
                sock.close()
                raise ConnectionError(f"无法连接命名管道 {path}: {exc}") from exc
        else:
            # TCP 路径：从 .port 文件读端口（由 create_server 写入）。
            # 重试是给「server 刚 listen、文件可能还在 OS 写缓冲里」留的窗口，
            # 实际几乎不会触发；2 次 50ms 总开销可忽略。
            port = None
            for _ in range(2):
                try:
                    port = int(Path(path).read_text(encoding="utf-8").strip())
                    break
                except (FileNotFoundError, ValueError):
                    time.sleep(0.05)
            if port is None:
                raise ConnectionError(
                    f"无法连接命名管道 {name}：端口文件 {path} 不可读"
                )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            try:
                sock.connect(("127.0.0.1", port))
            except OSError as exc:
                sock.close()
                raise ConnectionError(f"无法连接命名管道 {name} (127.0.0.1:{port}): {exc}") from exc
        sock.settimeout(None)
        return sock


# Win32 常量
_PIPE_ACCESS_DUPLEX = 0x00000003
_PIPE_TYPE_BYTE = 0x00000000
_PIPE_READMODE_BYTE = 0x00000000
_PIPE_WAIT = 0x00000000
_PIPE_UNLIMITED_INSTANCES = 255
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_INVALID_HANDLE_VALUE = -1
_ERROR_PIPE_CONNECTED = 535
_ERROR_PIPE_BUSY = 231


class Win32PipeBackend(PipeBackend):
    """真正的 Win32 命名管道实现（``kernel32`` 的 ctypes 直调，不引 pywin32）。

    与项目既有 ctypes 风格一致（见 ``superinject/winapi.py``）。仅在 Windows 上
    可用；非 Windows 调用会抛 :class:`RuntimeError`。
    """

    def __init__(self):
        import ctypes

        self._ctypes = ctypes
        self._k = None
        self._server = None
        self._name: Optional[str] = None
        self._conns: list = []
        self._lock = threading.Lock()

    def _kernel(self):
        if self._k is not None:
            return self._k
        if sys.platform != "win32":
            raise RuntimeError("Win32PipeBackend 仅 Windows 可用")
        import ctypes
        from ctypes import wintypes as wt

        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateNamedPipeW.restype = wt.HANDLE
        k.CreateNamedPipeW.argtypes = [
            wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD, wt.DWORD,
            wt.DWORD, ctypes.c_void_p]
        k.ConnectNamedPipe.restype = wt.BOOL
        k.ConnectNamedPipe.argtypes = [wt.HANDLE, ctypes.c_void_p]
        k.ReadFile.restype = wt.BOOL
        k.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                               ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
        k.WriteFile.restype = wt.BOOL
        k.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                                ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
        k.DisconnectNamedPipe.restype = wt.BOOL
        k.DisconnectNamedPipe.argtypes = [wt.HANDLE]
        k.CloseHandle.restype = wt.BOOL
        k.CloseHandle.argtypes = [wt.HANDLE]
        k.CreateFileW.restype = wt.HANDLE
        k.CreateFileW.argtypes = [
            wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD,
            wt.DWORD, wt.HANDLE]
        k.WaitNamedPipeW.restype = wt.BOOL
        k.WaitNamedPipeW.argtypes = [wt.LPCWSTR, wt.DWORD]
        self._k = k
        return k

    def _last_error(self) -> int:
        return self._ctypes.get_last_error()

    def create_server(self, name: str):
        k = self._kernel()
        c = self._ctypes
        handle = k.CreateNamedPipeW(
            name, _PIPE_ACCESS_DUPLEX,
            _PIPE_TYPE_BYTE | _PIPE_READMODE_BYTE | _PIPE_WAIT,
            _PIPE_UNLIMITED_INSTANCES, RECV_CHUNK, RECV_CHUNK, 0, None)
        if not handle or handle == c.c_void_p(_INVALID_HANDLE_VALUE).value:
            raise OSError(self._last_error(), f"CreateNamedPipeW({name}) 失败")
        self._server = handle
        self._name = name
        return handle

    def accept(self):
        k = self._kernel()
        handle = self._server
        if handle is None:
            return None
        ok = k.ConnectNamedPipe(handle, None)
        if not ok and self._last_error() != _ERROR_PIPE_CONNECTED:
            # 服务器已被 stop 关闭，或出现错误
            return None
        with self._lock:
            self._conns.append(handle)
        # 立刻为新连接准备下一个实例（管道服务端是「一连接一实例」）
        try:
            self._server = self.create_server(self._name)
        except OSError:  # pragma: no cover - 无法重建时下一轮会退出
            self._server = None
        return handle

    def read(self, handle) -> bytes:
        c = self._ctypes
        k = self._kernel()
        from ctypes import wintypes as wt

        buf = c.create_string_buffer(RECV_CHUNK)
        got = wt.DWORD(0)
        if not k.ReadFile(handle, buf, RECV_CHUNK, c.byref(got), None):
            return b""
        return bytes(buf.raw[: got.value])

    def write(self, handle, data: bytes) -> None:
        c = self._ctypes
        k = self._kernel()
        from ctypes import wintypes as wt

        wrote = wt.DWORD(0)
        k.WriteFile(handle, data, len(data), c.byref(wrote), None)

    def close_conn(self, handle) -> None:
        k = self._kernel()
        try:
            k.DisconnectNamedPipe(handle)
        except Exception:  # pragma: no cover
            pass
        try:
            k.CloseHandle(handle)
        except Exception:  # pragma: no cover
            pass
        with self._lock:
            if handle in self._conns:
                self._conns.remove(handle)

    def close(self) -> None:
        with self._lock:
            conns = list(self._conns)
            self._conns.clear()
        for conn in conns:
            self.close_conn(conn)
        server, self._server = self._server, None
        if server is not None:
            try:
                self._kernel().CloseHandle(server)
            except Exception:  # pragma: no cover
                pass

    def connect(self, name: str):
        k = self._kernel()
        c = self._ctypes
        last = 0
        for _ in range(20):
            handle = k.CreateFileW(name, _GENERIC_READ | _GENERIC_WRITE, 0,
                                   None, _OPEN_EXISTING, 0, None)
            if handle and handle != c.c_void_p(_INVALID_HANDLE_VALUE).value:
                return handle
            last = self._last_error()
            if last == _ERROR_PIPE_BUSY:
                k.WaitNamedPipeW(name, 200)
                continue
            break
        raise ConnectionError(f"无法连接命名管道 {name}（err={last}）")


def default_backend() -> PipeBackend:
    """按平台挑默认后端：Windows 走命名管道，其余走 AF_UNIX socket。"""
    if sys.platform == "win32":
        return Win32PipeBackend()
    return SocketPipeBackend()


def connect_pipe(name: str = PIPE_NAME, backend: Optional[PipeBackend] = None):
    """作为客户端连接命名管道，返回一个连接句柄。

    失败抛 :class:`ConnectionError`（launcher 据此报「主进程未运行」）。测试可传入
    :class:`SocketPipeBackend`。
    """
    backend = backend if backend is not None else default_backend()
    return backend.connect(name)


# --------------------------------------------------------------------------- 桥接服务端


class PipeBridgeServer:
    """监听命名管道，把每个连接的帧交给 :func:`mcp_server.handle_message`。

    每条请求是一帧（4 字节长度 + JSON），响应写回同一连接。接受连接用后台线程，
    每个连接一个服务线程 —— 不阻塞 GUI 主线程。
    """

    def __init__(self, session: Any, controller: Any = None,
                 backend: Optional[PipeBackend] = None,
                 name: str = PIPE_NAME):
        self.session = session
        self.controller = controller
        self.backend = backend if backend is not None else default_backend()
        self.name = name
        self._stop = threading.Event()
        self._accept_thread: Optional[threading.Thread] = None
        self._conn_threads: list[threading.Thread] = []
        self._running = False
        self._lock = threading.Lock()

    # -------------------------------------------------- 生命周期

    @property
    def running(self) -> bool:
        return self._running and not self._stop.is_set()

    def start(self) -> "PipeBridgeServer":
        if self._running:
            return self
        self.backend.create_server(self.name)   # 失败直接抛出，交调用方处理
        self._stop.clear()
        self._running = True
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="si-mcp-accept", daemon=True)
        self._accept_thread.start()
        log.debug("MCP 命名管道桥已监听 %s", self.name)
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self.backend.close()
        except Exception:  # pragma: no cover - 关闭失败不该阻塞退出
            log.debug("关闭 pipe 后端失败", exc_info=True)
        thread = self._accept_thread
        if thread is not None and thread.is_alive() \
                and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        with self._lock:
            conn_threads = list(self._conn_threads)
            self._conn_threads.clear()
        for t in conn_threads:
            if t.is_alive() and t is not threading.current_thread():
                t.join(timeout=1.0)
        self._accept_thread = None
        self._running = False
        log.debug("MCP 命名管道桥已停止 %s", self.name)

    # -------------------------------------------------- 内部

    def _session_now(self) -> Any:
        s = self.session
        return s() if callable(s) else s

    def _controller_now(self) -> Any:
        if self.controller is None:
            from .controller import Controller

            self.controller = Controller()
        return self.controller

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                handle = self.backend.accept()
            except OSError:  # pragma: no cover - 监听已关闭
                break
            if handle is None:
                continue
            if self._stop.is_set():
                self.backend.close_conn(handle)
                break
            thread = threading.Thread(target=self._serve_conn, args=(handle,),
                                      name="si-mcp-conn", daemon=True)
            with self._lock:
                self._conn_threads.append(thread)
            thread.start()

    def _serve_conn(self, handle) -> None:
        from . import mcp_server

        buf = bytearray()
        try:
            while not self._stop.is_set():
                try:
                    chunk = self.backend.read(handle)
                except TimeoutError:
                    continue
                except OSError:  # pragma: no cover - 连接已断
                    break
                if not chunk:
                    break
                buf.extend(chunk)
                try:
                    frames, buf = ipc.decode_frames(buf)
                except ValueError:
                    break
                for message in frames:
                    response = self._dispatch(message, mcp_server)
                    if response is not None:
                        self.backend.write(handle, ipc.encode_frame(response))
        finally:
            self.backend.close_conn(handle)

    def _dispatch(self, message: Any, mcp_server) -> Optional[dict]:
        try:
            return mcp_server.handle_message(
                self._session_now(), self._controller_now(), message)
        except Exception as exc:  # pragma: no cover - 兜底，绝不断连接
            log.exception("处理 MCP 消息失败")
            mid = message.get("id") if isinstance(message, dict) else None
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32603, "message": f"internal error: {exc}"}}


# --------------------------------------------------------------------------- launcher 转发


def pump_stdio(backend: PipeBackend, handle: Any, *, stdin: Any = None,
               stdout: Any = None, grace: float = LAUNCHER_GRACE) -> int:
    """launcher 的核心：stdin（面向 Agent 的 stdio）↔ 命名管道 双向转发。

    * 主线程把 stdin 每一行（一条 JSON-RPC）编码成帧写进管道；
    * 后台线程从管道读帧、解码成一行 JSON 写回 stdout。

    **stdout 只能出 JSON-RPC 帧**（与 ``mcp`` 一致），日志一律走 stderr —— 调用方
    负责 stderr。stdin 读到 EOF 后，给在途响应留 ``grace`` 秒排空再收尾。
    """
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stop = threading.Event()

    def emit(obj: Any) -> None:
        stdout.write(json.dumps(obj, ensure_ascii=False, default=str) + "\n")
        stdout.flush()

    def reader() -> None:
        buf = bytearray()
        while not stop.is_set():
            try:
                chunk = backend.read(handle)
            except TimeoutError:
                continue
            except OSError:  # pragma: no cover - 管道已断
                break
            if not chunk:
                break
            buf.extend(chunk)
            try:
                frames, buf = ipc.decode_frames(buf)
            except ValueError:
                break
            for frame in frames:
                emit(frame)

    thread = threading.Thread(target=reader, name="si-mcp-launcher-read",
                              daemon=True)
    thread.start()
    rc = 0
    try:
        for raw in stdin:
            line = raw.strip() if isinstance(raw, str) else str(raw).strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                emit({"jsonrpc": "2.0", "id": None,
                      "error": {"code": -32700, "message": "parse error"}})
                continue
            backend.write(handle, ipc.encode_frame(message))
    except KeyboardInterrupt:  # pragma: no cover - 交互中断
        rc = 130
    finally:
        if grace:
            time.sleep(grace)
        stop.set()
        try:
            backend.close_conn(handle)
        except Exception:  # pragma: no cover
            pass
        thread.join(timeout=1.0)
    return rc
