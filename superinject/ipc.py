"""注入端与控制器之间的控制通道。

传输用 **回环 TCP**（127.0.0.1，只监听本机），而不是命名管道：

* 命名管道在「服务端写、注入端阻塞读」并存时出现过方向性死等
  （CI 实测：控制器写 25 字节的命令永久阻塞，注入端也永久收不到，
  双方各卡 5 分钟直到超时）。回环 TCP 没有这种状态机陷阱。
* 纯 socket 实现可以在任何平台跑单元测试，命名管道在 macOS 上完全测不了。

握手流程（保持「注入端反向连回来」的设计，一次注入即可长期批量控制）：

1. 注入前，控制器在 ``<工作目录>/port-<目标PID>.txt`` 写下 ``端口 令牌``；
2. 注入端 DLL 启动后读这个文件，连到 ``127.0.0.1:<端口>``；
3. DLL 发 hello（带 pid 与令牌），控制器校验 pid 在本次目标里、令牌一致，
   建立映射；之后就是「4 字节小端长度 + UTF-8 JSON」的请求/响应。
"""

from __future__ import annotations

import json
import logging
import os
import queue
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional

log = logging.getLogger("supinject.ipc")

MAX_FRAME = 64 * 1024 * 1024
RECV_CHUNK = 1 << 20
HELLO_TIMEOUT = 15.0
SEND_TIMEOUT = 10.0


def work_dir() -> Path:
    import tempfile

    return Path(tempfile.gettempdir()) / "SuperInject"


def port_file(pid: int, base: Optional[Path] = None) -> Path:
    return (base or work_dir()) / f"port-{int(pid)}.txt"


# ------------------------------------------------------------- 帧编解码


def encode_frame(payload: dict) -> bytes:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return struct.pack("<I", len(body)) + body


def decode_frames(buffer: bytes | bytearray) -> tuple[list[dict], bytearray]:
    """从缓冲区中解析出所有完整帧，返回 (帧列表, 剩余缓冲)。

    传入 bytes 也可以（内部换成 bytearray）；剩余缓冲始终以 bytearray 返回，
    调用方按 ``frames, buf = decode_frames(buf)`` 接回去即可。
    """
    if not isinstance(buffer, bytearray):
        buffer = bytearray(buffer)
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


# ------------------------------------------------------------- 连接


class Connection:
    """与某个目标进程注入端的连接。"""

    def __init__(self, sock: socket.socket, pid: int):
        self.sock = sock
        self.pid = pid
        self.info: dict = {}
        self.alive = True
        self._write_lock = threading.Lock()

    def send(self, payload: dict, timeout: float = SEND_TIMEOUT) -> None:
        data = encode_frame(payload)
        with self._write_lock:
            self.sock.settimeout(timeout)
            try:
                self.sock.sendall(data)
            except socket.timeout as exc:  # pragma: no cover - 依赖真实网络
                raise TimeoutError(f"写入控制通道超时（{timeout}s）") from exc
            except OSError as exc:
                self.alive = False
                raise OSError(f"写入控制通道失败: {exc}") from exc

    def close(self) -> None:
        self.alive = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:  # pragma: no cover
            pass


@dataclass
class _Target:
    pid: int
    token: str


class AgentServer:
    """注入端的接入点：监听回环端口，管理多个目标的连接与请求/响应匹配。"""

    def __init__(self, controller_pid: Optional[int] = None,
                 base_dir: Optional[Path] = None):
        self.controller_pid = controller_pid or os.getpid()
        self.base_dir = Path(base_dir) if base_dir else work_dir()
        self._targets: Dict[int, _Target] = {}
        self._conns: Dict[int, Connection] = {}
        self._waiters: Dict[int, queue.Queue] = {}
        self._threads: Dict[int, threading.Thread] = {}
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._seq = 0
        self._listener: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self.port = 0
        self.on_attach: Optional[Callable[[int, dict], None]] = None
        self.on_detach: Optional[Callable[[int], None]] = None

    # -------------------------------------------------- 生命周期

    def start(self) -> int:
        """启动监听（幂等），返回端口。"""
        with self._lock:
            if self._listener is not None:
                return self.port
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # 只监听本机回环：不对外暴露，也不会触发防火墙弹窗
            listener.bind(("127.0.0.1", 0))
            listener.listen(16)
            listener.settimeout(0.5)
            self._listener = listener
            self.port = listener.getsockname()[1]
            t = threading.Thread(target=self._accept_loop, name="si-accept",
                                 daemon=True)
            self._accept_thread = t
        t.start()
        log.debug("控制通道监听 127.0.0.1:%s", self.port)
        return self.port

    def register(self, pid: int) -> None:
        """登记目标进程：写好端口令牌文件，等待注入端连回来。"""
        self.start()
        token = secrets.token_hex(16)
        with self._lock:
            self._targets[int(pid)] = _Target(int(pid), token)
        path = port_file(pid, self.base_dir)
        try:
            self.base_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(f"{self.port} {token}\n", encoding="utf-8")
        except OSError as exc:  # pragma: no cover - 目录不可写
            log.warning("写入端口文件失败 %s: %s", path, exc)
        log.debug("已登记目标 pid=%s 端口=%s", pid, self.port)

    def unregister(self, pid: int) -> None:
        with self._lock:
            self._targets.pop(int(pid), None)
            conn = self._conns.pop(int(pid), None)
        if conn:
            conn.close()
        try:
            port_file(pid, self.base_dir).unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            pass

    def shutdown(self) -> None:
        self._stop.set()
        with self._lock:
            conns = list(self._conns.values())
            self._conns.clear()
            listener, self._listener = self._listener, None
            targets = [t.pid for t in self._targets.values()]
            self._targets.clear()
        for c in conns:
            c.close()
        if listener:
            try:
                # Linux 上 close() 不会唤醒阻塞在 accept() 的线程：内核还持着这个
                # 监听 socket，新连接照样能进 backlog（macOS 会立刻拒绝），同一份
                # 代码在两平台表现不同。先 shutdown 再 close，阻塞的 accept() 才会
                # 立即返回。
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:  # pragma: no cover - 未连接/不支持
                pass
            try:
                listener.close()
            except OSError:  # pragma: no cover
                pass
        for pid in targets:
            try:
                port_file(pid, self.base_dir).unlink(missing_ok=True)
            except OSError:  # pragma: no cover
                pass

    # -------------------------------------------------- 查询

    def is_attached(self, pid: int) -> bool:
        with self._lock:
            conn = self._conns.get(int(pid))
        return bool(conn and conn.alive)

    def targets(self) -> set[int]:
        with self._lock:
            return set(self._targets)

    def attached_pids(self) -> set[int]:
        with self._lock:
            return {pid for pid, c in self._conns.items() if c.alive}

    def wait_attach(self, pid: int, timeout: float = 10.0,
                    interval: float = 0.05) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.is_attached(pid):
                return True
            if int(pid) not in self.targets():
                return False
            time.sleep(interval)
        return self.is_attached(pid)

    def wait_detach(self, pid: int, timeout: float = 8.0,
                    interval: float = 0.05) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.is_attached(pid):
                return True
            time.sleep(interval)
        return not self.is_attached(pid)

    # -------------------------------------------------- 请求

    def request(self, pid: int, cmd: dict, timeout: float = 20.0) -> dict:
        with self._lock:
            conn = self._conns.get(int(pid))
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
            conn.send(payload, timeout=max(2.0, min(timeout, SEND_TIMEOUT)))
        except Exception as exc:
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
        return {int(pid): self.request(pid, cmd, timeout) for pid in pids}

    # -------------------------------------------------- 内部

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            with self._lock:
                listener = self._listener
            if listener is None:
                return
            try:
                sock, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:  # pragma: no cover - 监听套接字已关闭
                return
            threading.Thread(target=self._handshake, args=(sock, addr),
                             name="si-hello", daemon=True).start()

    def _handshake(self, sock: socket.socket, addr) -> None:
        pid, token = 0, ""
        try:
            sock.settimeout(HELLO_TIMEOUT)
            buf = bytearray()
            frames: list[dict] = []
            while not frames:
                chunk = sock.recv(RECV_CHUNK)
                if not chunk:
                    sock.close()
                    return
                buf.extend(chunk)
                frames, buf = decode_frames(buf)
            hello = frames[0]
            pid = int(hello.get("pid") or 0)
            token = str(hello.get("token") or "")
            with self._lock:
                target = self._targets.get(pid)
            if target is None or target.token != token:
                log.warning("拒绝未登记/令牌不符的连接 pid=%s from %s", pid, addr)
                sock.close()
                return
            conn = Connection(sock, pid)
            conn.info = hello
            with self._lock:
                self._conns[pid] = conn
            sock.settimeout(1.0)
            log.info("已连接注入端 pid=%s %s", pid, hello.get("image"))
            if self.on_attach:
                try:
                    self.on_attach(pid, hello)
                except Exception:  # pragma: no cover
                    log.exception("on_attach 回调失败")
            self._read_loop(pid, conn, buf, frames[1:])
        except (OSError, ValueError) as exc:
            log.debug("握手结束 pid=%s: %s", pid, exc)

    def _read_loop(self, pid: int, conn: Connection, buf: bytearray,
                   pending: list[dict]) -> None:
        for msg in pending:
            self._dispatch(pid, msg)
        try:
            while not self._stop.is_set():
                try:
                    chunk = conn.sock.recv(RECV_CHUNK)
                except socket.timeout:
                    if not conn.alive or self._stop.is_set():
                        break
                    continue
                except OSError:  # pragma: no cover
                    break
                if not chunk:
                    break
                buf.extend(chunk)
                frames, buf = decode_frames(buf)
                for msg in frames:
                    self._dispatch(pid, msg)
        finally:
            conn.close()
            with self._lock:
                if self._conns.get(pid) is conn:
                    self._conns.pop(pid, None)
            log.debug("注入端已断开 pid=%s", pid)
            if self.on_detach:
                try:
                    self.on_detach(pid)
                except Exception:  # pragma: no cover
                    pass

    def _dispatch(self, pid: int, msg: dict) -> None:
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
