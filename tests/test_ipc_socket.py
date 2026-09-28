"""控制通道（回环 TCP）的真实测试。

这些用例在本机真的起监听、真的连 socket、真的收发帧 —— 不是打桩，
所以在 macOS 开发机上就能跑（命名管道时代完全做不到这一点）。
"""

from __future__ import annotations

import json
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject import ipc
from superinject.version import port_file_name


class FakeAgent:
    """模拟注入端：读会合文件 → 连控制器 → 发 hello → 回命令。"""

    def __init__(self, work_dir: Path, pid: int, token: str | None = None,
                 image: str = r"C:\demo\fake.exe"):
        self.work_dir = work_dir
        self.pid = pid
        self.image = image
        self.forced_token = token
        self.sock: socket.socket | None = None
        self.hello_sent = False
        self.seen: list[dict] = []
        self._thread: threading.Thread | None = None

    # -------------------------------------------------- 会合文件
    def read_port_file(self) -> tuple[int, str] | None:
        f = self.work_dir / port_file_name(self.pid)
        if not f.exists():
            return None
        text = f.read_text(encoding="utf-8").strip()
        port, _, token = text.partition(" ")
        return int(port), token.strip()

    def connect(self, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            got = self.read_port_file()
            if got:
                port, token = got
                s = socket.socket()
                s.settimeout(2.0)
                try:
                    s.connect(("127.0.0.1", port))
                except OSError:
                    s.close()
                    time.sleep(0.05)
                    continue
                self.sock = s
                self.send({"type": "hello", "pid": self.pid, "version": "1.0.1",
                           "proto": 1, "arch": 64, "elevated": True,
                           "image": self.image,
                           "token": self.forced_token if self.forced_token is not None else token})
                self.hello_sent = True
                return True
            time.sleep(0.05)
        return False

    # -------------------------------------------------- 帧收发
    def send(self, payload: dict) -> None:
        data = ipc.encode_frame(payload)
        assert self.sock is not None
        self.sock.sendall(data)

    def serve(self, handler=None) -> None:
        """开始收命令并按 handler 回包（默认回 ok）。"""
        assert self.sock is not None

        def loop() -> None:
            buf = b""
            while True:
                try:
                    chunk = self.sock.recv(65536)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                frames, buf = ipc.decode_frames(buf)
                for f in frames:
                    self.seen.append(f)
                    reply = handler(f) if handler else {"type": "reply", "ok": True}
                    if reply is not None:
                        reply = dict(reply)
                        reply.setdefault("id", f.get("id"))
                        self.send(reply)

        self._thread = threading.Thread(target=loop, daemon=True)
        self._thread.start()

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()
            self.sock = None


@pytest.fixture()
def work_dir(tmp_path: Path) -> Path:
    d = tmp_path / "SuperInject"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.fixture()
def server(work_dir: Path):
    srv = ipc.AgentServer(base_dir=work_dir)
    yield srv
    srv.shutdown()


def _attach(server: ipc.AgentServer, work_dir: Path, pid: int, **kw) -> FakeAgent:
    server.register(pid)
    agent = FakeAgent(work_dir, pid, **kw)
    assert agent.connect(), "模拟注入端未能连上控制器"
    assert server.wait_attach(pid, 5.0), "控制器没有认下这条连接"
    return agent


# ---------------------------------------------------------------- 用例

def test_register_writes_rendezvous_file(server, work_dir):
    server.register(1000)
    f = work_dir / port_file_name(1000)
    assert f.exists()
    port, token = f.read_text(encoding="utf-8").strip().split(" ")
    assert 0 < int(port) < 65536, "必须是有效回环端口"
    assert int(port) == server.port
    assert len(token) == 32, "令牌应为 16 字节随机数的十六进制"


def test_listener_only_on_loopback(server, work_dir):
    """端口只能从本机回环访问，不对外监听。"""
    server.register(1001)
    port, _ = (work_dir / port_file_name(1001)).read_text(encoding="utf-8").split(" ")
    s = socket.socket()
    s.settimeout(2.0)
    try:
        s.connect(("127.0.0.1", int(port)))
        ok = True
    except OSError:
        ok = False
    finally:
        s.close()
    assert ok, "回环地址应当能连上（这就是注入端要走的路）"


def test_attach_and_request_roundtrip(server, work_dir):
    pid = 2000
    agent = _attach(server, work_dir, pid)
    agent.serve()
    assert server.is_attached(pid)
    assert pid in server.attached_pids()

    resp = server.request(pid, {"type": "ping"}, timeout=5.0)
    assert resp is not None
    assert resp.get("ok") is True
    assert agent.seen and agent.seen[0]["type"] == "ping"


def test_attach_callback_receives_hello(server, work_dir):
    got: list[dict] = []
    server.on_attach = lambda pid, hello: got.append(hello)
    agent = _attach(server, work_dir, 2100)
    for _ in range(50):
        if got:
            break
        time.sleep(0.02)
    assert got and got[0]["pid"] == 2100
    assert got[0]["image"].endswith("fake.exe")
    agent.close()


def test_bad_token_is_rejected(server, work_dir):
    pid = 2200
    server.register(pid)
    bad = FakeAgent(work_dir, pid, token="0" * 32)
    assert bad.connect()
    time.sleep(0.3)
    assert not server.is_attached(pid), "令牌不对的连接不能被当成注入端"
    bad.close()


def test_unregistered_pid_is_rejected(server, work_dir):
    pid = 2300
    server.register(pid)
    other = FakeAgent(work_dir, 2399)          # 没注册的 PID
    got = other.read_port_file()
    assert got is None, "未注册的 PID 不该有会合文件"
    other.close()


def test_detach_detected_on_close(server, work_dir):
    pid = 2400
    agent = _attach(server, work_dir, pid)
    assert server.is_attached(pid)
    agent.close()
    assert server.wait_detach(pid, 5.0), "注入端断开后控制器应当感知到"


def test_unregister_removes_rendezvous_and_stops_attach(server, work_dir):
    pid = 2500
    agent = _attach(server, work_dir, pid)
    server.unregister(pid)
    agent.close()
    assert not server.is_attached(pid)
    assert not (work_dir / port_file_name(pid)).exists()


def test_request_without_agent_times_out_cleanly(server, work_dir):
    pid = 2600
    server.register(pid)
    t0 = time.time()
    resp = server.request(pid, {"type": "ping"}, timeout=1.0)
    assert resp is not None and resp.get("ok") is False
    assert time.time() - t0 < 5.0, "没有注入端时必须快速返回错误，不能挂死"


def test_broadcast_hits_every_agent(server, work_dir):
    agents = [_attach(server, work_dir, 3000 + i) for i in range(3)]
    for a in agents:
        a.serve()
    res = server.broadcast([3000, 3001, 3002], {"type": "ping"}, timeout=5.0)
    assert set(res) == {3000, 3001, 3002}
    for pid, resp in res.items():
        assert resp.get("ok") is True, f"pid {pid} 没回包: {resp}"
    for a in agents:
        assert any(f["type"] == "ping" for f in a.seen)


def test_command_with_big_payload_is_reframed(server, work_dir):
    """大 payload（多块 TCP 分片）必须被正确切帧。"""
    pid = 3100
    agent = _attach(server, work_dir, pid)
    agent.serve()
    payload = "AB" * 40000                       # 80KB 十六进制
    resp = server.request(pid, {"type": "mem_write", "data": payload}, timeout=5.0)
    assert resp and resp.get("ok") is True
    assert agent.seen[0]["data"] == payload


def test_hello_with_bad_length_closes_connection(server, work_dir):
    """畸形帧（长度离谱）不能让控制器崩掉，直接丢连接。"""
    pid = 3200
    server.register(pid)
    port, token = (work_dir / port_file_name(pid)).read_text(encoding="utf-8").split(" ")
    s = socket.socket()
    s.settimeout(2.0)
    s.connect(("127.0.0.1", int(port)))
    s.sendall((ipc.MAX_FRAME + 1).to_bytes(4, "little") + b"{}")
    deadline = time.time() + 3
    while time.time() < deadline and server.is_attached(pid):
        time.sleep(0.05)
    assert not server.is_attached(pid)
    s.close()


def test_shutdown_closes_everything(work_dir):
    srv = ipc.AgentServer(base_dir=work_dir)
    srv.register(4000)
    port_file = work_dir / port_file_name(4000)
    assert port_file.exists()
    srv.shutdown()
    assert not srv.is_attached(4000)
    assert not port_file.exists()
    # 监听也应当关闭：再连应当失败
    port, _ = (port_file.read_text(encoding="utf-8").split(" ") if port_file.exists()
               else (str(srv.port), ""))
    s = socket.socket()
    s.settimeout(1.0)
    try:
        s.connect(("127.0.0.1", int(port)))
        ok = False
    except OSError:
        ok = True
    finally:
        s.close()
    assert ok


def test_hello_json_is_well_formed(server, work_dir):
    pid = 4100
    agent = _attach(server, work_dir, pid)
    assert agent.hello_sent
    assert json.loads(json.dumps({"type": "hello"}))["type"] == "hello"
    agent.close()
