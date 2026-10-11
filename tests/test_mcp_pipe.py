"""命名管道桥（v1.3.0 P6）单测。

全部用 :class:`~superinject.mcp_pipe.SocketPipeBackend`（AF_UNIX）在 macOS/Linux 上
**真跑** —— 真起 server、真连 socket、真收发帧，不碰 Win32 命名管道。这样 P6 的
桥接 / 转发逻辑在没有 Windows 的 CI 上也能被完整覆盖。
"""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject import cli, ipc, mcp_pipe
from superinject.mcp_consent import build_session


class FakeController:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def list_processes(self):
        self.calls.append("list_processes")
        return [{"pid": 1234, "name": "notepad.exe"}]

    def status(self):
        self.calls.append("status")
        return {"ok": True}

    def mem_write(self, pid, address, hexdata):
        self.calls.append("mem_write")
        return {"ok": True}


@pytest.fixture()
def session():
    return build_session(pids=[1234], capabilities=["read", "write"])


def _unique_name(tag: str) -> str:
    # 避免用例间共享 socket 文件
    return f"SuperInjectMCP-{tag}-{time.time_ns()}"


def _send(backend, handle, message: dict) -> None:
    backend.write(handle, ipc.encode_frame(message))


def _recv_frame(backend, handle, timeout: float = 5.0) -> dict:
    buf = bytearray()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = backend.read(handle)
        except TimeoutError:
            continue
        if not chunk:
            break
        buf.extend(chunk)
        frames, buf = ipc.decode_frames(buf)
        if frames:
            return frames[0]
    raise AssertionError("未在超时内收到响应帧")


def _start_server(session, name, controller=None):
    backend = mcp_pipe.SocketPipeBackend()
    server = mcp_pipe.PipeBridgeServer(session, controller or FakeController(),
                                       backend=backend, name=name)
    server.start()
    return server, backend


# --------------------------------------------------------------------------- 1. initialize 往返


def test_socket_bridge_initialize_roundtrip(session):
    name = _unique_name("init")
    server, _ = _start_server(session, name)
    try:
        assert server.running is True
        client = mcp_pipe.SocketPipeBackend()
        handle = client.connect(name)
        _send(client, handle, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": "2024-11-05"}})
        resp = _recv_frame(client, handle)
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 1
        assert resp["result"]["serverInfo"]["name"] == "superinject"
        assert resp["result"]["protocolVersion"] == "2024-11-05"
        client.close_conn(handle)
        client.close()
    finally:
        server.stop()


# --------------------------------------------------------------------------- 2. 长连接多帧


def test_socket_bridge_multiple_frames_same_connection(session):
    name = _unique_name("multi")
    controller = FakeController()
    server, _ = _start_server(session, name, controller)
    try:
        client = mcp_pipe.SocketPipeBackend()
        handle = client.connect(name)
        _send(client, handle, {"jsonrpc": "2.0", "id": 1,
                               "method": "initialize", "params": {}})
        assert _recv_frame(client, handle)["id"] == 1

        _send(client, handle, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = _recv_frame(client, handle)["result"]["tools"]
        assert any(t["name"] == "list_processes" for t in tools)

        _send(client, handle, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                               "params": {"name": "list_processes",
                                          "arguments": {}}})
        call = _recv_frame(client, handle)
        assert call["id"] == 3
        assert call["result"]["isError"] is False
        payload = json.loads(call["result"]["content"][0]["text"])
        assert payload[0]["pid"] == 1234
        assert controller.calls == ["list_processes"]

        # 通知（无 id）不应答；随后一条请求仍要能正常拿到响应
        _send(client, handle, {"jsonrpc": "2.0",
                               "method": "notifications/initialized"})
        _send(client, handle, {"jsonrpc": "2.0", "id": 4, "method": "ping"})
        assert _recv_frame(client, handle)["id"] == 4
    finally:
        server.stop()


# --------------------------------------------------------------------------- 3. 未授权会话 → 拒绝


def test_unauthorized_session_denies_tool_call():
    name = _unique_name("unauth")
    controller = FakeController()
    server, _ = _start_server(None, name, controller)   # 无授权会话
    try:
        client = mcp_pipe.SocketPipeBackend()
        handle = client.connect(name)
        _send(client, handle, {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "mem_write",
                                          "arguments": {"pid": 1234, "address": 1,
                                                        "hex": "90"}}})
        resp = _recv_frame(client, handle)
        assert resp["result"]["isError"] is True
        payload = json.loads(resp["result"]["content"][0]["text"])
        assert payload["error"] == "consent_denied"
        assert controller.calls == [], "越权时绝不能落到控制器"
    finally:
        server.stop()


# --------------------------------------------------------------------------- 4. stop：running False + 释放名字


def test_stop_marks_not_running_and_releases_name(session):
    name = _unique_name("stop")
    server, _ = _start_server(session, name)
    try:
        assert server.running is True
        client = mcp_pipe.SocketPipeBackend()
        handle = client.connect(name)
        client.close_conn(handle)
        client.close()
    finally:
        server.stop()
    assert server.running is False, "stop() 后 running 必须为 False"

    # 名字已释放：同一 name 能重新起一个新的 server 并被连上
    server2, _ = _start_server(session, name)
    try:
        assert server2.running is True
        client = mcp_pipe.SocketPipeBackend()
        handle = client.connect(name)
        _send(client, handle, {"jsonrpc": "2.0", "id": 9, "method": "ping"})
        assert _recv_frame(client, handle)["id"] == 9
        client.close_conn(handle)
        client.close()
    finally:
        server2.stop()


# --------------------------------------------------------------------------- 5. launcher 连不上 → 非 0


def test_launcher_reports_error_when_main_not_running():
    backend = mcp_pipe.SocketPipeBackend()
    out = io.StringIO()
    err = io.StringIO()
    rc = cli.run_mcp_launcher([], stdin=io.StringIO(""),
                              stdout=out, stderr=err, backend=backend)
    assert rc != 0, "连不上主进程必须返回非 0"
    assert "主进程未运行" in err.getvalue()
    assert out.getvalue() == "", "stdout 不能有非 JSON-RPC 输出"


# --------------------------------------------------------------------------- 6. connect_pipe 抽象


def test_connect_pipe_returns_handle_when_server_up(session):
    name = _unique_name("connect")
    server, _ = _start_server(session, name)
    try:
        handle = mcp_pipe.connect_pipe(name, mcp_pipe.SocketPipeBackend())
        assert handle is not None
        backend = mcp_pipe.SocketPipeBackend()
        backend.close_conn(handle)
    finally:
        server.stop()


def test_connect_pipe_raises_when_server_down():
    backend = mcp_pipe.SocketPipeBackend()
    with pytest.raises(ConnectionError):
        mcp_pipe.connect_pipe(_unique_name("down"), backend)


# --------------------------------------------------------------------------- 7. launcher 端到端转发


def test_run_mcp_launcher_end_to_end(monkeypatch, session):
    """launcher 的 stdin → 管道 → 主进程 → stdout 全链路（无 UAC 路径）。"""
    name = _unique_name("e2e")
    controller = FakeController()
    server, _ = _start_server(session, name, controller)
    try:
        monkeypatch.setattr(mcp_pipe, "PIPE_NAME", name)
        backend = mcp_pipe.SocketPipeBackend()
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "list_processes", "arguments": {}}}
        stdin = io.StringIO(json.dumps(request) + "\n")
        stdout = io.StringIO()
        stderr = io.StringIO()
        rc = cli.run_mcp_launcher([], stdin=stdin, stdout=stdout,
                                  stderr=stderr, backend=backend)
        assert rc == 0, stderr.getvalue()
        lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
        assert len(lines) == 1, stdout.getvalue()
        obj = json.loads(lines[0])      # stdout 只能是 JSON-RPC 帧
        assert obj["jsonrpc"] == "2.0"
        assert obj["id"] == 1
        payload = json.loads(obj["result"]["content"][0]["text"])
        assert payload[0]["pid"] == 1234
    finally:
        server.stop()
