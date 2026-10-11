"""MCP server 层单测：JSON-RPC 协议、越权响应、stdout 纯净性。

这些用例不碰真实 Windows / 真实注入 —— 只测协议层（P4 的范围）。
"""

from __future__ import annotations

import io
import json
from typing import List

import pytest

from superinject import mcp_server
from superinject.mcp_consent import build_session
from superinject.version import __version__


class FakeController:
    def __init__(self) -> None:
        self.calls: List[str] = []

    def list_processes(self):
        self.calls.append("list_processes")
        return [{"pid": 1234, "name": "notepad.exe"}]

    def status(self):
        self.calls.append("status")
        return {"ok": True}

    def mem_write(self, pid, address, hexdata):
        self.calls.append("mem_write")
        return {"ok": True, "written": len(hexdata) // 2}

    def terminate(self, pids):
        self.calls.append("terminate")
        return {"ok": True}


@pytest.fixture()
def session():
    return build_session(pids=[1234], capabilities=["read", "write"])


# --------------------------------------------------------------------------- initialize


def test_initialize_reports_server_info(session):
    r = mcp_server.handle_message(session, FakeController(),
                                  {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                   "params": {"protocolVersion": "2024-11-05"}})
    res = r["result"]
    assert res["serverInfo"]["name"] == "superinject"
    assert res["serverInfo"]["version"] == __version__
    assert "tools" in res["capabilities"]
    assert res["protocolVersion"] == "2024-11-05"


def test_initialize_without_protocol_version_uses_default(session):
    r = mcp_server.handle_message(session, FakeController(),
                                  {"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert r["result"]["protocolVersion"]


# --------------------------------------------------------------------------- tools/list


def test_tools_list_returns_array_filtered_by_session():
    ro = build_session(pids=[1234], capabilities=["read"])
    r = mcp_server.handle_message(ro, FakeController(),
                                  {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    names = {t["name"] for t in r["result"]["tools"]}
    assert "list_processes" in names
    assert "terminate" not in names


# --------------------------------------------------------------------------- tools/call


def test_tools_call_success(session):
    ctrl = FakeController()
    r = mcp_server.handle_message(session, ctrl,
                                  {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                   "params": {"name": "list_processes", "arguments": {}}})
    assert r["result"]["isError"] is False
    assert ctrl.calls == ["list_processes"]
    payload = json.loads(r["result"]["content"][0]["text"])
    assert payload[0]["pid"] == 1234


def test_tools_call_denied_is_error_not_exception():
    """越权必须是结构化响应，不能抛异常 —— 否则 Agent 看不到拒绝原因。"""
    ro = build_session(pids=[1234], capabilities=["read"])
    ctrl = FakeController()
    r = mcp_server.handle_message(ro, ctrl,
                                  {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                   "params": {"name": "mem_write",
                                              "arguments": {"pid": 1234, "address": 1,
                                                            "hexdata": "90"}}})
    assert r["result"]["isError"] is True
    payload = json.loads(r["result"]["content"][0]["text"])
    assert payload["error"] == "consent_denied"
    assert payload["capability"] == "write"
    assert ctrl.calls == [], "越权时绝不能调用 Controller"


def test_tools_call_missing_name_is_invalid_params(session):
    r = mcp_server.handle_message(session, FakeController(),
                                  {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                   "params": {"arguments": {}}})
    assert r["error"]["code"] == -32602


def test_unknown_method_returns_method_not_found(session):
    r = mcp_server.handle_message(session, FakeController(),
                                  {"jsonrpc": "2.0", "id": 6, "method": "no/such/method"})
    assert r["error"]["code"] == -32601


# --------------------------------------------------------------------------- 通知 / 错误包


def test_notifications_get_no_response(session):
    assert mcp_server.handle_message(
        session, FakeController(),
        {"jsonrpc": "2.0", "method": "notifications/initialized"}) is None


def test_request_without_id_is_treated_as_notification(session):
    assert mcp_server.handle_message(
        session, FakeController(), {"jsonrpc": "2.0", "method": "ping"}) is None


def test_non_dict_message_is_invalid_request(session):
    r = mcp_server.handle_message(session, FakeController(), "not a dict")
    assert r["error"]["code"] == -32600


# --------------------------------------------------------------------------- stdout 纯净性（硬约束）


def test_stdout_carries_only_jsonrpc_frames(session):
    """stdio 传输要求 stdout 只有 JSON-RPC 帧；任何日志混进去都会破坏协议。"""
    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "list_processes", "arguments": {}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
    stdout = io.StringIO()

    rc = mcp_server.run_stdio(session, FakeController(), stdin=stdin, stdout=stdout)
    assert rc == 0

    lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
    # 4 条请求里 2 条通知不回应 → 3 条响应
    assert len(lines) == 3, f"响应条数不对：{len(lines)}"
    for line in lines:
        obj = json.loads(line)  # 非 JSON 行会在这里炸
        assert obj["jsonrpc"] == "2.0"
        assert "result" in obj or "error" in obj


def test_stdio_reports_parse_error_without_dying(session):
    stdin = io.StringIO("this is not json\n" +
                        json.dumps({"jsonrpc": "2.0", "id": 9, "method": "ping"}) + "\n")
    stdout = io.StringIO()

    rc = mcp_server.run_stdio(session, FakeController(), stdin=stdin, stdout=stdout)
    assert rc == 0, "坏包不能让主循环退出"
    lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 2
    assert json.loads(lines[0])["error"]["code"] == -32700
    assert json.loads(lines[1])["id"] == 9


def test_stdio_skips_blank_lines(session):
    stdin = io.StringIO("\n\n" +
                        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n\n")
    stdout = io.StringIO()
    mcp_server.run_stdio(session, FakeController(), stdin=stdin, stdout=stdout)
    lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 1, "空行不该产生响应"


# --------------------------------------------------------------------------- SDK 探测


def test_sdk_available_returns_bool():
    assert isinstance(mcp_server.sdk_available(), bool)
