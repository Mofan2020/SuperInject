"""MCP 路由层单测：工具清单分档、越权拒绝、目标白名单、正常分发。"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from superinject import mcp_router
from superinject.mcp_consent import build_session


class FakeController:
    """记录被调用过的 (方法名, 参数)，用于断言「越权时没碰 Controller」。"""

    def __init__(self) -> None:
        self.calls: List[tuple] = []

    def _record(self, name: str, *args, **kwargs) -> Dict[str, Any]:
        self.calls.append((name, args, kwargs))
        return {"ok": True, "method": name}

    def list_processes(self):
        return self._record("list_processes")

    def status(self):
        return self._record("status")

    def mem_write(self, pid, address, hexdata):
        return self._record("mem_write", pid, address, hexdata)

    def terminate(self, pids):
        return self._record("terminate", pids)

    def mem_read(self, pid, address, size=64):
        return self._record("mem_read", pid, address, size)


@pytest.fixture()
def ctrl():
    return FakeController()


# --------------------------------------------------------------------------- 工具清单


def test_tool_count_and_tier_split_matches_plan():
    """分档数量与 v1.3.0 计划一致 —— 改动工具清单时这条会提醒同步文档。"""
    from collections import Counter
    tiers = Counter(s.capability for s in mcp_router._TOOLS)
    assert tiers["read"] == 16
    assert tiers["write"] == 14
    assert tiers["dangerous"] == 1
    assert sum(tiers.values()) == 31


def test_list_tools_read_only_session_hides_write_and_dangerous():
    session = build_session(pids=[1234], capabilities=["read"])
    names = [t["name"] for t in mcp_router.list_tools(session)]
    assert "list_processes" in names
    assert "mem_write" not in names
    assert "terminate" not in names
    assert "breakpoint_set" not in names


def test_list_tools_full_session_exposes_everything():
    session = build_session(pids=[1234],
                            capabilities=["read", "write", "dangerous"])
    names = {t["name"] for t in mcp_router.list_tools(session)}
    assert "terminate" in names
    assert "mem_write" in names
    assert len(names) == 31


def test_list_tools_none_session_is_empty():
    assert mcp_router.list_tools(None) == []


def test_every_tool_has_usable_description_and_schema():
    """description 是给 Agent 看的，不能空、不能是免责声明套话。"""
    for spec in mcp_router._TOOLS:
        assert spec.description.strip(), f"{spec.name} 缺 description"
        assert len(spec.description) >= 8, f"{spec.name} 的 description 太短"
        schema = spec.input_schema
        assert isinstance(schema, dict)
        assert schema.get("type") == "object", f"{spec.name} schema 非 object"
        assert "properties" in schema, f"{spec.name} schema 缺 properties"


def test_dangerous_and_write_tools_declare_target_args():
    """带 PID 的工具必须声明 target_args，否则白名单校验会漏。"""
    for spec in mcp_router._TOOLS:
        if spec.name in {"status", "list_processes", "dll", "dumps", "events"}:
            continue
        assert spec.target_args, f"{spec.name} 未声明 target_args，白名单会漏校验"


# --------------------------------------------------------------------------- 越权（不碰 Controller）


def test_write_tool_denied_for_read_only_session(ctrl):
    session = build_session(pids=[1234], capabilities=["read"])
    out = mcp_router.call_tool(session, "mem_write",
                               {"pid": 1234, "address": 4096, "hexdata": "90"},
                               ctrl)
    assert out["error"] == "consent_denied"
    assert out["capability"] == "write"
    assert ctrl.calls == [], "越权时绝不能调用 Controller"


def test_dangerous_tool_denied_without_dangerous_tier(ctrl):
    session = build_session(pids=[1234], capabilities=["read", "write"])
    out = mcp_router.call_tool(session, "terminate", {"pids": [1234]}, ctrl)
    assert out["error"] == "consent_denied"
    assert out["capability"] == "dangerous"
    assert ctrl.calls == []


def test_unknown_tool_reported(ctrl):
    session = build_session(pids=[1234], capabilities=["read", "write"])
    out = mcp_router.call_tool(session, "definitely_not_a_tool", {}, ctrl)
    assert out["error"] == "unknown_tool"
    assert ctrl.calls == []


def test_target_outside_allowlist_denied(ctrl):
    session = build_session(pids=[1111], capabilities=["read", "write"])
    out = mcp_router.call_tool(session, "mem_write",
                               {"pid": 2222, "address": 4096, "hexdata": "90"},
                               ctrl, resolve_name=lambda p: "other.exe")
    assert out["error"] == "consent_denied"
    assert out.get("pid") == 2222
    assert ctrl.calls == [], "目标不在白名单时绝不能调用 Controller"


def test_target_allowed_by_name_glob(ctrl):
    session = build_session(names=["notepad*"], capabilities=["read"])
    out = mcp_router.call_tool(session, "mem_read",
                               {"pid": 4321, "address": 4096, "size": 16},
                               ctrl, resolve_name=lambda p: "notepad.exe")
    assert out.get("ok") is True
    assert ctrl.calls and ctrl.calls[0][0] == "mem_read"


# --------------------------------------------------------------------------- 正常分发


def test_read_tool_routes_to_controller(ctrl):
    session = build_session(pids=[1234], capabilities=["read"])
    out = mcp_router.call_tool(session, "list_processes", {}, ctrl)
    assert ctrl.calls, "正常调用必须落到 Controller"
    assert ctrl.calls[0][0] == "list_processes"
    assert isinstance(out, (list, dict)), "返回体必须是可 JSON 序列化的结构"


def test_write_tool_routes_when_authorised(ctrl):
    session = build_session(pids=[1234], capabilities=["read", "write"])
    out = mcp_router.call_tool(session, "mem_write",
                               {"pid": 1234, "address": 4096, "hexdata": "90"},
                               ctrl)
    assert out.get("ok") is True
    assert ctrl.calls[0][0] == "mem_write"


def test_missing_pid_argument_does_not_crash(ctrl):
    """没带 PID 的调用应当在 handler 层得到空值处理，而不是抛异常。"""
    session = build_session(pids=[1234], capabilities=["read", "write"])
    out = mcp_router.call_tool(session, "mem_write",
                               {"address": 4096, "hexdata": "90"}, ctrl)
    assert isinstance(out, dict), "缺失参数不能抛异常"
