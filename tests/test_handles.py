"""lsof-style handle enumeration tests (added in v1.3.3).

Covers three concerns:
  1) Controller._categorize_handle pure-logic categorization
     (Win32 object type name + name prefix rules)
  2) Controller.list_handles protocol layer: forwards ``handles`` to the
     injected DLL, then groups items into by_category with the right order
  3) MCP tool registration: list_handles appears in tools/list read tier

The unit tests are macOS-runnable (no Win32 dependency).
"""

from __future__ import annotations

import pytest

from superinject import controller as ctrl_mod
from superinject import mcp_router
from superinject.mcp_consent import build_session

# --------------------------------------------------------------------------- categorization


@pytest.mark.parametrize(
    "type_name,name,expected",
    [
        # Known Win32 type names map directly
        ("File",         r"C:\Windows\notepad.exe",          "文件"),
        ("NamedPipe",    r"\Device\NamedPipe\spoolss",       "管道"),
        ("Key",          r"\REGISTRY\MACHINE\SOFTWARE",      "注册表"),
        ("Event",        r"BaseNamedObjects\MyEvent",        "同步"),
        ("Semaphore",    "",                                  "同步"),
        ("Section",      "",                                  "内存"),
        ("Thread",       "",                                  "进程/线程"),
        ("WindowStation", "WinSta0",                          "GUI"),
        # Type unknown but name prefix is
        ("",             r"\Device\Tcp",                     "设备"),
        ("",             r"\Device\NamedPipe\foo",           "管道"),
        ("",             r"\REGISTRY\USER\Foo",              "注册表"),
        ("",             "AFD",                               "网络"),
        # Private type / no name
        ("SomePrivate",  "",                                  "Other"),
        ("",             "",                                  "Other"),
    ],
)
def test_categorize_handle(type_name, name, expected):
    assert ctrl_mod.Controller._categorize_handle(type_name, name) == expected


# --------------------------------------------------------------------------- protocol layer


class _FakeServer:
    def __init__(self, response):
        self._response = response
        self.calls = []

    def request(self, pid, msg, timeout=15):
        self.calls.append((pid, msg, timeout))
        return self._response


def test_list_handles_groups_by_category():
    fake = _FakeServer({
        "ok": True,
        "items": [
            {"handle": 0x10, "type": "File", "name": r"C:\a.txt", "access": 0x1F},
            {"handle": 0x20, "type": "Key",  "name": r"\REGISTRY\MACHINE", "access": 0xF},
            {"handle": 0x30, "type": "",     "name": r"\Device\Tcp", "access": 0x0},
            {"handle": 0x40, "type": "Unknown", "name": "", "access": 0x0},
        ],
    })
    c = ctrl_mod.Controller.__new__(ctrl_mod.Controller)
    c.server = fake
    r = c.list_handles(1234)

    assert r["ok"] is True
    assert r["pid"] == 1234
    assert r["count"] == 4
    assert set(r["by_category"].keys()) == {"文件", "注册表", "设备", "Other"}
    # category order follows _HANDLE_CATEGORY_ORDER
    cat_order = list(r["by_category"].keys())
    assert cat_order.index("文件") < cat_order.index("设备")
    file_items = r["by_category"]["文件"]
    assert file_items[0]["handle"] == 0x10
    assert file_items[0]["category"] == "文件"
    assert r["items"][2]["category"] == "设备"
    assert fake.calls[0][0] == 1234
    assert fake.calls[0][1] == {"type": "handles"}
    assert fake.calls[0][2] == 15


def test_list_handles_dll_error_propagates():
    fake = _FakeServer({
        "ok": False, "error": "NtQuerySystemInformation failed", "items": []
    })
    c = ctrl_mod.Controller.__new__(ctrl_mod.Controller)
    c.server = fake
    r = c.list_handles(1234)
    assert r["ok"] is False
    assert "NtQuerySystemInformation" in r["error"]
    assert r["count"] == 0
    assert r["items"] == []
    assert r["by_category"] == {}


# --------------------------------------------------------------------------- MCP registration


def test_list_handles_appears_in_tools_list():
    session = build_session(pids=[1234], capabilities=["read"])
    names = {t["name"] for t in mcp_router.list_tools(session)}
    assert "list_handles" in names


def test_list_handles_requires_read_capability():
    spec = mcp_router._TOOLS_BY_NAME["list_handles"]
    assert spec.capability == "read"
    assert "pid" in spec.input_schema["properties"]
    assert spec.input_schema.get("required") == ["pid"]


def test_list_handles_tier_count_bumped_to_32():
    """v1.3.3 adds list_handles, bringing the total to 32 tools
    (17 read + 14 write + 1 dangerous)."""
    from collections import Counter
    tiers = Counter(s.capability for s in mcp_router._TOOLS)
    assert tiers["read"] == 17
    assert tiers["write"] == 14
    assert tiers["dangerous"] == 1
    assert sum(tiers.values()) == 32


def test_list_handles_handler_calls_controller():
    fake = _FakeServer({"ok": True, "items": [
        {"handle": 0x10, "type": "File", "name": r"C:\a.txt", "access": 0x1F}
    ]})
    c = ctrl_mod.Controller.__new__(ctrl_mod.Controller)
    c.server = fake
    r = mcp_router._h_list_handles(c, {"pid": 9999})
    assert r["ok"] is True
    assert r["pid"] == 9999
    assert fake.calls[0][0] == 9999


def test_list_handles_handler_rejects_missing_pid():
    class _NoCall:
        def request(self, *a, **k):  # pragma: no cover
            raise AssertionError("should not be called")

    r = mcp_router._h_list_handles(_NoCall(), {})
    assert r["ok"] is False
    assert "pid" in r["error"]
