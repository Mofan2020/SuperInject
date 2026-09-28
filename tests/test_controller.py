"""控制器逻辑测试（对 Win32 层做打桩，纯逻辑可在任意平台跑）。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject import controller as ctl_mod
from superinject.controller import Controller


@pytest.fixture()
def fake_procs(monkeypatch):
    table = [(100, "notepad.exe"), (200, "chrome.exe"), (300, "SuperInject.exe")]
    monkeypatch.setattr(ctl_mod.winapi, "enum_processes", lambda: table)
    monkeypatch.setattr(ctl_mod.winapi, "process_path",
                        lambda pid: f"C:\\{pid}.exe")
    monkeypatch.setattr(ctl_mod.winapi, "process_memory_mb", lambda pid: 12.5)
    return table


def test_list_processes_marks_injected(fake_procs, monkeypatch):
    monkeypatch.setattr(ctl_mod.winapi, "os_getpid", lambda: 999)
    c = Controller()
    items = c.list_processes()
    assert {i["pid"] for i in items} == {100, 200, 300}
    assert all(i["mem_mb"] == 12.5 for i in items)
    assert all(i["injected"] is False for i in items)


def test_resolve_by_name_and_pid(fake_procs):
    c = Controller()
    assert c.resolve_targets([], ["chrome.exe"]) == [200]
    assert c.resolve_targets([], ["chrome.exe", "notepad.exe"]) == [200, 100]
    assert c.resolve_targets([100, 100], []) == [100]
    assert c.resolve_targets(["abc"], []) == []
    assert c.resolve_targets([], ["does-not-exist.exe"]) == []


def test_inject_missing_dll(fake_procs, tmp_path):
    c = Controller(dll_path=tmp_path / "nope.dll")
    res = c.inject([100])
    assert res[0]["ok"] is False
    assert "不存在" in res[0]["error"]


def test_inject_registers_pipe_then_injects(fake_procs, tmp_path, monkeypatch):
    dll = tmp_path / "SuperInjectAgent.dll"
    dll.write_bytes(b"MZ")
    registered = []

    c = Controller(dll_path=dll)
    monkeypatch.setattr(c.server, "register", lambda pid: registered.append(pid))
    monkeypatch.setattr(ctl_mod.winapi, "inject_dll", lambda p: 0x140000000)

    res = c.inject([100, 200])
    assert registered == [100, 200]
    assert all(r["ok"] and r["module"] == "0x140000000" for r in res)


def test_inject_failure_is_reported(fake_procs, tmp_path, monkeypatch):
    dll = tmp_path / "SuperInjectAgent.dll"
    dll.write_bytes(b"MZ")
    c = Controller(dll_path=dll)
    monkeypatch.setattr(c.server, "register", lambda pid: None)

    def boom(pid):
        raise OSError("拒绝访问")

    monkeypatch.setattr(ctl_mod.winapi, "inject_dll", boom)
    res = c.inject([100])
    assert res[0]["ok"] is False and "拒绝访问" in res[0]["error"]


def test_freeze_and_unfreeze(fake_procs, monkeypatch):
    calls = []
    monkeypatch.setattr(ctl_mod.winapi, "suspend_process",
                        lambda pid: calls.append(("suspend", pid)) or True)
    monkeypatch.setattr(ctl_mod.winapi, "resume_process",
                        lambda pid: calls.append(("resume", pid)) or True)
    c = Controller()
    assert all(r["ok"] for r in c.freeze([100, 200]))
    assert all(r["ok"] for r in c.unfreeze([100]))
    assert calls == [("suspend", 100), ("suspend", 200), ("resume", 100)]


def test_mem_search_rejects_bad_pattern(fake_procs):
    c = Controller()
    res = c.mem_search([100], "not-hex!!")
    assert res[0]["ok"] is False


def test_mem_search_sends_normalized_pattern(fake_procs, monkeypatch):
    sent = {}

    c = Controller()
    monkeypatch.setattr(
        c.server, "request",
        lambda pid, cmd, timeout=0: sent.update({"pid": pid, "cmd": cmd}) or
        {"ok": True, "results": [], "count": 0},
    )
    res = c.mem_search([100], "4D 5A ?? ??", 10)
    assert res[0]["ok"] is True
    assert sent["cmd"]["pattern"] == "4d5a0000"
    assert sent["cmd"]["mask"] == "ffff0000"
    assert sent["cmd"]["max"] == 10


def test_status_shape(fake_procs, tmp_path):
    c = Controller(dll_path=tmp_path / "a.dll")
    st = c.status()
    assert st["version"]
    assert st["dll_exists"] is False
    assert isinstance(st["injected"], dict)
