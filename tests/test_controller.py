"""控制器逻辑测试（对 Win32 层做打桩，纯逻辑可在任意平台跑）。"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject import controller as ctl_mod
from superinject.controller import Controller, native_arch


@pytest.fixture()
def dll(tmp_path):
    p = tmp_path / "SuperInjectAgent.dll"
    p.write_bytes(b"MZ-fake")
    return p


# ------------------------------------------------------------------ 进程表

def test_list_processes_marks_injected(stub_winapi):
    c = Controller()
    items = c.list_processes()
    assert {i["pid"] for i in items} == {100, 200, 300}
    assert all(i["mem_mb"] == 12.5 for i in items)
    assert all(i["injected"] is False for i in items)


def test_list_processes_reflects_attached(stub_winapi, monkeypatch):
    c = Controller()
    monkeypatch.setattr(c.server, "is_attached", lambda pid: pid == 200)
    by_pid = {i["pid"]: i for i in c.list_processes()}
    assert by_pid[200]["injected"] is True
    assert by_pid[100]["injected"] is False


def test_resolve_by_name_and_pid(stub_winapi):
    c = Controller()
    assert c.resolve_targets([], ["chrome.exe"]) == [200]
    assert c.resolve_targets([], ["chrome.exe", "notepad.exe"]) == [200, 100]
    assert c.resolve_targets([100, 100], []) == [100]
    assert c.resolve_targets(["abc"], []) == []
    assert c.resolve_targets([], ["does-not-exist.exe"]) == []


def test_resolve_keeps_every_pid_of_same_name(stub_winapi, monkeypatch):
    """同名进程（多标签浏览器等）应全部返回，不能只取第一个。"""
    monkeypatch.setattr(ctl_mod.winapi, "enum_processes",
                        lambda: [(10, "chrome.exe"), (11, "chrome.exe")])
    c = Controller()
    assert c.resolve_targets([], ["chrome.exe"]) == [10, 11]


# ------------------------------------------------------------------ 注入检查

def test_preflight_blocks_critical_process(stub_winapi, monkeypatch):
    monkeypatch.setattr(ctl_mod.winapi, "enum_processes",
                        lambda: [(4, "System"), (900, "lsass.exe"), (100, "notepad.exe")])
    c = Controller()
    checks = {c0["pid"]: c0 for c0 in c.preflight([4, 900, 100])}
    assert checks[4]["blocked"] and "关键" in checks[4]["reason"]
    assert checks[900]["blocked"]
    assert checks[100]["ok"] and not checks[100]["blocked"]


def test_preflight_blocks_arch_mismatch(stub_winapi, monkeypatch):
    monkeypatch.setattr(ctl_mod.winapi, "is_wow64", lambda pid: True)   # 目标 32 位
    if native_arch() != "x64":
        pytest.skip("仅在 64 位 Python 下有意义")
    # 模拟「x86 DLL 不可用」：本机开发通常有 native/build/SuperInjectAgent_x86.dll，
    # 这里强行把 dll_for_arch x86 路径退掉，断言老逻辑仍能拦下。
    from superinject import dll_manager
    monkeypatch.setattr(dll_manager, "dll_for_arch",
                        lambda arch: None if arch == "x86" else dll_manager.dll_for_arch(arch))
    c = Controller()
    check = c.preflight([100])[0]
    assert check["blocked"] and "位数不匹配" in check["reason"]


def test_preflight_allows_arch_mismatch_when_dll_available(stub_winapi, monkeypatch):
    """x86 DLL 内嵌 / 已编目标下，跨位数应该被放行（带警告），而不是直接 blocked。"""
    monkeypatch.setattr(ctl_mod.winapi, "is_wow64", lambda pid: True)   # 目标 32 位
    if native_arch() != "x64":
        pytest.skip("仅在 64 位 Python 下有意义")
    from superinject import dll_manager
    monkeypatch.setattr(dll_manager, "dll_for_arch",
                        lambda arch: __import__("pathlib").Path("/dev/null"))
    c = Controller()
    check = c.preflight([100])[0]
    assert check["blocked"] is False
    assert check["ok"] is True
    assert any("x86" in w for w in check["warnings"])


def test_preflight_reports_inaccessible(stub_winapi, monkeypatch):
    monkeypatch.setattr(ctl_mod.winapi, "open_process", lambda pid, access=None: 0)
    monkeypatch.setattr(ctl_mod.winapi, "format_error", lambda code=None: "拒绝访问")
    c = Controller()
    check = c.preflight([100])[0]
    assert check["blocked"] and "拒绝访问" in check["reason"]


def test_preflight_rejects_self(stub_winapi):
    import os

    c = Controller()
    check = c.preflight([os.getpid()])[0]
    assert check["blocked"] and "自身" in check["reason"]


def test_preflight_warns_when_dll_loaded_but_not_attached(stub_winapi, monkeypatch):
    monkeypatch.setattr(ctl_mod.winapi, "module_loaded", lambda pid, name: True)
    c = Controller()
    check = c.preflight([100])[0]
    assert check["ok"] and check["warnings"]


# ------------------------------------------------------------------ 注入

def test_inject_missing_dll(stub_winapi, tmp_path):
    c = Controller(dll_path=tmp_path / "nope.dll")
    res = c.inject([100])
    assert res[0]["ok"] is False
    assert "不存在" in res[0]["error"]


def test_inject_registers_pipe_then_injects(stub_winapi, dll, monkeypatch, fast_inject):
    registered = []

    c = Controller(dll_path=dll)
    monkeypatch.setattr(c.server, "register", lambda pid: registered.append(pid))
    monkeypatch.setattr(c.server, "wait_attach", lambda pid, timeout=0: True)
    monkeypatch.setattr(ctl_mod.winapi, "inject_dll",
                        lambda pid, path, timeout=0: 0x140000000)

    res = c.inject([100, 200])
    assert registered == [100, 200]
    assert all(r["ok"] and r["attached"] and r["module"] == "0x140000000" for r in res)


def test_inject_reports_channel_failure(stub_winapi, dll, monkeypatch, fast_inject):
    """DLL 注入成功但没连上控制通道时必须算失败，不能谎报成功。"""
    c = Controller(dll_path=dll)
    monkeypatch.setattr(c.server, "register", lambda pid: None)
    monkeypatch.setattr(c.server, "wait_attach", lambda pid, timeout=0: False)
    monkeypatch.setattr(ctl_mod.winapi, "inject_dll", lambda pid, path, timeout=0: 0x140)

    res = c.inject([100])[0]
    assert res["ok"] is False
    assert res["injected"] is True          # 模块确实进去了
    assert "未建立控制通道" in res["error"]


def test_inject_failure_is_reported(stub_winapi, dll, monkeypatch, fast_inject):
    c = Controller(dll_path=dll)
    monkeypatch.setattr(c.server, "register", lambda pid: None)

    def boom(pid, path, timeout=0):
        raise OSError("拒绝访问")

    monkeypatch.setattr(ctl_mod.winapi, "inject_dll", boom)
    res = c.inject([100])
    assert res[0]["ok"] is False and "拒绝访问" in res[0]["error"]


def test_inject_blocked_process_not_touched(stub_winapi, dll, monkeypatch, fast_inject):
    monkeypatch.setattr(ctl_mod.winapi, "enum_processes", lambda: [(4, "System")])
    called = []
    monkeypatch.setattr(ctl_mod.winapi, "inject_dll",
                        lambda pid, path, timeout=0: called.append(pid) or 1)
    c = Controller(dll_path=dll)
    res = c.inject([4])
    assert res[0]["ok"] is False and res[0]["blocked"] is True
    assert called == []


def test_reinject_unloads_first(stub_winapi, dll, monkeypatch, fast_inject):
    """已注入的进程再次注入：必须先卸载旧 DLL 再注入（热更新）。"""
    events = []

    c = Controller(dll_path=dll)
    monkeypatch.setattr(c.server, "is_attached", lambda pid: True)
    monkeypatch.setattr(c.server, "register", lambda pid: events.append(("register", pid)))

    def fake_request(pid, cmd, timeout=0):
        events.append(("cmd", cmd.get("type")))
        return {"ok": True}

    monkeypatch.setattr(c.server, "request", fake_request)
    monkeypatch.setattr(c.server, "wait_detach", lambda pid, timeout=0: True)
    monkeypatch.setattr(ctl_mod.winapi, "inject_dll",
                        lambda pid, path, timeout=0: events.append(("inject", pid)) or 0x140)

    res = c.inject([100])[0]
    assert events[0] == ("cmd", "unload")
    assert ("inject", 100) in events
    assert res["reinjected"] is True and res["ok"] is True


def test_reinject_aborts_when_unload_fails(stub_winapi, dll, monkeypatch, fast_inject):
    c = Controller(dll_path=dll)
    monkeypatch.setattr(c.server, "is_attached", lambda pid: True)
    monkeypatch.setattr(c.server, "request", lambda pid, cmd, timeout=0: {"ok": True})
    monkeypatch.setattr(c.server, "wait_detach", lambda pid, timeout=0: False)
    called = []
    monkeypatch.setattr(ctl_mod.winapi, "inject_dll",
                        lambda pid, path, timeout=0: called.append(pid) or 1)

    res = c.inject([100])[0]
    assert res["ok"] is False and "卸载失败" in res["error"]
    assert called == []


def test_inject_stale_module_requires_restart(stub_winapi, dll, monkeypatch, fast_inject):
    """模块在但通道没连上（上次残留）时应明确报错，而不是假装成功。"""
    monkeypatch.setattr(ctl_mod.winapi, "module_loaded", lambda pid, name: True)
    c = Controller(dll_path=dll)
    monkeypatch.setattr(c.server, "wait_attach", lambda pid, timeout=0: False)
    called = []
    monkeypatch.setattr(ctl_mod.winapi, "inject_dll",
                        lambda pid, path, timeout=0: called.append(pid) or 1)

    res = c.inject([100])[0]
    assert res["ok"] is False and "请重启目标进程" in res["error"]
    assert called == []


# ------------------------------------------------------------------ 控制

def test_freeze_and_unfreeze(stub_winapi, monkeypatch):
    calls = []
    monkeypatch.setattr(ctl_mod.winapi, "suspend_process",
                        lambda pid: calls.append(("suspend", pid)) or True)
    monkeypatch.setattr(ctl_mod.winapi, "resume_process",
                        lambda pid: calls.append(("resume", pid)) or True)
    states = {100: True, 200: True}
    monkeypatch.setattr(ctl_mod.winapi, "process_suspend_state",
                        lambda pid: states.get(pid, False))
    c = Controller()
    assert all(r["ok"] for r in c.freeze([100, 200]))
    assert all(r["verified"] is True for r in c.freeze([100]))
    assert all(r["ok"] for r in c.unfreeze([100]))
    assert calls == [("suspend", 100), ("suspend", 200), ("suspend", 100), ("resume", 100)]


def test_unload_waits_for_detach(stub_winapi, monkeypatch):
    c = Controller()
    monkeypatch.setattr(c.server, "request", lambda pid, cmd, timeout=0: {"ok": True})
    monkeypatch.setattr(c.server, "wait_detach", lambda pid, timeout=0: True)
    monkeypatch.setattr(c.server, "unregister", lambda pid: None)
    res = c.unload([100])[0]
    assert res["ok"] and res["detached"] is True


def test_unload_flags_incomplete_detach(stub_winapi, monkeypatch):
    c = Controller()
    monkeypatch.setattr(c.server, "request", lambda pid, cmd, timeout=0: {"ok": True})
    monkeypatch.setattr(c.server, "wait_detach", lambda pid, timeout=0: False)
    monkeypatch.setattr(c.server, "unregister", lambda pid: None)
    res = c.unload([100])[0]
    assert res["detached"] is False and "卸载干净" in res["error"]


def test_status_shape(stub_winapi, tmp_path):
    c = Controller(dll_path=tmp_path / "a.dll")
    st = c.status()
    assert st["version"]
    assert st["dll_exists"] is False
    assert isinstance(st["injected"], dict)
    assert st["privilege"] == "admin"
    assert st["arch"] in ("x86", "x64")


# ------------------------------------------------------------------ 内存

def test_mem_search_rejects_bad_pattern(stub_winapi):
    c = Controller()
    res = c.mem_search([100], "not-hex!!")
    assert res[0]["ok"] is False


def test_mem_search_sends_normalized_pattern(stub_winapi, monkeypatch):
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


# ------------------------------------------------------------------ 资源

def test_resources_builds_preview_urls(stub_winapi, tmp_path, monkeypatch):
    export = tmp_path / "SuperInject" / "100"
    export.mkdir(parents=True)
    img = export / "res_100_1.png"
    img.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)

    c = Controller()
    c.preview_url = lambda p: f"http://127.0.0.1:9/{'100/res_100_1.png'}"
    monkeypatch.setattr(c.server, "request", lambda pid, cmd, timeout=0: {
        "ok": True, "dir": str(export),
        "items": [{"path": str(img), "ext": "png", "size": 40, "source": "mapped"}],
    })
    item = c.resources([100])[0]["resp"]["items"][0]
    assert item["kind"] == "image"
    assert item["previewable"] is True
    assert item["url"].endswith("100/res_100_1.png")
    assert item["origin"] == str(img)


def test_resources_converts_dib_dump(stub_winapi, tmp_path, monkeypatch):
    """RT_BITMAP 的裸 DIB 应被转成可打开的 .bmp。"""
    import struct

    export = tmp_path / "SuperInject" / "100"
    export.mkdir(parents=True)
    dib = export / "res_100_1.dib"
    dib.write_bytes(struct.pack("<IiiHHIIiiII", 40, 2, 2, 1, 24, 0, 16, 0, 0, 0, 0)
                    + b"\x00" * 16)

    c = Controller()
    monkeypatch.setattr(c.server, "request", lambda pid, cmd, timeout=0: {
        "ok": True, "dir": str(export),
        "items": [{"path": str(dib), "ext": "dib", "rtype": 2, "size": 56,
                   "source": "resource"}],
    })
    item = c.resources([100])[0]["resp"]["items"][0]
    assert item["ext"] == "bmp" and item["kind"] == "image"
    assert Path(item["path"]).name == "res_100_1.bmp"
    assert Path(item["path"]).read_bytes()[:2] == b"BM"
    assert item["dump"] == str(dib)
