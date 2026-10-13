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


def test_list_processes_filters_by_name_substr(stub_winapi):
    """list_processes(name_substr=...) 只返回名字含子串的进程。"""
    c = Controller()
    out = c.list_processes(name_substr="chrome")
    assert [i["pid"] for i in out] == [200]


def test_list_processes_filters_by_path_substr(stub_winapi):
    """list_processes(path_substr=...) 是按**进程映像路径**找进程的核心入口。

    stub 给出 path = "C:\\<pid>.exe"，所以 "C:\\200.exe" 命中 PID 200，
    "notepad" 不命中（stub path 里没有这些字串 —— path 过滤只看路径，
    不看名字）。
    """
    c = Controller()
    out = c.list_processes(path_substr=r"C:\200.exe")
    assert [i["pid"] for i in out] == [200]
    out2 = c.list_processes(path_substr="notepad")
    assert out2 == []                # path 过滤只看路径，不看名字


def test_list_processes_filters_by_arch(stub_winapi, monkeypatch):
    """list_processes(arch="x64"/"x86") 按位数过滤。"""
    monkeypatch.setattr(ctl_mod.winapi, "is_wow64",
                        lambda pid: pid == 100)     # 100 是 x86, 200/300 是 x64
    c = Controller()
    out_x86 = c.list_processes(arch="x86")
    out_x64 = c.list_processes(arch="x64")
    assert [i["pid"] for i in out_x86] == [100]
    assert sorted(i["pid"] for i in out_x64) == [200, 300]
    # 透出 arch 字段
    for i in out_x86:
        assert i["arch"] == "x86"


def test_find_in_dir_returns_only_processes_under_parent(stub_winapi):
    """find_in_dir 按父目录子串找进程：避免 path 子串误匹配。

    stub 的 path 是 "C:\\<pid>.exe"，父目录全是 "C:\\"。
    子串 "C:\\" 应当命中所有 3 个 PID；
    子串 "D:\\" 一个都不命中。
    """
    c = Controller()
    out = c.find_in_dir("C:" + chr(92))   # 末尾反斜杠（"C:\\" 写法 raw string
                                            # 不允许末尾带 \\）
    assert {i["pid"] for i in out} == {100, 200, 300}
    out_none = c.find_in_dir("D:" + chr(92))
    assert out_none == []


def test_resolve_targets_accepts_paths(stub_winapi):
    """resolve_targets(paths=...) 接路径子串列表。

    stub path 形如 "C:\\<pid>.exe"（Windows 真实路径）。这里用
    进程名做子串更稳：stub path 包含数字 pid，所以 "C:\\200.exe"
    中的 "200" 真在 path 里（不会误中 100 / 300，因为它们含 100
    / 300 不含 "200"）。用反斜杠字面要小心 Python 字符串转义：
    raw string r"C:\\200.exe" 才能正确表达 1 个反斜杠。
    """
    c = Controller()
    out = c.resolve_targets([], [], paths=[r"C:\200.exe"])
    p200 = ctl_mod.winapi.process_path(200)
    p300 = ctl_mod.winapi.process_path(300)
    q = r"C:\200.exe"
    debug = "out=%r q=%r p200=%r p300=%r" % (out, q, p200, p300)
    assert out == [200], debug
    # 不应误中 100 / 300
    out2 = c.resolve_targets([], [], paths=[r"C:\300.exe"])
    assert out2 == [300]


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


# ----------------------------------------------------------- 事件路由

def test_event_callback_and_list(stub_winapi):
    """DLL 推上来的事件要进 ``_events`` 列表并触发 ``on_event`` 回调。"""
    import threading

    from superinject import controller as ctl_mod
    c = ctl_mod.Controller.__new__(ctl_mod.Controller)
    c.server = ipc_server_stub()
    c._lock = threading.Lock()
    c._injected = {}
    c._frozen = set()
    c._change_cb = None
    c._events = []
    c._event_seq = 0
    c._event_cb = None
    seen: list[dict] = []
    c.on_event(lambda evt: seen.append(evt))
    c._on_event(4321, {"type": "event:crash",
                      "path": "C:/tmp/x.dmp",
                      "reason": "AV",
                      "address": "0x00007FF6ABCD"})
    assert len(seen) == 1
    assert seen[0]["pid"] == 4321
    assert seen[0]["type"] == "event:crash"
    assert seen[0]["reason"] == "AV"
    # 列表查询：按 pid 过滤 + 按 name 过滤 + clear
    items = c.list_events(pid=4321)
    assert len(items) == 1 and items[0]["path"] == "C:/tmp/x.dmp"
    c._on_event(4322, {"type": "event:patch",
                       "name": "patched",
                       "rva": 0x1000})
    only_patch = c.list_events(name="patch")
    assert len(only_patch) == 1 and only_patch[0]["pid"] == 4322
    c.list_events(clear=True)
    assert c.list_events() == []


def ipc_server_stub():
    """只暴露 ``on_event`` 属性，其他方法假装在场的最小 server 占位。

    cast 到 ``Any`` 是因为 SimpleNamespace 不是 AgentServer 类型 —— 这只是
    单测里的轻量替身，不需要拉起真 socket。
    """
    from types import SimpleNamespace
    obj = SimpleNamespace(on_attach=None, on_detach=None,
                          is_attached=lambda pid: False,
                          attached_pids=lambda: set())
    return obj  # type: ignore[return-value]


# ----------------------------------------------------------- 扫描 dump

def test_detach_synthesizes_crash_events(stub_winapi, tmp_path, monkeypatch):
    """目标进程断开后，dump 目录里新出现的 .dmp 应被合成 event:crash。
    attach 时记录的"水位线"过滤掉 attach 之前已经存在的旧 dump。
    """
    # 把 ipc.work_dir 指到 tmp_path/SuperInject
    base = tmp_path / "SuperInject"
    pid_dir = base / "7777"
    pid_dir.mkdir(parents=True)

    import threading

    from superinject import controller as ctl_mod
    from superinject import ipc as ipc_mod

    monkeypatch.setattr(ipc_mod, "work_dir", lambda: base)
    monkeypatch.setattr(ctl_mod.ipc, "work_dir", lambda: base)

    c = ctl_mod.Controller.__new__(ctl_mod.Controller)
    c.server = ipc_server_stub()
    c._lock = threading.Lock()
    c._injected = {}
    c._frozen = set()
    c._change_cb = None
    c._events = []
    c._event_seq = 0
    c._event_cb = None
    c._seen_dump_mtime = {}

    seen: list[dict] = []
    c.on_event(lambda e: seen.append(e))

    # attach 前先放一个旧 dump（mtime 较早），应该被过滤掉
    old = pid_dir / "dump-old.dmp"
    old.write_bytes(b"\x00" * 128)
    # 把它 mtime 调到很早
    import os as _os
    _os.utime(old, (1_000_000, 1_000_000))
    # attach 时设水位线 = 最大 mtime = 1_000_000
    c._on_attach(7777, {"image": "fake.exe"})

    # detach 之前再放两个新 dump：应被合成
    new1 = pid_dir / "dump-1.dmp"
    new1.write_bytes(b"X" * 256)
    new2 = pid_dir / "dump-2.dmp"
    new2.write_bytes(b"Y" * 512)
    # 写 sidecar
    (pid_dir / "dump-1.dmp.json").write_text(
        '{"pid":7777,"tid":42,"reason":"ACCESS_VIOLATION","code":3221225477,'
        '"address":"0x00007FF6ABCD","flags":0,"tick":1000,"dump":"<d>"}',
        encoding="utf-8")

    c._on_detach(7777)

    only_crash = [e for e in c.list_events() if e.get("type") == "event:crash"]
    assert len(only_crash) == 2, (c.list_events(), only_crash)
    # 排序不固定；sidecar 只在 dump-1 上有，dump-2 reason 应为空字符串兜底
    by_path = {e["path"]: e for e in only_crash}
    assert by_path[str(new1)]["reason"] == "ACCESS_VIOLATION"
    assert by_path[str(new1)]["address"] == "0x00007FF6ABCD"
    assert by_path[str(new1)]["tid"] == 42
    assert by_path[str(new2)]["reason"] == ""   # 兜底
    # on_event 回调也是两条
    assert len([e for e in seen if e["type"] == "event:crash"]) == 2


def test_detach_no_new_dump_stays_quiet(stub_winapi, tmp_path, monkeypatch):
    """水位线之后没有新 dump → 不应合成 event。"""
    import threading

    from superinject import controller as ctl_mod
    from superinject import ipc as ipc_mod
    base = tmp_path / "SuperInject"
    pid_dir = base / "8888"
    pid_dir.mkdir(parents=True)

    monkeypatch.setattr(ipc_mod, "work_dir", lambda: base)
    monkeypatch.setattr(ctl_mod.ipc, "work_dir", lambda: base)

    c = ctl_mod.Controller.__new__(ctl_mod.Controller)
    c.server = ipc_server_stub()
    c._lock = threading.Lock()
    c._injected = {}
    c._frozen = set()
    c._change_cb = None
    c._events = []
    c._event_seq = 0
    c._event_cb = None
    c._seen_dump_mtime = {}

    c._on_attach(8888, {"image": "fake.exe"})
    c._on_detach(8888)
    assert c.list_events() == []
