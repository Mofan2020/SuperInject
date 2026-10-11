"""CLI 模式（``-c``）的解析与分发测试。

跨平台：所有 Win32 调用都打桩。
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import superinject.cli as cli
from superinject import controller as ctl_mod

# ---------------------------------------------------------------- help

def test_help_runs_without_cli_flag(capsys):
    """``-h`` 必须独立可用，不需要 ``-c``。"""
    rc = cli.run(["-h"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "SuperInject" in out and "inject" in out


def test_missing_cli_flag_rejected(capsys):
    rc = cli.run([])
    assert rc == 64


# ---------------------------------------------------------------- parse

def test_parse_subcommand_style():
    pre, sub, rest = cli.parse(["-c", "-y", "inject", "1234", "--json"])
    assert pre.cli is True and pre.yes is True and pre.json is True
    assert sub == "inject"
    assert rest == ["1234"]


def test_parse_flag_before_subcommand():
    pre, sub, rest = cli.parse(["-c", "-y", "--json", "inject", "1234"])
    assert pre.json is True and sub == "inject" and rest == ["1234"]


def test_parse_single_string_dsl():
    pre, sub, rest = cli.parse(["-c", "-y", "inject 1234 --json"])
    assert sub == "inject" and rest == ["1234", "--json"]


def test_parse_with_double_dash_alias():
    pre, sub, _ = cli.parse(["--cli", "--yes", "list"])
    assert pre.cli and pre.yes and sub == "list"


# ---------------------------------------------------------------- yes gate

def test_yes_required(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    rc = cli.run(["-c", "list"])
    assert rc == 3
    err = capsys.readouterr().out
    assert "-y" in err


# ---------------------------------------------------------------- helpers

def _win(monkeypatch, items_or_factory):
    """统一打桩：把 winapi.IS_WINDOWS 强制 True + 替成假 Controller。"""
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    if callable(items_or_factory):
        monkeypatch.setattr(cli, "_ensure_controller", items_or_factory)
    else:
        items = items_or_factory

        class _FakeCtrl:
            def list_processes(self_inner):
                return list(items)

        monkeypatch.setattr(cli, "_ensure_controller",
                            lambda dll_path=None: _FakeCtrl())


# ---------------------------------------------------------------- list

def test_list_filters_by_path(monkeypatch, capsys):
    items = [
        {"pid": 1, "name": "chrome.exe",
         "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "injected": False},
        {"pid": 2, "name": "notepad.exe", "path": "C:\\Windows\\notepad.exe",
         "injected": True},
        {"pid": 3, "name": "calc.exe", "path": "C:\\Windows\\System32\\calc.exe",
         "injected": False},
    ]
    _win(monkeypatch, items)
    rc = cli.run(["-c", "-y", "list", "--path", "Windows"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "notepad.exe" in out
    assert "calc.exe" in out
    assert "chrome.exe" not in out


def test_list_injected_only(monkeypatch, capsys):
    items = [
        {"pid": 1, "name": "a.exe", "path": "p1", "injected": False},
        {"pid": 2, "name": "b.exe", "path": "p2", "injected": True},
    ]
    _win(monkeypatch, items)
    cli.run(["-c", "-y", "list", "--injected-only"])
    out = capsys.readouterr().out
    assert "b.exe" in out and "a.exe" not in out


def test_list_filters_by_name(monkeypatch, capsys):
    items = [
        {"pid": 1, "name": "chrome.exe", "path": "C:\\chrome.exe",
         "injected": False},
        {"pid": 2, "name": "notepad.exe", "path": "C:\\Windows\\notepad.exe",
         "injected": False},
    ]
    _win(monkeypatch, items)
    cli.run(["-c", "-y", "list", "--name", "chrome"])
    out = capsys.readouterr().out
    assert "chrome.exe" in out
    assert "notepad.exe" not in out


def test_list_json_output(monkeypatch, capsys):
    items = [{"pid": 1, "name": "a.exe", "path": "p1", "injected": False}]
    _win(monkeypatch, items)
    rc = cli.run(["-c", "-y", "--json", "list"])
    out = capsys.readouterr().out
    assert rc == 0
    parsed = json.loads(out)
    assert isinstance(parsed, list) and parsed[0]["name"] == "a.exe"


# ---------------------------------------------------------------- inject

def test_inject_requires_pid(monkeypatch, capsys):
    _win(monkeypatch, lambda dll_path=None: type("C", (), {})())
    rc = cli.run(["-c", "-y", "inject"])
    out = capsys.readouterr().out
    assert "缺少" in out and rc != 0


def test_inject_groups_by_arch(monkeypatch, capsys):
    """多进程混位数：按目标位数分组批量注入。"""
    monkeypatch.setattr(ctl_mod.winapi, "is_wow64", lambda pid: pid == 100)
    from superinject import dll_manager
    # Windows 上 ``Path("/tmp/fake-x64.dll")`` 会被解析成 ``\\tmp\\fake-x64.dll``，
    # 用 tempfile.mkdtemp 拿一个跨平台都正常的目录。
    td = Path(tempfile.mkdtemp())
    monkeypatch.setattr(dll_manager, "dll_for_arch",
                        lambda arch: td / f"fake-{arch}.dll")

    calls = []

    class FakeCtrl:
        def __init__(self, dll_path=None):
            self.dll_path = dll_path

        def inject(self, pids, dll_path=None, **kw):
            calls.append((self.dll_path, list(pids)))
            return [{"pid": p, "ok": True, "injected": True, "attached": True}
                    for p in pids]

    # 关键：cli._resolve_dll_for_pid 通过 cli.winapi.is_wow64 探测位数；
    # FakeCtrl 上的 dll_path 必须用 dll_for_arch 的返回值（也是测试桩替过的），
    # 否则 dispatcher 会进入 None 分支。
    monkeypatch.setattr(cli, "winapi",
                        type("W", (), {"IS_WINDOWS": True, "is_wow64":
                                       lambda pid: pid == 100}))
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "_ensure_controller", FakeCtrl)

    rc = cli.run(["-c", "-y", "--json", "inject",
                  "--pid", "100", "--pid", "200"])
    assert rc == 0
    paths = sorted(str(p) for p, _ in calls)
    assert str(td / "fake-x64.dll") in paths
    assert str(td / "fake-x86.dll") in paths


def test_inject_arch_override(monkeypatch, capsys):
    """显式 ``--arch x86`` 时所有目标走同一 DLL。"""
    from superinject import dll_manager
    td = Path(tempfile.mkdtemp())
    monkeypatch.setattr(dll_manager, "dll_for_arch",
                        lambda arch: td / f"fake-{arch}.dll")

    calls = []

    class FakeCtrl:
        def __init__(self, dll_path=None):
            self.dll_path = dll_path

        def inject(self, pids, dll_path=None, **kw):
            calls.append((str(self.dll_path), list(pids)))
            return [{"pid": p, "ok": True} for p in pids]

    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", FakeCtrl)
    rc = cli.run(["-c", "-y", "--json", "inject",
                  "--pid", "100", "--pid", "200", "--arch", "x86"])
    assert rc == 0
    assert len(calls) == 1
    assert calls[0][0] == str(td / "fake-x86.dll")
    assert calls[0][1] == [100, 200]


# ---------------------------------------------------------------- misc

def test_no_windows_returns_error(monkeypatch):
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": False}))
    rc = cli.run(["-c", "-y", "list"])
    assert rc == 4


def test_unknown_subcommand(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    rc = cli.run(["-c", "-y", "bogus"])
    assert rc != 0
    out = capsys.readouterr().out
    assert "未知子命令" in out


def test_status_uses_controller(monkeypatch, capsys):
    captured = []

    class FakeCtrl:
        def status(self):
            captured.append(True)
            return {"ok": True, "kind": "status", "version": "1.1.0",
                    "arch": "x64"}

    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())
    rc = cli.run(["-c", "-y", "status"])
    assert rc == 0
    assert captured == [True]
    out = capsys.readouterr().out
    assert "1.1.0" in out


def test_dll_subcommand(stub_winapi, monkeypatch, capsys):
    """``dll`` 子命令走 dll_manager.verify_and_sync。"""
    from superinject import dll_manager
    monkeypatch.setattr(dll_manager, "verify_and_sync",
                        lambda path=None, force=False, arch="x64":
                        dll_manager.VerifyResult(
                            ok=True, action="ok", path=Path("/tmp/x.dll"),
                            message="ok", embedded_sha="abc",
                            disk_sha="abc"))
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller",
                        lambda dll_path=None: type("C", (), {})())
    rc = cli.run(["-c", "-y", "--json", "dll"])
    assert rc == 0
    out = capsys.readouterr().out
    parsed = json.loads(out)
    assert parsed["kind"] == "dll" and parsed["ok"] is True


def test_report_writes_to_disk(stub_winapi, monkeypatch, tmp_path, capsys):
    items = [{"pid": 1, "name": "a.exe", "path": "p1", "injected": False}]
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller",
                        lambda dll_path=None: type("C", (), {
                            "list_processes": lambda self: items})())
    out_path = tmp_path / "report.json"
    rc = cli.run(["-c", "-y", "--json", "--report", str(out_path), "list"])
    assert rc == 0
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data[0]["name"] == "a.exe"


def test_mem_read(monkeypatch, capsys):
    class FakeCtrl:
        def mem_read(self, pid, address, size):
            return {"ok": True, "kind": "mem-read", "hex": "DEADBEEF",
                    "address": address, "size": size}
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())
    rc = cli.run(["-c", "-y", "--json",
                  "mem-read", "--pid", "100", "--address", "0x401000", "--size", "16"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["hex"] == "DEADBEEF" and data["address"] == 0x401000


def test_mem_search(monkeypatch, capsys):
    class FakeCtrl:
        def mem_search(self, pids, pattern, max_results):
            return [{"pid": 100, "ok": True, "resp": {"results": []}}]
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())
    rc = cli.run(["-c", "-y", "--json",
                  "mem-search", "--pid", "100", "--pattern", "4D 5A ?? ??"])
    assert rc == 0


def test_info_passes_no_exports_and_budget(monkeypatch, capsys):
    seen = {}

    class FakeCtrl:
        def info(self, pids, no_exports, budget):
            seen["pids"] = pids
            seen["no_exports"] = no_exports
            seen["budget"] = budget
            return [{"pid": 100, "ok": True,
                     "resp": {"modules": [], "ok": True}}]

    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())
    rc = cli.run(["-c", "-y", "--json", "info",
                  "--pid", "100", "--no-exports", "--exports-budget", "8"])
    assert rc == 0
    assert seen["pids"] == [100]
    assert seen["no_exports"] is True
    assert seen["budget"] == 8


def test_exports_forwards_address_and_name(monkeypatch, capsys):
    seen = {}

    class FakeCtrl:
        def exports(self, pid, name, base, budget):
            seen["args"] = (pid, name, base, budget)
            return {"ok": True, "count": 2,
                    "exports": [{"name": "Foo", "rva": 0x100, "ord": 1},
                                {"name": "Bar", "rva": 0x200, "ord": 2}]}

    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())
    rc = cli.run(["-c", "-y", "--json", "exports",
                  "--pid", "1234", "--name", "user32.dll",
                  "--base", "0x7FFE0000", "--budget", "32"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "exports"
    assert data["count"] == 2
    assert {e["name"] for e in data["exports"]} == {"Foo", "Bar"}
    assert seen["args"] == (1234, "user32.dll", 0x7FFE0000, 32)


# ----------------------------------------------------------- 线程

def test_threads_and_thread_control(monkeypatch, capsys):
    """threads / thread-suspend / thread-resume 子命令端到端。"""
    threads_resp = {
        "ok": True,
        "threads": [
            {"tid": 4321, "base_priority": 8, "delta_priority": 0,
             "suspend_count": 0, "state": "Wait", "wait_reason": "UserRequest",
             "description": "main"},
            {"tid": 8765, "base_priority": 8, "delta_priority": 0,
             "suspend_count": 1, "state": "Ready", "wait_reason": "",
             "description": "worker"},
        ],
    }

    class FakeCtrl:
        def threads(self, pid):
            self.seen_threads = pid
            return threads_resp

        def thread_suspend(self, pid, tid):
            self.suspend_call = (pid, tid)
            return {"ok": True, "tid": tid,
                    "prev_suspend_count": 0, "suspend_count": 1}

        def thread_resume(self, pid, tid):
            self.resume_call = (pid, tid)
            return {"ok": True, "tid": tid,
                    "prev_suspend_count": 1, "suspend_count": 0}

    ctrl = FakeCtrl()
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: ctrl)

    rc = cli.run(["-c", "-y", "--json", "threads", "--pid", "9999"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "threads"
    assert len(data["threads"]) == 2
    assert data["threads"][0]["tid"] == 4321
    assert ctrl.seen_threads == 9999

    rc = cli.run(["-c", "-y", "--json", "thread-suspend",
                  "--pid", "9999", "--tid", "8765"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "thread-suspend"
    assert data["tid"] == 8765
    assert data["prev_suspend_count"] == 0
    assert data["suspend_count"] == 1
    assert ctrl.suspend_call == (9999, 8765)

    rc = cli.run(["-c", "-y", "--json", "thread-resume",
                  "--pid", "9999", "--tid", "8765"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "thread-resume"
    assert data["prev_suspend_count"] == 1
    assert data["suspend_count"] == 0
    assert ctrl.resume_call == (9999, 8765)


def test_threads_returns_error_on_fail(monkeypatch, capsys):
    class FakeCtrl:
        def threads(self, pid):
            return {"ok": False, "error": "DLL 未注入",
                    "threads": []}

    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())
    rc = cli.run(["-c", "-y", "--json", "threads", "--pid", "9999"])
    # CLI 协议：dict.ok=False 时 exit code 2（与其它命令一致）
    assert rc == 2
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False
    assert data["error"] == "DLL 未注入"


# ----------------------------------------------------------- events / dumps

def test_events_lists_in_memory_queue(monkeypatch, capsys):
    """``events`` 子命令应读出控制器 ``list_events`` 的结果，--json 可读。"""
    fake_evts = [
        {"pid": 100, "type": "event:crash", "path": "x.dmp", "reason": "AV",
         "seq": 1, "ts_ms": 1700000000000},
        {"pid": 100, "type": "event:patch", "name": "patched", "seq": 2,
         "ts_ms": 1700000001000},
    ]

    class FakeCtrl:
        def __init__(self):
            self.calls = []

        def list_events(self, pid=None, name=None, clear=False):
            self.calls.append((pid, name, clear))
            return fake_evts

    ctrl = FakeCtrl()
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: ctrl)
    rc = cli.run(["-c", "-y", "--json", "events",
                  "--pid", "100", "--name", "crash"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "events"
    assert data["count"] == 2
    # pid 与 name 被传到 list_events
    assert ctrl.calls and ctrl.calls[0][:2] == (100, "crash")


def test_dumps_scans_work_dir(monkeypatch, tmp_path, capsys):
    """``dumps`` 应列出 ``%TEMP%/SuperInject/<pid>/dump-*.dmp``，无 PID 时
    枚举所有 PID 子目录。"""
    # 替换 ipc.work_dir 指向 tmp_path/SuperInject
    base = tmp_path / "SuperInject"
    (base / "1234").mkdir(parents=True)
    (base / "1234" / "dump-1.dmp").write_bytes(b"\x4D\x44\x4D\x50" + b"\x00" * 100)
    (base / "1234" / "dump-2.dmp").write_bytes(b"\x4D\x44\x4D\x50" + b"\x00" * 200)
    (base / "9999").mkdir(parents=True)
    (base / "9999" / "dump-x.dmp").write_bytes(b"x" * 50)

    opened_via = []

    class FakeCtrl:
        def open_path(self, p):
            opened_via.append(p)
            return True

    monkeypatch.setattr(cli, "ipc", _make_fake_ipc(base))
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())
    rc = cli.run(["-c", "-y", "--json", "dumps"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "dumps"
    # 两个 PID 各有文件，按 mtime 倒序：先 dump-2 再 dump-1，再 dump-x。
    paths = [it["path"] for it in data["items"]]
    assert len(paths) == 3
    assert any("1234/dump-1.dmp" in p for p in paths)
    assert any("1234/dump-2.dmp" in p for p in paths)
    assert any("9999/dump-x.dmp" in p for p in paths)


def _make_fake_ipc(base):
    """一个假装是 ``ipc`` 模块的对象。用普通类显式声明 staticmethod，
    避免 SimpleNamespace 把 lambda 自动转成 bound method 让 ``work_dir()`` 多收一个 self。
    """
    class _I:
        pass
    _I.work_dir = staticmethod(lambda: base)
    _I.parse_int = staticmethod(lambda s, d=0: int(str(s), 0))
    _I.now_ms = staticmethod(lambda: 0)
    _I.encode_frame = staticmethod(lambda d: b"")
    _I.decode_frames = staticmethod(lambda b: ([], bytearray()))
    return _I()


def test_dumps_open_picks_first(monkeypatch, tmp_path, capsys):
    base = tmp_path / "SuperInject"
    (base / "1234").mkdir(parents=True)
    (base / "1234" / "dump-1.dmp").write_bytes(b"y" * 10)

    opened_via = []

    class FakeCtrl:
        def open_path(self, p):
            opened_via.append(p)
            return True

    monkeypatch.setattr(cli, "ipc", _make_fake_ipc(base))
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())
    rc = cli.run(["-c", "-y", "--json", "dumps", "--open"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["opened"].endswith("dump-1.dmp")
    assert opened_via and opened_via[0].endswith("dump-1.dmp")
