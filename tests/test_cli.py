"""CLI 模式（``-c``）的解析与分发测试。

跨平台：所有 Win32 调用都打桩。
"""

from __future__ import annotations

import json
import sys
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
    import tempfile
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
    import tempfile
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
