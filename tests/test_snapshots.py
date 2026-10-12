"""内存快照 / diff 控制器测试（跨平台）。

所有用例都打桩 — 内存读 / 写 / 快照都不真发生，
只走 Controller / SnapshotStore 两侧的协议层和落盘逻辑。

用 ``tmp_path`` 强制把 ``snapshot_root`` 重定向到本地目录，
避免污染 macOS / Linux 默认的 ``~/.local/share`` 或 Windows 的
``%LOCALAPPDATA%``。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject.controller import Controller
from superinject.snapshots import SnapshotStore, snapshot_root

# ---------------------------------------------- SnapshotStore 落盘往返


def _fake_snap(name: str, count: int = 4, byte_total: int = 16384,
               sha_seed: str = "abc") -> dict:
    """构造一份「看着像 DLL 返回」的快照 dict，用于 save/list/load。"""
    pages = []
    for i in range(count):
        addr = 0x1000 + i * 0x1000
        pages.append({
            "addr": addr,
            "size": 4096,
            "sha": sha_seed + format(i, "060x") + format(0, "0") + "0" * 58,
            "head64": format(i, "02x") * 64,
        })
    return {
        "ok": True,
        "name": name,
        "count": count,
        "bytes": byte_total,
        "sha256": sha_seed * 16 + sha_seed * 16,  # 64 hex chars
        "pages": pages,
    }


def test_snapshot_root_posix_layout(monkeypatch, tmp_path):
    """非 Windows 布局：``~/.local/share/SuperInject/snapshots``。

    用 ``is_windows=False`` 参数指定分支，**不要** patch ``os.name`` ——
    那会让 pathlib 以为自己在 POSIX 上，于是在 Windows 上去实例化
    ``PosixPath`` 并抛 ``NotImplementedError``（windows runner 曾因此全红）。
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    actual = str(snapshot_root(is_windows=False)).replace("\\", "/")
    assert actual.endswith("/.local/share/SuperInject/snapshots")
    assert str(tmp_path) in actual


def test_snapshot_root_windows_layout(monkeypatch, tmp_path):
    """Windows 布局：``%LOCALAPPDATA%\\SuperInject\\snapshots``。

    这条在 macOS 上同样要能跑 —— 以前只测了 POSIX 分支，Windows 分支
    从没被任何平台验证过。
    """
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    actual = snapshot_root(is_windows=True)
    assert actual == tmp_path / "SuperInject" / "snapshots"


def test_snapshot_root_windows_falls_back_without_localappdata(monkeypatch, tmp_path):
    """``LOCALAPPDATA`` 缺失时回退到 ``~/AppData/Local``。"""
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    actual = snapshot_root(is_windows=True)
    assert actual.parts[-3:] == ("SuperInject", "snapshots") or \
        actual.parts[-2:] == ("SuperInject", "snapshots")
    assert "AppData" in actual.parts


def test_snapshot_save_load_delete_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    store = SnapshotStore(root=tmp_path / "snaps")
    pid = 7777

    snap = _fake_snap("hello")
    path = store.save(pid, snap)
    assert path.exists()
    assert path.name == "hello.json"
    assert path.parent.name == "7777"

    # load → 与 save 的 dict 一致（pages 完整；索引项已加入）
    loaded = store.load(pid, "hello")
    assert loaded["name"] == "hello"
    assert loaded["count"] == 4
    assert loaded["pages"][0]["addr"] == 0x1000

    # delete → load() 抛 KeyError；索引也清掉
    assert store.delete(pid, "hello") is True
    assert not path.exists()
    with pytest.raises(KeyError):
        store.load(pid, "hello")


def test_snapshot_list_orders_by_created_at_and_dedupes(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    store = SnapshotStore(root=tmp_path / "snaps")
    pid = 1234
    # 三条独立快照
    store.save(pid, _fake_snap("a"))
    store.save(pid, _fake_snap("b"))
    store.save(pid, _fake_snap("c"))
    items = store.list(pid)
    assert [e.name for e in items] == ["a", "b", "c"]
    # 同名再 save 一遍 → 索引里只有 1 条（覆盖）
    store.save(pid, _fake_snap("a", sha_seed="zzzz"))
    again = store.list(pid)
    assert [e.name for e in again] == ["a", "b", "c"]
    assert again[0].sha256.startswith("zzzz")


def test_snapshot_atomic_write_no_partial_files(monkeypatch, tmp_path):
    """落盘用临时文件 + os.replace：中途抛错不会留下半截正式文件。"""
    monkeypatch.setenv("HOME", str(tmp_path))
    store = SnapshotStore(root=tmp_path / "snaps")
    pid = 4321
    # 让 json.dump 抛错（模拟磁盘写失败）
    from superinject import snapshots as snap_mod
    real_dump = snap_mod.json.dump
    def boom(*a, **kw):
        raise OSError("disk full")
    snap_mod.json.dump = boom
    try:
        with pytest.raises(OSError):
            store.save(pid, _fake_snap("will-fail"))
    finally:
        snap_mod.json.dump = real_dump
    # 不该留下 <name>.json
    assert not (tmp_path / "snaps" / str(pid) / "will-fail.json").exists()
    # 索引也不该被更新
    assert store.list(pid) == []


# ---------------------------------------------- Controller 协议层


def _patch_ctrl_env(monkeypatch, tmp_path):
    """把 SnapshotStore 默认根目录重定向到 tmp_path。

    ``Controller._snapshot_store`` 优先看 ``SUPERINJECT_SNAPSHOT_ROOT``
    环境变量，没设置再用 ``snapshot_root()`` 推出的目录。
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("SUPERINJECT_SNAPSHOT_ROOT", str(tmp_path / "snaps"))


def test_controller_snapshot_sends_frame_and_persists(monkeypatch, tmp_path):
    """Controller.snapshot：
       1. 发 ``mem_snapshot`` 帧到 DLL；
       2. DLL 返回的 JSON 落盘 + 索引同步。
    """
    _patch_ctrl_env(monkeypatch, tmp_path)
    sent = {}

    fake_resp = _fake_snap("snap-1", count=2, byte_total=8192)
    fake_resp["path"] = "ignored-by-controller"

    c = Controller()
    monkeypatch.setattr(
        c.server, "request",
        lambda pid, cmd, timeout=0: sent.update(
            {"pid": pid, "cmd": cmd, "_": "called"}) or dict(fake_resp),
    )
    out = c.snapshot(pid=100, name="snap-1")

    assert sent["cmd"]["type"] == "mem_snapshot"
    assert sent["cmd"]["name"] == "snap-1"
    assert "regions" not in sent["cmd"]
    assert out["ok"] is True
    assert out["name"] == "snap-1"
    assert out["count"] == 2
    # 落盘文件存在
    on_disk = tmp_path / "snaps" / str(100) / "snap-1.json"
    assert on_disk.exists()
    assert json.loads(on_disk.read_text(encoding="utf-8"))["sha256"][:8] == "abcabcab"


def test_controller_snapshot_sends_regions(monkeypatch, tmp_path):
    """传 regions 时要把 ``[base,size]`` 数组塞进 msg。"""
    _patch_ctrl_env(monkeypatch, tmp_path)
    c = Controller()
    sent = {}
    monkeypatch.setattr(
        c.server, "request",
        lambda pid, cmd, timeout=0: sent.update({"cmd": cmd}) or
        dict(_fake_snap("snap-2")),
    )
    c.snapshot(pid=100, name="snap-2",
               regions=[{"base": 0x401000, "size": 0x1000}])
    assert sent["cmd"]["regions"] == [{"base": 0x401000, "size": 0x1000}]


def test_controller_snapshot_rejects_missing_name(monkeypatch, tmp_path):
    _patch_ctrl_env(monkeypatch, tmp_path)
    c = Controller()
    out = c.snapshot(pid=100, name="")
    assert out["ok"] is False
    assert "name" in out["error"]


def test_controller_diff_changed_when_two_different_snapshots(monkeypatch, tmp_path):
    _patch_ctrl_env(monkeypatch, tmp_path)
    sent = {}
    mock_snap_a = _fake_snap("before", count=2, sha_seed="aaaa")
    mock_snap_b = _fake_snap("after",  count=2, sha_seed="bbbb")
    monkeypatch.setattr("superinject.snapshots.SnapshotStore.diff",
                        lambda self, pid, a, b: {
                            "a": mock_snap_a, "b": mock_snap_b,
                            "pages_a": mock_snap_a["pages"],
                            "pages_b": mock_snap_b["pages"],
                        })

    mem_diff_resp = {
        "ok": True,
        "changed": [
            {"addr": 0x1000, "old_sha": "aaaaa...", "new_sha": "bbbbb...",
             "old_bytes": "00" * 64, "new_bytes": "ff" * 64},
        ],
        "only_in_a": [],
        "unchanged_count": 1,
    }
    c = Controller()
    monkeypatch.setattr(
        c.server, "request",
        lambda pid, cmd, timeout=0: sent.update({"cmd": cmd}) or dict(mem_diff_resp),
    )
    out = c.diff(pid=100, name1="before", name2="after")
    assert out["ok"] is True
    assert sent["cmd"]["type"] == "mem_diff"
    assert out["unchanged_count"] == 1
    assert out["changed"][0]["addr"] == 0x1000


def test_controller_diff_unchanged_when_same_snapshot(monkeypatch, tmp_path):
    _patch_ctrl_env(monkeypatch, tmp_path)
    same = _fake_snap("only", sha_seed="xxx")
    monkeypatch.setattr("superinject.snapshots.SnapshotStore.diff",
                        lambda self, pid, a, b: {
                            "a": same, "b": same,
                            "pages_a": same["pages"],
                            "pages_b": same["pages"],
                        })
    c = Controller()
    monkeypatch.setattr(
        c.server, "request",
        lambda pid, cmd, timeout=0: {
            "ok": True,
            "changed": [],
            "only_in_a": [],
            "unchanged_count": len(same["pages"]),
        },
    )
    out = c.diff(pid=100, name1="only", name2="only")
    assert out["ok"] is True
    assert out["changed"] == []
    assert out["unchanged_count"] == len(same["pages"])


def test_controller_diff_reports_missing_snapshot(monkeypatch, tmp_path):
    _patch_ctrl_env(monkeypatch, tmp_path)
    from superinject.snapshots import SnapshotStore
    monkeypatch.setattr(
        SnapshotStore, "diff",
        lambda self, pid, a, b: (_ for _ in ()).throw(
            KeyError(f"snapshot not found: pid={pid} name={a}")),
    )
    c = Controller()
    out = c.diff(pid=999, name1="ghost", name2="any")
    assert out["ok"] is False
    assert "ghost" in out["error"]


# ---------------------------------------------- CLI 输出格式


def test_cli_snapshot_subcommand_parses_args(monkeypatch, tmp_path, capsys):
    """``snapshot --pid N --name X`` 正确转给 Controller.snapshot。"""
    from superinject import cli

    captured = {}

    class FakeCtrl:
        def snapshot(self, pid, name, regions=None):
            captured["pid"] = pid
            captured["name"] = name
            captured["regions"] = regions
            return {"ok": True, "kind": "snapshot", "name": name,
                    "count": 7, "bytes": 12345, "sha256": "f" * 64,
                    "path": "/tmp/x.json"}

    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())

    rc = cli.run(["-c", "-y", "--json", "snapshot",
                  "--pid", "100", "--name", "demo",
                  "--region", "0x401000", "0x1000"])
    assert rc == 0
    assert captured["pid"] == 100
    assert captured["name"] == "demo"
    # parse_int 会把 "0x401000" / "0x1000" 转 int
    assert captured["regions"] == [{"base": 0x401000, "size": 0x1000}]
    parsed = json.loads(capsys.readouterr().out)
    assert parsed["name"] == "demo"
    assert parsed["count"] == 7


def test_cli_diff_subcommand_plain_text(monkeypatch, capsys):
    """plain text 模式下输出 [diff] 形式 —— ``_dump_plain`` 对 changed 数组只是
    列前 10 条 + 计数摘要：先确认 CLI 至少把这字段送到了。"""
    from superinject import cli

    class FakeCtrl:
        def diff(self, pid, name1, name2, limit=0):
            return {"ok": True, "kind": "diff",
                    "pid": pid, "a": name1, "b": name2,
                    "changed": [{"addr": 0x401000, "size": 4096,
                                 "old_sha": "aaa", "new_sha": "bbb",
                                 "old_bytes": "00" * 64,
                                 "new_bytes": "ff" * 64}],
                    "only_in_a": [],
                    "unchanged_count": 3}

    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())

    rc = cli.run(["-c", "-y", "diff",
                  "--pid", "100", "--a", "before", "--b", "after", "--limit", "10"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "before" in out and "after" in out


def test_cli_snapshots_lists(monkeypatch, capsys):
    from superinject import cli

    class FakeCtrl:
        def list_snapshots(self, pid):
            return [
                {"name": "a", "created_at": "2026-10-11T00:00:00Z",
                 "bytes": 1000, "sha256": "aaa", "pages": 4},
                {"name": "b", "created_at": "2026-10-11T00:01:00Z",
                 "bytes": 2000, "sha256": "bbb", "pages": 8},
            ]

    monkeypatch.setattr(cli, "_skip_elevation", lambda: True)
    monkeypatch.setattr(cli, "winapi", type("W", (), {"IS_WINDOWS": True}))
    monkeypatch.setattr(cli, "_ensure_controller", lambda dll_path=None: FakeCtrl())

    cli.run(["-c", "-y", "--json", "snapshots", "--pid", "100"])
    data = json.loads(capsys.readouterr().out)
    assert data["kind"] == "snapshots"
    assert [it["name"] for it in data["items"]] == ["a", "b"]
