"""``superinject.mcp_config_writer`` 单测（v1.3.0 P7）。

覆盖硬约束：合并写入（不是整文件覆盖）、写前备份、原子写、坏 JSON 不动原文件、
内容一致则 unchanged 不备份、dry_run 不落盘。

跨平台做法：``monkeypatch`` 把 ``HOME`` / ``USERPROFILE`` / ``APPDATA`` 指到
``tmp_path`` 下的假目录（Windows 用 ``USERPROFILE``/``APPDATA``，POSIX 用 ``HOME``），
路径断言用 ``Path`` 比较而不是字面字符串（避免 ``/`` 与 ``\\`` 的差异）。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from superinject import mcp_config_writer


@pytest.fixture()
def agent_env(monkeypatch, tmp_path):
    """把 Agent 配置目录指到 tmp_path 下的假 HOME / APPDATA。"""
    home = tmp_path / "home"
    appdata = tmp_path / "appdata"
    home.mkdir()
    appdata.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.delenv("SUPERINJECT_CLAUDE_DIR", raising=False)
    monkeypatch.delenv("SUPERINJECT_CURSOR_DIR", raising=False)
    return {"home": home, "appdata": appdata}


def _target_path(target_id: str) -> Path:
    for t in mcp_config_writer.targets():
        if t["id"] == target_id:
            return Path(t["path"])
    raise AssertionError(f"未知目标 {target_id}")


def _expected_claude(home: Path, appdata: Path) -> Path:
    if os.name == "nt":
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    if sys.platform == "darwin":
        return (Path(home) / "Library" / "Application Support" / "Claude" /
                "claude_desktop_config.json")
    return Path(home) / ".config" / "Claude" / "claude_desktop_config.json"


def _read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _backups(path: Path):
    return sorted(path.parent.glob(path.name + ".bak-*"))


# --------------------------------------------------------------------------- targets()


def test_targets_returns_reasonable_structure(agent_env):
    ts = mcp_config_writer.targets()
    assert isinstance(ts, list)
    ids = {t["id"] for t in ts}
    assert {"claude-desktop", "cursor"} <= ids
    for t in ts:
        assert {"id", "label", "path", "exists"} <= set(t)
        assert isinstance(t["path"], str) and t["path"]
        assert isinstance(t["exists"], bool)
        assert t["exists"] is False, "假环境里配置文件都还不存在"


def test_targets_does_not_create_any_directory(agent_env):
    """探测不能凭空建目录（否则「未安装的 Agent」也会被写出一个空目录树）。"""
    ts = mcp_config_writer.targets()
    for t in ts:
        assert not Path(t["path"]).parent.exists(), t


def test_claude_and_cursor_paths_are_platform_appropriate(agent_env):
    home, appdata = agent_env["home"], agent_env["appdata"]
    assert _target_path("claude-desktop") == _expected_claude(home, appdata)
    assert _target_path("cursor") == Path(home) / ".cursor" / "mcp.json"


# --------------------------------------------------------------------------- created


def test_created_when_file_absent(agent_env):
    res = mcp_config_writer.write_config("cursor")
    assert res["ok"] is True, res
    assert res["action"] == "created"
    assert res["backup"] is None
    path = _target_path("cursor")
    assert path.exists()
    data = _read_json(path)
    assert data["mcpServers"]["superinject"] == res["entry"]
    assert res["entry"]["command"], "条目要有 command"
    assert isinstance(res["entry"]["args"], list)


def test_write_creates_parent_dir_for_explicit_target(agent_env):
    """用户明确指定目标时才建目录（Cursor 的 ~/.cursor 一开始不存在）。"""
    path = _target_path("cursor")
    assert not path.parent.exists()
    res = mcp_config_writer.write_config("cursor")
    assert res["ok"] is True, res
    assert path.exists()


# --------------------------------------------------------------------------- merge


def test_merge_preserves_other_keys_and_other_servers(agent_env):
    path = _target_path("claude-desktop")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "theme": "dark",
        "mcpServers": {
            "other-agent": {"command": "other.exe", "args": ["serve"]},
            "superinject": {"command": "OLD", "args": ["old"]},
        },
        "nested": {"keep": [1, 2, 3]},
    }), encoding="utf-8")

    res = mcp_config_writer.write_config("claude-desktop")
    assert res["ok"] is True and res["action"] == "updated", res

    data = _read_json(path)
    assert data["theme"] == "dark", "其他顶层键必须原样保留"
    assert data["nested"] == {"keep": [1, 2, 3]}
    assert data["mcpServers"]["other-agent"] == {"command": "other.exe",
                                                 "args": ["serve"]}, "别人的条目不能被删"
    assert data["mcpServers"]["superinject"] == res["entry"]


# --------------------------------------------------------------------------- unchanged


def test_unchanged_when_identical_and_no_backup(agent_env):
    first = mcp_config_writer.write_config("cursor")
    assert first["action"] == "created"
    before = _target_path("cursor").read_text(encoding="utf-8")

    second = mcp_config_writer.write_config("cursor")
    assert second["ok"] is True
    assert second["action"] == "unchanged", second
    assert second["backup"] is None, "unchanged 不备份"
    assert _backups(_target_path("cursor")) == [], "unchanged 不产生 .bak"
    assert _target_path("cursor").read_text(encoding="utf-8") == before, "unchanged 不写"


# --------------------------------------------------------------------------- updated + backup


def test_updated_creates_backup_matching_original(agent_env):
    path = _target_path("cursor")
    path.parent.mkdir(parents=True, exist_ok=True)
    original = json.dumps({"mcpServers": {"superinject": {"command": "OLD"}}},
                          ensure_ascii=False)
    path.write_text(original, encoding="utf-8")

    res = mcp_config_writer.write_config("cursor")
    assert res["ok"] is True and res["action"] == "updated", res
    assert res["backup"], "更新必须产生备份路径"

    backups = _backups(path)
    assert len(backups) == 1
    assert Path(res["backup"]) == backups[0]
    assert backups[0].read_text(encoding="utf-8") == original, \
        "备份内容必须与原文件逐字一致"
    # 备份名建在原文件旁边，形如 mcp.json.bak-<时间戳>
    assert backups[0].name.startswith(path.name + ".bak-")


# --------------------------------------------------------------------------- 坏 JSON


def test_bad_json_is_refused_and_file_untouched(agent_env):
    path = _target_path("cursor")
    path.parent.mkdir(parents=True, exist_ok=True)
    broken = '{ "mcpServers": { "x": , }  '   # 手改坏
    path.write_text(broken, encoding="utf-8")

    res = mcp_config_writer.write_config("cursor")
    assert res["ok"] is False, res
    assert "JSON" in res["error"]
    assert path.read_text(encoding="utf-8") == broken, "坏 JSON 时原文件不能被改"
    assert _backups(path) == [], "报错路径不该产生备份"


def test_non_object_top_level_is_refused(agent_env):
    path = _target_path("cursor")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("[]", encoding="utf-8")
    res = mcp_config_writer.write_config("cursor")
    assert res["ok"] is False
    assert path.read_text(encoding="utf-8") == "[]"


def test_mcp_servers_not_object_is_refused(agent_env):
    path = _target_path("cursor")
    path.parent.mkdir(parents=True, exist_ok=True)
    weird = json.dumps({"mcpServers": ["oops"]})
    path.write_text(weird, encoding="utf-8")
    res = mcp_config_writer.write_config("cursor")
    assert res["ok"] is False
    assert "mcpServers" in res["error"]
    assert path.read_text(encoding="utf-8") == weird


# --------------------------------------------------------------------------- dry_run


def test_dry_run_reports_but_does_not_write(agent_env):
    path = _target_path("claude-desktop")
    res = mcp_config_writer.write_config("claude-desktop", dry_run=True)
    assert res["ok"] is True
    assert res["action"] == "created"
    assert res["dry_run"] is True
    assert res["backup"] is None
    assert res["entry"]["command"], "dry_run 也要回将要写入的 entry"
    assert not path.exists(), "dry_run 不能落盘"


def test_dry_run_updated_does_not_backup(agent_env):
    path = _target_path("cursor")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"mcpServers": {"superinject": {"command": "OLD"}}}),
                    encoding="utf-8")
    res = mcp_config_writer.write_config("cursor", dry_run=True)
    assert res["action"] == "updated" and res["dry_run"] is True
    assert _backups(path) == [], "dry_run 不能备份"


# --------------------------------------------------------------------------- 原子性


def test_no_temp_files_left_behind(agent_env):
    mcp_config_writer.write_config("cursor")
    mcp_config_writer.write_config("cursor")          # unchanged
    mcp_config_writer.write_config("claude-desktop")  # created
    for target_id in ("cursor", "claude-desktop"):
        path = _target_path(target_id)
        assert list(path.parent.glob(path.name + ".tmp*")) == [], "不能留临时文件"


# --------------------------------------------------------------------------- 参数 / 错误


def test_unknown_target_returns_error(agent_env):
    res = mcp_config_writer.write_config("nope")
    assert res["ok"] is False
    assert "未知目标" in res["error"]


def test_mode_direct_changes_args(agent_env):
    res = mcp_config_writer.write_config("cursor", mode="direct")
    args = [str(a) for a in res["entry"]["args"]]
    assert "mcp" in args and not any("mcp-launcher" in a for a in args), args


def test_launcher_path_is_used(agent_env):
    res = mcp_config_writer.write_config("cursor",
                                         launcher_path="/opt/SuperInject.exe")
    assert res["entry"]["command"] == "/opt/SuperInject.exe"
