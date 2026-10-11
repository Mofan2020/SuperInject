"""GUI 层 MCP 授权接线单测（v1.3.0 P5）。

只测 ``superinject.gui.Api`` 的四个 MCP 方法 —— 不启动 pywebview、不碰 Windows：

* ``submit_consent``：前端授权表单 → 构造签名会话 + 落盘；
* ``mcp_status``：未授权 / 已授权 / 已过期三态；
* ``revoke_consent``：删授权文件；
* ``mcp_config_snippet``：Agent 端配置片段是合法 JSON。

consent 落盘路径用 ``SUPERINJECT_CONSENT_PATH`` 指向 ``tmp_path``，避免污染
用户真实目录。
"""

from __future__ import annotations

import json
import time

import pytest

from superinject import mcp_consent
from superinject.gui import Api


@pytest.fixture()
def api(monkeypatch, tmp_path):
    """构造一个 Api，并把 consent 落盘路径指向 tmp_path。"""
    monkeypatch.setenv("SUPERINJECT_CONSENT_PATH",
                       str(tmp_path / "mcp_consent.json"))
    return Api({"window": None})


def _consent_file(tmp_path):
    return tmp_path / "mcp_consent.json"


# --------------------------------------------------------------------------- submit_consent: 正常路径


def test_submit_consent_persists_valid_session(api, tmp_path):
    res = api.submit_consent({
        "pids": "1234,5678",
        "names": "notepad*",
        "capabilities": ["read", "write"],
        "ttl_seconds": 1800,
    })
    assert res["ok"] is True, res
    assert "1234" in res["summary"] and "notepad*" in res["summary"]
    assert res["expires_at"] > time.time()

    path = _consent_file(tmp_path)
    assert path.exists(), "授权必须真的落盘"

    session = mcp_consent.load_consent(path)
    assert session is not None
    assert session.pid_allowlist == {1234, 5678}
    assert session.name_glob == ["notepad*"]
    assert session.capabilities == {"read", "write"}
    assert mcp_consent.is_valid(session) is True, "落盘后签名仍应有效"


def test_submit_consent_name_only_is_allowed(api, tmp_path):
    """只给进程名通配、不给 PID 也应放行（两者是「或」）。"""
    res = api.submit_consent({"pids": "", "names": "mytool.exe",
                              "capabilities": ["read"]})
    assert res["ok"] is True, res
    assert _consent_file(tmp_path).exists()


# --------------------------------------------------------------------------- submit_consent: 非法 payload


def test_submit_consent_rejects_empty_capabilities(api, tmp_path):
    res = api.submit_consent({"pids": "1", "capabilities": []})
    assert res["ok"] is False
    assert res["error"]
    assert not _consent_file(tmp_path).exists(), "非法 payload 不能落盘"


def test_submit_consent_rejects_unknown_capability(api, tmp_path):
    res = api.submit_consent({"pids": "1", "capabilities": ["read", "bogus"]})
    assert res["ok"] is False
    assert not _consent_file(tmp_path).exists()


def test_submit_consent_rejects_empty_targets(api, tmp_path):
    """PID 与进程名都空 = 放行一切目标，必须拒绝。"""
    res = api.submit_consent({"pids": "", "names": "", "capabilities": ["read"]})
    assert res["ok"] is False
    assert "空" in res["error"]
    assert not _consent_file(tmp_path).exists()


def test_submit_consent_rejects_bad_pid(api, tmp_path):
    res = api.submit_consent({"pids": "not-a-pid", "capabilities": ["read"]})
    assert res["ok"] is False
    assert not _consent_file(tmp_path).exists()


def test_submit_consent_rejects_non_dict(api, tmp_path):
    res = api.submit_consent("这不是对象")
    assert res["ok"] is False
    assert not _consent_file(tmp_path).exists()


# --------------------------------------------------------------------------- mcp_status 三态


def test_mcp_status_none_when_no_file(api, tmp_path):
    st = api.mcp_status()
    assert st["consent"]["state"] == "none"
    assert st["consent"]["valid"] is False
    assert st["server"]["running"] is False
    assert st["server"]["transport"] == "stdio"


def test_mcp_status_valid_after_submit(api, tmp_path):
    api.submit_consent({"pids": "42", "capabilities": ["read", "write"]})
    st = api.mcp_status()
    assert st["consent"]["state"] == "valid"
    assert st["consent"]["valid"] is True
    assert st["consent"]["capabilities"] == ["read", "write"]
    assert st["consent"]["pid_allowlist"] == [42]
    assert st["consent"]["expires_at"] > time.time()


def test_mcp_status_expired_for_stale_session(api, tmp_path):
    past = time.time() - 3600
    session = mcp_consent.build_session(pids=[7], capabilities=["read"],
                                        ttl=1800, now=past)
    mcp_consent.save_consent(session, _consent_file(tmp_path))
    st = api.mcp_status()
    assert st["consent"]["state"] == "expired"
    assert st["consent"]["valid"] is False
    assert "7" in st["consent"]["summary"], "过期也要能显示上一份白名单"


# --------------------------------------------------------------------------- revoke_consent


def test_revoke_consent_removes_file_and_status_becomes_none(api, tmp_path):
    api.submit_consent({"pids": "9", "capabilities": ["read"]})
    assert _consent_file(tmp_path).exists()

    res = api.revoke_consent()
    assert res["ok"] is True
    assert res["removed"] is True
    assert not _consent_file(tmp_path).exists()

    assert api.mcp_status()["consent"]["state"] == "none"


def test_revoke_consent_when_absent_is_ok(api, tmp_path):
    res = api.revoke_consent()
    assert res["ok"] is True
    assert res["removed"] is False


# --------------------------------------------------------------------------- mcp_config_snippet


def test_mcp_config_snippet_is_valid_json(api):
    text = api.mcp_config_snippet()
    assert isinstance(text, str)
    data = json.loads(text)
    assert "mcpServers" in data
    assert "superinject" in data["mcpServers"]
    entry = data["mcpServers"]["superinject"]
    assert entry["command"]
    assert isinstance(entry["args"], list)
