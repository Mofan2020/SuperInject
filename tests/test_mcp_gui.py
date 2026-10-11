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
    assert st["server"]["transport"] == "pipe"


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


# --------------------------------------------------------------------------- MCP 命名管道服务（v1.3.0 P6）


def test_start_mcp_service_requires_valid_consent(api):
    """无有效授权时不允许起命名管道服务。"""
    res = api.start_mcp_service()
    assert res["ok"] is False, res
    assert "授权" in res["error"]
    assert api.mcp_status()["server"]["running"] is False


def test_start_and_stop_mcp_service_socket_backend(api):
    """有授权 → 用 SocketPipeBackend 起服务，running 变 True；停止后回 False。

    用 socket 后端注入，避免在非 Windows 上真起 Win32 命名管道。
    """
    from superinject.mcp_pipe import SocketPipeBackend

    api.submit_consent({"pids": "1234", "capabilities": ["read"]})
    res = api.start_mcp_service(backend=SocketPipeBackend())
    assert res["ok"] is True, res
    assert res["running"] is True
    assert res["pipe"]
    try:
        st = api.mcp_status()
        assert st["server"]["running"] is True, "mcp_status 必须反映真实运行状态"
        assert st["server"]["transport"] == "pipe"
        assert st["server"]["pipe"] == res["pipe"]
    finally:
        stop = api.stop_mcp_service()
    assert stop["ok"] is True
    assert stop["stopped"] is True
    assert api.mcp_status()["server"]["running"] is False


def test_stop_mcp_service_when_not_running_is_ok(api):
    res = api.stop_mcp_service()
    assert res["ok"] is True
    assert res["stopped"] is False
    assert res["running"] is False


def test_mcp_config_snippet_defaults_to_launcher(api):
    """默认输出无 UAC 的 mcp-launcher 配置；mode=direct 才是直连版。"""
    launcher = json.loads(api.mcp_config_snippet())["mcpServers"]["superinject"]
    assert any("mcp-launcher" in str(a) for a in launcher["args"]), launcher
    direct = json.loads(
        api.mcp_config_snippet(mode="direct"))["mcpServers"]["superinject"]
    assert any(str(a) == "mcp" for a in direct["args"]), direct
    assert not any("mcp-launcher" in str(a) for a in direct["args"])
