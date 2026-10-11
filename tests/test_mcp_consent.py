"""MCP 会话授权（consent）层单测 —— 纯 Python，macOS / Windows 都能跑。"""

from __future__ import annotations

import json
import time

import pytest

from superinject import mcp_consent
from superinject.mcp_consent import (
    ConsentError,
    build_session,
    check_capability,
    check_target,
    is_valid,
    load_consent,
    request_consent_cli,
    save_consent,
)

# --------------------------------------------------------------------------- 基本信息


def test_build_session_signs_and_has_expected_fields():
    s = build_session(pids=[1234], names=["notepad*"], capabilities=["read"])
    assert s.pid_allowlist == {1234}
    assert s.name_glob == ["notepad*"]
    assert s.capabilities == {"read"}
    assert s.signature, "构造时必须自动签名"
    assert s.expires_at > s.created_at


def test_capabilities_unknown_tier_is_rejected():
    """未知能力分档必须直接报错，而不是被静默丢掉 —— 静默丢弃会让用户
    以为「我勾了」而实际没授权。"""
    with pytest.raises(ConsentError):
        build_session(capabilities=["read", "write", "bogus"])


def test_targets_summary_readable():
    s = build_session(pids=[1, 2], names=["a*"], capabilities=["read"])
    txt = s.targets_summary()
    assert "1" in txt and "2" in txt and "a*" in txt


# --------------------------------------------------------------------------- 有效期 / 签名


def test_is_valid_true_for_fresh_session():
    s = build_session(pids=[1], capabilities=["read"])
    assert is_valid(s) is True


def test_is_valid_false_when_expired():
    now = time.time()
    s = build_session(pids=[1], capabilities=["read"], ttl=60, now=now)
    assert is_valid(s, now=now + 30) is True
    assert is_valid(s, now=now + 61) is False, "超过 expires_at 必须失效"


def test_is_valid_false_when_signature_tampered():
    s = build_session(pids=[1], capabilities=["read"])
    s.capabilities = {"read", "dangerous"}
    assert is_valid(s) is False, "手改能力分档必须让签名对不上"


def test_is_valid_false_for_none_and_unsigned():
    assert is_valid(None) is False
    unsigned = build_session(pids=[1], capabilities=["read"])
    unsigned.signature = ""
    assert is_valid(unsigned) is False


# --------------------------------------------------------------------------- 目标白名单


def test_check_target_by_pid():
    s = build_session(pids=[1234], capabilities=["read"])
    assert check_target(s, 1234) is True
    assert check_target(s, 5678) is False


def test_check_target_by_name_glob_case_insensitive():
    s = build_session(names=["notepad*", "MyTool.exe"], capabilities=["read"])
    assert check_target(s, 999, "notepad.exe") is True
    assert check_target(s, 999, "NOTEPAD.EXE") is True
    assert check_target(s, 999, "mytool.exe") is True
    assert check_target(s, 999, "calc.exe") is False


def test_check_target_empty_allowlist_denies_everything():
    s = build_session(capabilities=["read"])
    assert check_target(s, 1234, "notepad.exe") is False, "空白名单 = 一律拒绝"


def test_check_target_none_session_denies():
    assert check_target(None, 1234, "anything.exe") is False


# --------------------------------------------------------------------------- 能力分档


def test_check_capability_tiers():
    ro = build_session(capabilities=["read"])
    assert check_capability(ro, "read") is True
    assert check_capability(ro, "write") is False
    assert check_capability(ro, "dangerous") is False

    full = build_session(capabilities=["read", "write", "dangerous"])
    assert check_capability(full, "dangerous") is True

    assert check_capability(None, "read") is False


# --------------------------------------------------------------------------- 落盘往返


def test_save_and_load_roundtrip(tmp_path):
    path = tmp_path / "consent.json"
    s = build_session(pids=[42], names=["x*"], capabilities=["read", "write"])
    save_consent(s, path)
    assert path.exists()

    got = load_consent(path)
    assert got is not None
    assert got.pid_allowlist == {42}
    assert got.name_glob == ["x*"]
    assert got.capabilities == {"read", "write"}
    assert is_valid(got) is True, "往返后签名仍应有效"


def test_load_consent_missing_file_returns_none(tmp_path):
    assert load_consent(tmp_path / "nope.json") is None


def test_load_consent_corrupt_file_returns_none(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{ this is not json", encoding="utf-8")
    assert load_consent(path) is None, "损坏文件不能抛异常"


def test_load_consent_wrong_shape_returns_none(tmp_path):
    path = tmp_path / "shape.json"
    path.write_text(json.dumps({"totally": "different"}), encoding="utf-8")
    assert load_consent(path) is None


def test_consent_path_honours_env_override(tmp_path, monkeypatch):
    target = tmp_path / "custom.json"
    monkeypatch.setenv("SUPERINJECT_CONSENT_PATH", str(target))
    assert mcp_consent.consent_path() == target


# --------------------------------------------------------------------------- CLI 一次性授权


def _cli(text: str):
    import io
    return request_consent_cli(io.StringIO(text))


def test_request_consent_cli_parses_valid_config():
    s = _cli("YES\npids=1234,5678\nnames=notepad*\ncapabilities=read,write\n")
    assert s.pid_allowlist == {1234, 5678}
    assert s.name_glob == ["notepad*"]
    assert s.capabilities == {"read", "write"}
    assert is_valid(s) is True


def test_request_consent_cli_requires_yes_first_line():
    with pytest.raises(ConsentError):
        _cli("yes\ncapabilities=read\n")
    with pytest.raises(ConsentError):
        _cli("OK\ncapabilities=read\n")


def test_request_consent_cli_rejects_empty():
    with pytest.raises(ConsentError):
        _cli("")


def test_request_consent_cli_rejects_unknown_field():
    with pytest.raises(ConsentError):
        _cli("YES\ncapabilities=read\nbogus=1\n")


def test_request_consent_cli_rejects_missing_capabilities():
    with pytest.raises(ConsentError):
        _cli("YES\npids=1\n")


def test_request_consent_cli_rejects_malformed_line():
    with pytest.raises(ConsentError):
        _cli("YES\nthis line has no equals sign\n")


def test_request_consent_cli_accepts_plain_string():
    """stream_in 也可以是裸字符串（便于 --consent-stdin 直接喂文本）。"""
    s = request_consent_cli("YES\npids=7\ncapabilities=read\n")
    assert s.pid_allowlist == {7}
