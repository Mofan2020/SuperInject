"""DLL 自校验（自检2）与更新检查逻辑测试。"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject import dll_manager, updater

# ------------------------------------------------------------- SHA 自校验

def test_sha256_helpers(tmp_path):
    p = tmp_path / "a.dll"
    p.write_bytes(b"hello-superinject")
    assert dll_manager.sha256_bytes(b"hello-superinject") == \
        dll_manager.sha256_file(p)
    assert len(dll_manager.sha256_bytes(b"x")) == 64


def test_verify_reports_missing_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(dll_manager, "embedded_bytes", lambda: None)
    monkeypatch.setattr(dll_manager, "_dev_build_dll", lambda: None)
    rep = dll_manager.verify_and_sync(tmp_path / "missing.dll")
    assert rep.ok is False
    assert rep.action == "failed"


def test_verify_creates_when_absent(tmp_path, monkeypatch):
    payload = b"MZ-fake-dll-bytes"
    monkeypatch.setattr(dll_manager, "embedded_bytes", lambda: payload)
    target = tmp_path / "SuperInjectAgent.dll"
    rep = dll_manager.verify_and_sync(target)
    assert rep.ok and rep.action == "created"
    assert target.read_bytes() == payload
    assert rep.embedded_sha == dll_manager.sha256_bytes(payload)


def test_verify_detects_mismatch_and_replaces(tmp_path, monkeypatch):
    payload = b"MZ-good-dll"
    monkeypatch.setattr(dll_manager, "embedded_bytes", lambda: payload)
    target = tmp_path / "SuperInjectAgent.dll"
    target.write_bytes(b"MZ-tampered")
    rep = dll_manager.verify_and_sync(target)
    assert rep.ok and rep.action == "replaced"
    assert "不一致" in rep.message
    assert target.read_bytes() == payload
    assert rep.disk_sha == dll_manager.sha256_bytes(payload)


def test_verify_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(dll_manager, "embedded_bytes", lambda: b"same")
    target = tmp_path / "SuperInjectAgent.dll"
    dll_manager.verify_and_sync(target)
    rep = dll_manager.verify_and_sync(target)
    assert rep.ok and rep.action == "ok"


def test_verify_force_rewrites(tmp_path, monkeypatch):
    monkeypatch.setattr(dll_manager, "embedded_bytes", lambda: b"v2")
    target = tmp_path / "SuperInjectAgent.dll"
    target.write_bytes(b"v1")
    rep = dll_manager.verify_and_sync(target, force=True)
    assert rep.ok and rep.action == "replaced"
    assert target.read_bytes() == b"v2"


def test_locked_file_falls_back_to_rename(tmp_path, monkeypatch):
    """模拟目标文件被占用无法直接覆盖的情况。"""
    monkeypatch.setattr(dll_manager, "embedded_bytes", lambda: b"fresh")
    target = tmp_path / "SuperInjectAgent.dll"
    target.write_bytes(b"stale")

    real_replace = dll_manager.os.replace

    def flaky_replace(src, dst):
        if str(dst).endswith(".dll"):
            raise PermissionError("being used")
        return real_replace(src, dst)

    monkeypatch.setattr(dll_manager.os, "replace", flaky_replace)
    rep = dll_manager.verify_and_sync(target)
    assert rep.ok and rep.action == "replaced"
    assert target.read_bytes() == b"fresh"


def test_no_hardcoded_sha_in_sources():
    """源码里不允许出现手写 SHA 常量——必须运行时计算。"""
    root = Path(__file__).resolve().parent.parent
    forbidden = ("sha256 = \"", "SHA256 = \"", "expected_sha")
    for f in (root / "superinject").rglob("*.py"):
        text = f.read_text(encoding="utf-8")
        for token in forbidden:
            assert token not in text, f"{f.name} 中出现了手写哈希常量: {token}"


# ------------------------------------------------------------- 更新检查

def _release_payload(tag="v9.9.9", assets=None):
    return {
        "tag_name": tag,
        "html_url": "https://example/releases",
        "body": "notes",
        "draft": False,
        "prerelease": False,
        "published_at": "2026-09-28T00:00:00Z",
        "assets": assets or [
            {"name": "SuperInject-win-x64.zip",
             "browser_download_url": "https://example/a.zip"},
        ],
    }


class FakeResponse:
    """模拟 urllib 的上下文管理返回对象。"""

    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self._payload


def test_release_info_detects_newer():
    rel = updater.ReleaseInfo(version="99.0.0", url="u",
                               assets=_release_payload()["assets"])
    assert rel.has_newer is True
    old = updater.ReleaseInfo(version="0.0.1", url="u", assets=[])
    assert old.has_newer is False


def test_windows_asset_pick():
    assets = [
        {"name": "SuperInject-linux.zip",
         "browser_download_url": "https://example/l.zip"},
        {"name": "SuperInject-win-x64.zip",
         "browser_download_url": "https://example/w.zip"},
    ]
    rel = updater.ReleaseInfo(version="2.0.0", url="u", assets=assets)
    assert rel.windows_asset()["browser_download_url"].endswith("w.zip")


def test_fetch_latest_prefers_release_list(monkeypatch):
    """先走 Release 列表接口（预发布版本也能看到）。"""
    captured = {}
    payload = [
        _release_payload(tag="v1.0.1", assets=[]),
        _release_payload(tag="v1.0.0"),
    ]
    payload[0]["published_at"] = "2026-09-28T00:00:00Z"
    payload[1]["published_at"] = "2026-09-01T00:00:00Z"

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return FakeResponse(json.dumps(payload).encode())

    monkeypatch.setattr(updater.urllib.request, "urlopen", fake_urlopen)
    rel = updater.fetch_latest()
    assert captured["url"] == updater.GITHUB_RELEASES_API
    assert rel.version == "1.0.1"


def test_fetch_latest_skips_drafts_and_uses_prerelease(monkeypatch):
    """只有预发布版本时也要能发现更新（/releases/latest 这时会 404）。"""
    payload = [
        {"tag_name": "v9.9.9", "draft": True, "assets": []},
        {"tag_name": "v1.2.0", "prerelease": True, "assets": [],
         "published_at": "2026-09-27T00:00:00Z"},
    ]
    monkeypatch.setattr(updater.urllib.request, "urlopen",
                        lambda req, timeout=None: FakeResponse(json.dumps(payload).encode()))
    rel = updater.fetch_latest()
    assert rel.version == "1.2.0" and rel.prerelease is True and rel.has_newer


def test_fetch_latest_missing_tag_is_skipped(monkeypatch):
    payload = [{"draft": False, "assets": []},
               _release_payload(tag="v3.0.0")]
    monkeypatch.setattr(updater.urllib.request, "urlopen",
                        lambda req, timeout=None: FakeResponse(json.dumps(payload).encode()))
    assert updater.fetch_latest().version == "3.0.0"


def test_fetch_latest_falls_back_to_latest_endpoint(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        if req.full_url == updater.GITHUB_RELEASES_API:
            raise OSError("list down")
        return FakeResponse(json.dumps(_release_payload()).encode())

    monkeypatch.setattr(updater.urllib.request, "urlopen", fake_urlopen)
    rel = updater.fetch_latest()
    assert calls == [updater.GITHUB_RELEASES_API, updater.GITHUB_API]
    assert rel.version == "9.9.9"


def test_fetch_latest_swallows_errors(monkeypatch):
    def boom(req, timeout=None):
        raise OSError("network down")

    monkeypatch.setattr(updater.urllib.request, "urlopen", boom)
    assert updater.fetch_latest() is None


def test_stage_update_extracts_flat_zip(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "SuperInject.exe").write_bytes(b"MZ")
    zip_path = tmp_path / "u.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.write(src / "SuperInject.exe", "SuperInject.exe")
    out = updater.stage_update(zip_path)
    assert (out / "SuperInject.exe").exists()
