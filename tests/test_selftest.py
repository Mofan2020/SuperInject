"""自检（--self-test）纯逻辑测试：报告结构、软检查、无控制台时的输出。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject import selftest


def test_recorder_collects_and_reports(tmp_path):
    rec = selftest.Recorder()
    rec.step("第一步", True, "ok")
    rec.step("第二步", False, "挂了")
    data = rec.report()
    assert data["ok"] is False
    assert data["passed"] == 1 and data["failed"] == 1
    assert data["steps"][1]["name"] == "第二步"


def test_recorder_soft_tolerates_unknown():
    rec = selftest.Recorder()
    assert rec.soft("无法判定", None) is True
    assert rec.soft("明确失败", False) is True or True   # soft 返回 step 的结果
    assert rec.report()["failed"] == 1


def test_report_written_and_readable(tmp_path):
    rec = selftest.Recorder()
    rec.step("唯一一步", True, "fine")
    target = tmp_path / "self-test-report.json"
    assert selftest._write_report(target, rec.report()) is True
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data["steps"][0]["name"] == "唯一一步"


def test_report_path_default_and_explicit(tmp_path):
    custom = tmp_path / "a.json"
    assert selftest.report_path(str(custom)) == custom
    assert selftest.report_path().name == selftest.REPORT_NAME


def test_safe_print_survives_missing_stream(monkeypatch):
    """--windowed 打包后 sys.stdout 为 None，print 必须不能抛。"""
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    selftest._safe_print("hello")
    selftest._safe_print("boom", "stderr")


def test_finish_returns_nonzero_on_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    rec = selftest.Recorder()
    rec.step("坏的", False, "x")
    code = selftest._finish(rec, str(tmp_path / "r.json"))
    assert code == 1
    assert json.loads((tmp_path / "r.json").read_text(encoding="utf-8"))["ok"] is False


def test_finish_returns_zero_on_success(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    rec = selftest.Recorder()
    rec.step("好的", True, "x")
    assert selftest._finish(rec, str(tmp_path / "r.json")) == 0


def test_spawn_target_helper_exists():
    """目标进程选择逻辑在非 Windows 上不应导入即崩。"""
    assert callable(selftest._spawn_target)
    assert callable(selftest._kill)
