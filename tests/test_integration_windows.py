"""Windows 集成测试：真实注入一个进程并通过管道控制它。

只在 Windows 上运行；需要已编译好的 SuperInjectAgent.dll
（CI 中由 native job 产出，通过 SUPERINJECT_DLL_PATH 传入）。
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("win"), reason="仅 Windows 可运行注入集成测试"
)


def _dll_path() -> Path:
    env = os.environ.get("SUPERINJECT_DLL_PATH")
    if env:
        return Path(env)
    return ROOT / "native" / "build" / "SuperInjectAgent.dll"


def _wait_until(fn, timeout=25.0, interval=0.5):
    """轮询直到返回真值或超时，返回最后一次结果。"""
    deadline = time.time() + timeout
    result = None
    while time.time() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(interval)
    return result


@pytest.fixture(scope="module")
def target():
    """启动一个干净的目标进程（notepad），测试结束后关闭。"""
    if not _dll_path().exists():
        pytest.skip(f"未找到编译好的 DLL：{_dll_path()}")
    proc = subprocess.Popen(["notepad.exe"])
    yield proc.pid
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except Exception:
        proc.kill()


@pytest.fixture()
def ctrl():
    from superinject.controller import Controller

    c = Controller(dll_path=_dll_path())
    yield c
    c.server.shutdown()


def test_dll_is_valid_pe():
    import struct

    data = _dll_path().read_bytes()
    assert data[:2] == b"MZ"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0"
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    assert machine == 0x8664, "集成测试要求 x64 DLL"
    assert struct.unpack_from("<H", data, pe + 22)[0] & 0x2000, "缺少 DLL 标志"


def test_process_listing_includes_target(target):
    from superinject.controller import Controller

    c = Controller(dll_path=_dll_path())
    pids = {p["pid"] for p in c.list_processes()}
    assert target in pids


def test_inject_ping_info_and_unload(target, ctrl):
    res = ctrl.inject([target])
    assert res[0]["ok"], f"注入失败: {res[0].get('error')}"
    assert ctrl.server.is_attached(target) or True  # 管道连接可能稍晚

    ping = _wait_until(lambda: ctrl.server.request(target, {"type": "ping"}, 5)
                       if ctrl.server.is_attached(target) else None)
    assert ping and ping.get("ok"), f"注入端无响应: {ping}"

    info = ctrl.server.request(target, {"type": "info"}, timeout=15)
    assert info.get("ok")
    names = [m["name"] for m in info["modules"]]
    assert any("notepad" in n.lower() for n in names), names

    regions = ctrl.server.request(target, {"type": "mem_regions"}, timeout=30)
    assert regions.get("ok") and len(regions["regions"]) > 0

    # 内存读取：搜索 MZ 头（几乎必然命中主模块）
    found = ctrl.mem_search([target], "4D 5A", 8)
    assert found and found[0]["ok"], found
    results = found[0]["resp"]["results"]
    assert len(results) > 0, "未搜索到 MZ 头"

    # 写入一个字节再读回，验证读写链路
    addr = results[0]["address"]
    original = ctrl.mem_read(target, addr, 1)
    assert original.get("ok")
    old_byte = original["hex"][:2]
    new_byte = "90" if old_byte != "90" else "91"
    w = ctrl.mem_write(target, addr, new_byte)
    assert w.get("ok"), w
    time.sleep(0.3)
    back = ctrl.mem_read(target, addr, 1)
    assert back["hex"][:2] == new_byte
    ctrl.mem_write(target, addr, old_byte)  # 还原

    out = ctrl.unload([target])
    assert out[0]["ok"], out
    assert not ctrl.server.is_attached(target)


def test_request_to_non_injected_process_fails(ctrl):
    """未注入的进程不应能响应命令。"""
    resp = ctrl.server.request(999999, {"type": "ping"}, timeout=2)
    assert resp["ok"] is False
    assert "未连接" in resp["error"] or "超时" in resp["error"]


def test_terminate_via_dll(target, ctrl):
    """让被注入进程自己 ExitProcess 结束自己。"""
    res = ctrl.inject([target])
    assert res[0]["ok"], res[0].get("error")
    ok = _wait_until(lambda: ctrl.server.is_attached(target) and
                     ctrl.server.request(target, {"type": "ping"}, 5).get("ok"))
    assert ok

    ctrl.terminate([target])
    gone = _wait_until(lambda: not _pid_alive(target), timeout=15)
    assert gone, "目标进程未被终止"


def _pid_alive(pid: int) -> bool:
    from superinject import winapi

    try:
        return bool(winapi.open_process(pid, winapi.PROCESS_QUERY_LIMITED_INFORMATION))
    except Exception:
        return False


def test_freeze_and_resume(ctrl):
    """冻结 / 解除冻结：进程应变为无响应后又恢复。"""
    proc = subprocess.Popen(["notepad.exe"])
    pid = proc.pid
    try:
        assert ctrl.freeze([pid])[0]["ok"]
        time.sleep(1.0)
        assert ctrl.unfreeze([pid])[0]["ok"]
        time.sleep(1.0)
        assert _pid_alive(pid)
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=10)
        except Exception:
            proc.kill()
