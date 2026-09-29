"""在真实 Windows 上验证 SYSTEM 提权链路。

只在这里跑（CI 的 windows-latest，且要求管理员）：单元测试里的纯逻辑无法证明
「ctypes 声明对不对、令牌复制能不能成、CreateProcessAsUserW 能不能真的产出一个
SYSTEM 进程」—— 这三件事只有真机跑才知道。

断言的核心是一条**可观测的事实**：子进程自己写下 ``privilege == "system"``
且 SID 是 ``S-1-5-18``。不是「函数返回 True」，而是进程真的以 SYSTEM 起来了。
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

from superinject import elevate, winapi
from superinject import system_token as st

pytestmark = pytest.mark.skipif(not sys.platform.startswith("win"),
                                reason="仅 Windows 可跑真实令牌/进程 API")


@pytest.fixture(scope="module")
def admin_required():
    if not winapi.is_admin():
        pytest.skip("需要管理员权限（CI 的 windows runner 具备）")


def _wait_json(path: Path, timeout: float = 40.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        time.sleep(0.25)
    return {}


def test_enable_debug_privilege(admin_required):
    """SeDebugPrivilege 是打开 SYSTEM 进程令牌的前提。"""
    assert st.enable_privilege("SeDebugPrivilege") is True


def test_session_id_roundtrip(admin_required):
    import os

    assert st.current_session_id() == st.process_session_id(os.getpid())
    assert isinstance(st.current_session_id(), int)


def test_acquire_system_token_real(admin_required):
    """真复制一份 SYSTEM 主令牌，并确认它的 SID 是 LocalSystem。"""
    search = st.acquire_system_token()
    if not search.ok:
        # 极端环境下（比如没有任何 SYSTEM 进程在跑）允许跳过，但必须说明原因
        pytest.skip(f"本机拿不到 SYSTEM 令牌: {search.reason}")
    try:
        assert search.sid == winapi.LOCAL_SYSTEM_SID
        assert search.pid > 0
        assert search.name.lower().endswith(".exe")
    finally:
        st._kernel32().CloseHandle(st.HANDLE_T(search.token))


def test_launch_as_system_creates_real_system_process(admin_required, tmp_path):
    """端到端：用 SYSTEM 令牌拉起自己，子进程汇报的身份必须是 SYSTEM。"""
    probe = tmp_path / "system-probe.json"
    if not st.acquire_system_token().ok:
        pytest.skip("本机拿不到 SYSTEM 令牌，跳过端到端断言")

    res = st.launch_as_system(["--system-probe", str(probe)], wait=True)
    if not res.ok:
        pytest.skip(f"本机不允许以 SYSTEM 创建进程: {res.message}")

    data = _wait_json(probe)
    assert data, (f"子进程（pid={res.pid}, exit={res.exit_code}）没有写出身份文件 "
                  f"{probe}；命令行应为 `python -m superinject --system-probe`")
    assert data["privilege"] == "system", data
    assert data["sid"] == winapi.LOCAL_SYSTEM_SID, data
    assert data["marker"] is True, data      # 环境变量标记要传到子进程
    assert data["pid"] == res.pid


def test_ensure_privilege_uses_system_path_on_windows(monkeypatch):
    """Windows 管理员默认走 SYSTEM 分支（不是只到管理员就完事）。"""
    if winapi.current_privilege() != "admin":
        pytest.skip("当前不是管理员，走的是 UAC 分支")
    monkeypatch.delenv(st.LAUNCH_MARKER_ENV, raising=False)
    assert elevate.decide("admin", [], True, False) == "system"
