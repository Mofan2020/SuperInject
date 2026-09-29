"""SYSTEM 提权模块的跨平台测试。

这里锁死两类东西：

1. **结构体 ABI**：``STARTUPINFOW``/``PROCESS_INFORMATION`` 等必须与 Windows
   x64 的布局完全一致。用定宽类型（c_uint32 而非 DWORD）后这些断言在 macOS 上
   也能跑 —— 之前用 ``ctypes.wintypes.DWORD``（= c_ulong）时，本机算出来是
   Windows 的两倍大小，布局错误只有在 Windows 上才暴露。
2. **策略**：候选进程排序、环境块、重启命令行、以及 ``elevate.decide`` 的
   决策表（提权失败要降级而不是把程序打死）。
"""

from __future__ import annotations

import ctypes
import os

import pytest

from superinject import elevate
from superinject import system_token as st

# ---------------------------------------------------------------- 结构体 ABI


def test_startupinfo_layout_matches_win64():
    assert ctypes.sizeof(st.STARTUPINFOW) == 104
    assert st.STARTUPINFOW.cb.offset == 0
    assert st.STARTUPINFOW.lpDesktop.offset == 16
    # lpReserved2 必须按 8 字节对齐（Windows 上正是靠这条 padding 才对得上）
    assert st.STARTUPINFOW.lpReserved2.offset == 72
    assert st.STARTUPINFOW.hStdInput.offset == 80


def test_other_struct_sizes():
    assert ctypes.sizeof(st.PROCESS_INFORMATION) == 24
    assert ctypes.sizeof(st.LUID) == 8
    assert ctypes.sizeof(st.TOKEN_PRIVILEGES) == 16


def test_struct_field_types_are_fixed_width():
    """不许用 c_ulong 之类的平台相关类型（Windows 4 字节 / 本机 8 字节）。"""
    assert ctypes.sizeof(st.DWORD32) == 4
    assert ctypes.sizeof(st.LONG32) == 4
    assert ctypes.sizeof(st.WORD16) == 2
    assert ctypes.sizeof(st.HANDLE_T) == ctypes.sizeof(ctypes.c_void_p)


# ---------------------------------------------------------------- 候选排序


PROCS = [
    {"pid": 400, "name": "explorer.exe", "session": 1},
    {"pid": 40, "name": "winlogon.exe", "session": 1},
    {"pid": 41, "name": "winlogon.exe", "session": 0},
    {"pid": 42, "name": "services.exe", "session": 1},
    {"pid": 43, "name": "csrss.exe", "session": 1},
]


def test_same_session_first_then_preferred_order():
    got = [(p["name"], p["pid"]) for p in st.ordered_candidates(PROCS, session=1)]
    # explorer 不在优先名单里 → 垫底；winlogon 排在 services 前面
    assert got == [("winlogon.exe", 40), ("services.exe", 42),
                   ("csrss.exe", 43), ("explorer.exe", 400), ("winlogon.exe", 41)]


def test_cross_session_candidates_last():
    got = [p["pid"] for p in st.ordered_candidates(PROCS, session=0)]
    assert got[0] == 41                    # 本会话的 SYSTEM 进程优先
    assert got.index(41) < got.index(40)   # 跨会话的那个被排到本会话之后


def test_newer_pid_wins_within_same_rank():
    procs = [{"pid": 10, "name": "svchost.exe", "session": 1},
             {"pid": 90, "name": "svchost.exe", "session": 1}]
    assert [p["pid"] for p in st.ordered_candidates(procs, session=1)] == [90, 10]


def test_ordering_does_not_mutate_input():
    procs = [dict(p) for p in PROCS]
    st.ordered_candidates(procs, session=1)
    assert procs == PROCS


def test_preferred_names_are_system_processes():
    """候选名单只能放系统进程，绝不能拿用户进程当令牌来源。"""
    from superinject import winapi

    assert set(st.PREFERRED_NAMES) <= set(winapi.CRITICAL_PROCESSES)
    assert st.PREFERRED_NAMES[0] == "winlogon.exe"   # 未受 PPL 保护，首选


# ---------------------------------------------------------------- 环境块


def test_environment_block_format():
    """必须是 Windows 要的 ``k=v\\0k=v\\0\\0`` 形状（ctypes 会再补一个结尾 NUL）。"""
    block = st.build_environment_block({"B": "2", "A": "1"})[:]
    assert block == "A=1\0B=2\0\0\0"
    assert block.endswith("\0\0")            # 双 NUL 结尾是这个格式的硬要求
    # 空环境也不能变成「完全没有 NUL」的非法块
    assert st.build_environment_block({})[:] == "\0\0\0"


def test_child_environment_keeps_temp_and_marks_child(monkeypatch):
    monkeypatch.setenv("TEMP", r"C:\Users\dev\AppData\Local\Temp")
    env = st.child_environment({"EXTRA": 5})
    # TEMP 必须原样继承：控制器与注入端靠 %TEMP%\SuperInject\port-<PID>.txt 会合
    assert env["TEMP"] == r"C:\Users\dev\AppData\Local\Temp"
    assert env[st.LAUNCH_MARKER_ENV] == "1"
    assert env["EXTRA"] == "5"


def test_launch_marker_reads_env(monkeypatch):
    monkeypatch.delenv(st.LAUNCH_MARKER_ENV, raising=False)
    assert st.is_launched_child() is False
    monkeypatch.setenv(st.LAUNCH_MARKER_ENV, "1")
    assert st.is_launched_child() is True


def test_relaunch_argv_frozen(monkeypatch):
    monkeypatch.setattr(st.sys, "executable", r"C:\Tools\SuperInject.exe")
    monkeypatch.setattr(st.sys, "frozen", True, raising=False)
    exe, cmd = st.relaunch_argv(["--as-admin"])
    assert exe == r"C:\Tools\SuperInject.exe"
    assert cmd == r"C:\Tools\SuperInject.exe --as-admin"


def test_relaunch_argv_source_uses_module_entry(monkeypatch):
    """源码运行必须用 `python -m superinject`，而不是 sys.argv[0]。

    从 pytest / `python -c` 里被拉起时 sys.argv[0] 是**别人的**入口：
    CI 上真的重启出了一个 pytest 进程，探针参数成了未知选项，
    于是「提权成功了但什么都没发生」。这条测试锁死该回归。
    """
    monkeypatch.setattr(st.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(st.sys, "frozen", False, raising=False)
    monkeypatch.setattr(st.sys, "argv", ["/repo/tests/pytest_main.py"])
    exe, cmd = st.relaunch_argv(["--system-probe", "/tmp/p.json"])
    assert exe == "/usr/bin/python3"
    assert cmd == "/usr/bin/python3 -m superinject --system-probe /tmp/p.json"
    assert "pytest" not in cmd


def test_relaunch_argv_quotes_paths_with_spaces(monkeypatch):
    monkeypatch.setattr(st.sys, "executable",
                        r"C:\Program Files\Python\python.exe")
    monkeypatch.setattr(st.sys, "frozen", False, raising=False)
    _exe, cmd = st.relaunch_argv(["--system-probe", r"C:\tmp dir\p.json"])
    assert cmd.startswith(r'"C:\Program Files\Python\python.exe" -m superinject')
    assert cmd.endswith(r'"C:\tmp dir\p.json"')


def test_child_environment_sets_pythonpath_for_source_runs(monkeypatch):
    """源码运行时子进程要靠 PYTHONPATH 才能 import superinject。"""
    from pathlib import Path

    monkeypatch.setattr(st.sys, "frozen", False, raising=False)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    root = str(Path(st.__file__).resolve().parent.parent)
    env = st.child_environment()
    assert env["PYTHONPATH"] == root
    monkeypatch.setenv("PYTHONPATH", "/existing")
    env2 = st.child_environment()
    assert env2["PYTHONPATH"] == root + os.pathsep + "/existing"


def test_child_environment_skips_pythonpath_when_frozen(monkeypatch):
    monkeypatch.setattr(st.sys, "frozen", True, raising=False)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    assert "PYTHONPATH" not in st.child_environment()


# ---------------------------------------------------------------- 决策表


@pytest.mark.parametrize("priv,argv,expected", [
    ("system", [], "pass"),
    ("admin", [], "system"),
    ("admin", ["--as-admin"], "admin"),
    ("admin", ["--no-system"], "admin"),
    ("user", [], "uac"),
    ("admin", ["--self-test"], "system"),
])
def test_decide_table(priv, argv, expected):
    assert elevate.decide(priv, argv, want_system=True) == expected


def test_decide_does_not_loop_after_system_relaunch():
    """已经以 SYSTEM 拉起过一次却仍是管理员 → 不再反复重启。"""
    assert elevate.decide("admin", [], True, already_relaunched=True) == "admin"


def test_system_requested_default_on():
    assert elevate.system_requested([]) is True
    assert elevate.system_requested(["--as-admin"]) is False


# ---------------------------------------------------------------- 自检1 流程


def _patch_priv(monkeypatch, priv):
    monkeypatch.setattr(elevate, "current_privilege", lambda: priv)
    monkeypatch.setattr(elevate, "current_identity", lambda: "tester / x")


def test_ensure_privilege_passes_when_already_system(monkeypatch):
    _patch_priv(monkeypatch, "system")
    res = elevate.ensure_privilege([], auto_relaunch=False)
    assert res.ok and res.system and not res.relaunched and not res.degraded


def test_ensure_privilege_launches_system(monkeypatch):
    _patch_priv(monkeypatch, "admin")
    monkeypatch.setattr(elevate.sys, "platform", "win32")
    launched = {}

    def fake_launch(argv, timeout=30.0):
        launched["argv"] = argv
        return st.LaunchResult(True, "ok", "CreateProcessAsUserW", 4321, "S-1-5-18",
                               40, "winlogon.exe")

    monkeypatch.setattr(st, "launch_as_system", fake_launch)
    res = elevate.ensure_privilege(["--as-system"], auto_relaunch=False)
    assert res.ok and res.system and res.relaunched
    assert launched["argv"] == ["--as-system"]
    assert "winlogon.exe" in res.message


def test_ensure_privilege_degrades_when_system_launch_fails(monkeypatch):
    """SYSTEM 拿不到时必须降级为管理员继续跑，而不是把程序打死。"""
    _patch_priv(monkeypatch, "admin")
    monkeypatch.setattr(elevate.sys, "platform", "win32")
    monkeypatch.setattr(st, "launch_as_system", lambda argv, timeout=30.0:
                        st.LaunchResult(False, "没有可用的 SYSTEM 令牌"))
    res = elevate.ensure_privilege([], auto_relaunch=False)
    assert res.ok and not res.system and res.degraded
    assert "SYSTEM" in res.reason or "令牌" in res.reason
    assert res.to_dict()["degraded"] is True


def test_ensure_privilege_skips_system_with_flag(monkeypatch):
    _patch_priv(monkeypatch, "admin")
    res = elevate.ensure_privilege(["--as-admin"], auto_relaunch=False)
    assert res.ok and not res.degraded
    assert res.system is False


def test_ensure_privilege_needs_uac_for_plain_user(monkeypatch):
    _patch_priv(monkeypatch, "user")
    res = elevate.ensure_privilege([], auto_relaunch=False)
    assert not res.ok              # 不自动重启时必须明确失败
    assert "管理员" in res.message


def test_ensure_privilege_user_never_reported_as_ok(monkeypatch):
    """带着 SYSTEM 标记但仍是普通用户时不许当成通过。"""
    _patch_priv(monkeypatch, "user")
    monkeypatch.setenv(st.LAUNCH_MARKER_ENV, "1")
    res = elevate.ensure_privilege([], auto_relaunch=False)
    assert not res.ok


# ---------------------------------------------------------------- 非 Windows 兜底


def test_acquire_token_is_non_throwing_off_windows():
    """非 Windows 上必须给出原因而不是抛异常（自检/单测都会走到）。"""
    if os.name == "nt":
        pytest.skip("Windows 上走真实 API")
    res = st.acquire_system_token()
    assert not res.ok
    assert res.reason


def test_launch_off_windows_reports_reason():
    if os.name == "nt":
        pytest.skip("Windows 上走真实 API")
    res = st.launch_as_system(["--system-probe", "/tmp/none.json"])
    assert not res.ok and "Windows" in res.message


# ---------------------------------------------------------------- 窗口尺寸


def test_window_size_never_exceeds_screen():
    from superinject import gui

    # 小屏：窗口必须缩到屏幕以内，否则底部功能区永远看不到
    assert gui.window_size((1024, 600)) == (942, 552)
    assert gui.window_size((1366, 768)) == (1256, 706)
    # 大屏：用默认尺寸，不无限放大
    assert gui.window_size((3840, 2160)) == gui.DEFAULT_WINDOW
    # 拿不到屏幕信息时也要有合理默认
    assert gui.window_size(None) == gui.DEFAULT_WINDOW
    assert gui.window_size((0, 0)) == gui.DEFAULT_WINDOW


def test_min_window_fits_in_small_screen():
    from superinject import gui

    w, h = gui.window_size((1024, 600))
    assert w >= gui.MIN_WINDOW[0] and h >= gui.MIN_WINDOW[1]
    assert gui.MIN_WINDOW[0] <= 1024 and gui.MIN_WINDOW[1] <= 600


def test_start_kwargs_only_uses_supported_arguments():
    """webview.start 的参数要按版本能力裁剪，不能硬塞导致 TypeError。"""
    pytest.importorskip("webview")
    from superinject import gui

    kwargs = gui.start_kwargs(debug=False)
    assert kwargs["debug"] is False
    if "storage_path" in kwargs:
        assert kwargs["storage_path"].endswith("webview")
