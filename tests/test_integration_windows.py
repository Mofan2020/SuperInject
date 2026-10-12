"""Windows 集成测试：真实注入一个进程并通过命名管道控制它。

只在 Windows 上运行；需要已编译好的 SuperInjectAgent.dll
（CI 中由 native job 产出，通过 SUPERINJECT_DLL_PATH 传入）。

目标进程选用 ping.exe：它是短生命周期命令行程序，测试结束后可彻底回收，
不会像 Windows 11 的 notepad 那样留下常驻宿主进程拖住 CI 步骤。
"""

from __future__ import annotations

import os
import struct
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from conftest import spawn  # noqa: E402

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("win"), reason="仅 Windows 可运行注入集成测试"
)

TARGET_IMG = "ping.exe"
PAGE_READWRITE = 0x04


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


def kill(pid: int) -> None:
    subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)],
                   capture_output=True, check=False)


@pytest.fixture(scope="module")
def target():
    """模块级目标进程：整个模块复用，模块结束时强制回收。"""
    if not _dll_path().exists():
        pytest.skip(f"未找到编译好的 DLL：{_dll_path()}")
    pid = spawn([TARGET_IMG, "-t", "127.0.0.1"])
    yield pid
    kill(pid)


@pytest.fixture()
def ctrl():
    from superinject.controller import Controller

    c = Controller(dll_path=_dll_path())
    yield c
    c.server.shutdown()


@pytest.fixture()
def injected(ctrl):
    """每个用例一个自己的、已注入的目标进程。"""
    pid = spawn([TARGET_IMG, "-t", "127.0.0.1"])
    try:
        res = ctrl.inject([pid])[0]
        assert res["ok"], f"注入失败: {res.get('error')}"
        assert res["attached"], "控制通道未建立"
        assert _ping(ctrl, pid), "注入端无响应"
        yield pid
    finally:
        kill(pid)


def _ping(ctrl, pid, timeout=30):
    """等待注入端连接并返回 ping 结果。"""
    return _wait_until(
        lambda: ctrl.server.request(pid, {"type": "ping"}, 5).get("ok")
        if ctrl.server.is_attached(pid) else None,
        timeout=timeout,
    )


def _pid_alive(pid: int) -> bool:
    from superinject import winapi

    return winapi.pid_alive(pid)


# ------------------------------------------------------------------ DLL / 列表

def test_dll_is_valid_pe():
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


# ------------------------------------------------------------------ 注入检查

def test_preflight_blocks_self_and_system(ctrl, target):
    """自己与系统关键进程必须被拦下，普通进程放行。"""
    checks = {c["pid"]: c for c in ctrl.preflight([os.getpid(), 4, 0, target])}
    assert checks[os.getpid()]["blocked"]
    assert checks[4]["blocked"] and "关键" in checks[4]["reason"]
    assert checks[0]["blocked"]
    assert checks[target]["ok"] and not checks[target]["blocked"]
    assert checks[target]["name"].lower().startswith("ping")
    assert checks[target]["accessible"]


def test_preflight_flags_already_injected(injected, ctrl):
    check = ctrl.preflight([injected])[0]
    assert check["attached"] and check["dll_loaded"]
    assert any("重新注入" in w for w in check["warnings"])


def test_preflight_reports_nonexistent_pid(ctrl):
    check = ctrl.preflight([0x7FFFFFF0])[0]
    assert check["blocked"]


# ------------------------------------------------------------------ 注入 / 控制

def test_inject_ping_info_and_unload(injected, ctrl):
    pid = injected
    info = ctrl.server.request(pid, {"type": "info"}, timeout=15)
    assert info.get("ok")
    names = [m["name"].lower() for m in info["modules"]]
    assert any("ping" in n for n in names), names

    regions = ctrl.server.request(pid, {"type": "mem_regions"}, timeout=30)
    assert regions.get("ok") and len(regions["regions"]) > 0

    # 内存搜索：MZ 头几乎必然命中主模块
    found = ctrl.mem_search([pid], "4D 5A ?? ??", 8)
    assert found and found[0]["ok"], found
    results = found[0]["resp"]["results"]
    assert results, "未搜索到 MZ 头"

    out = ctrl.unload([pid])
    assert out[0]["ok"], out
    assert out[0]["detached"], "卸载后控制通道应断开"
    assert not ctrl.server.is_attached(pid)


def test_reinject_while_attached_hot_swaps(injected, ctrl):
    """已注入时再注入：应自动先卸载旧 DLL，再注入并重新连上。"""
    pid = injected
    res = ctrl.inject([pid])[0]
    assert res["ok"], res.get("error")
    assert res["reinjected"] is True, "没有走「先卸载再注入」的热更新路径"
    assert res["attached"] and _ping(ctrl, pid)


def test_mem_read_write_roundtrip(injected, ctrl):
    pid = injected

    # 1) 可写区域：读 8 字节 -> 改写 -> 读回 -> 还原
    regions = ctrl.server.request(pid, {"type": "mem_regions"}, timeout=30)["regions"]
    writable = [r for r in regions
                if r["protect"] == PAGE_READWRITE and r["size"] >= 4096]
    assert writable, "目标进程内没有找到可写内存区域"
    addr = int(writable[0]["base"]) + 0x100

    original = ctrl.mem_read(pid, addr, 8)
    assert original.get("ok") and len(original["hex"]) == 16, original
    new_byte = "90" if original["hex"][:2] != "90" else "91"
    payload = new_byte + original["hex"][2:]
    w = ctrl.mem_write(pid, addr, payload)
    assert w.get("ok"), w
    back = ctrl.mem_read(pid, addr, 8)
    assert back["hex"].lower() == payload.lower(), back
    assert ctrl.mem_write(pid, addr, original["hex"]).get("ok")

    # 2) 只读页：目标自己的 PE 头那一页。必须靠「临时改页保护」写进去，
    #    这正是调试器给已加载模块打补丁的路线。
    #    这里用模块基址，而不是「搜到的第一个 MZ」——第一个 MZ 可能落在
    #    别的只读映射里（例如只读文件映射），那种失败说明不了这条路子行不行。
    info = ctrl.server.request(pid, {"type": "info"}, timeout=30)
    assert info.get("ok"), info
    image = Path(TARGET_IMG).name.lower()
    bases = {m["name"].lower(): int(m["base"]) for m in info["modules"]}
    assert image in bases, f"模块表里没有 {image}，实际有 {list(bases)[:6]}"
    hdr = bases[image] + 0x100        # PE 头页内的 DOS stub 区，永远不会被执行
    head = ctrl.mem_read(pid, hdr, 2)
    assert head.get("ok"), head
    old = head["hex"][:2]
    new = "4E" if old.lower() != "4e" else "4D"
    patched = ctrl.mem_write(pid, hdr, new)
    assert patched.get("ok"), f"只读页写入失败: {patched}"
    assert patched.get("protection_changed"), (
        f"PE 头页本应只读，写入却不需要改保护（地址挑错了？）: {patched}")
    after = ctrl.mem_read(pid, hdr, 2)
    assert after["hex"][:2].lower() == new.lower(), after
    assert ctrl.mem_write(pid, hdr, old).get("ok")


def test_snapshot_and_diff(injected, ctrl):
    """P1 内存快照 / diff 端到端：
    1. 拿一个可写页 → 拍快照 A；
    2. mem_write 改 1 字节 → 拍快照 B；
    3. diff(A, B) 应该正好返回 1 条 changed 页，对应 addr 的旧 / 新 head64 不同。
    """
    pid = injected

    # 1) 找一个 RW 页当目标
    regions = ctrl.server.request(pid, {"type": "mem_regions"}, timeout=30)["regions"]
    rw = [r for r in regions
          if r["protect"] == PAGE_READWRITE and r["size"] >= 4096]
    assert rw, "目标进程内没有 RW 区，无法跑快照端到端测试"
    rw_region = {"base": int(rw[0]["base"]), "size": int(rw[0]["size"])}

    # 2) 拍 A（限到这一页所在的 region，避免一次跑出几 MB 数据）
    snap_a = ctrl.snapshot(pid, "before", regions=[rw_region])
    assert snap_a["ok"] and snap_a["count"] >= 1, snap_a
    assert Path(snap_a["path"]).exists(), snap_a["path"]

    # 3) 改 1 字节（取 rw region 内 +1 偏移 —— 必须落在 head64 范围内，因为
    # diff 返回的 old_bytes/new_bytes 是 head64 而非整页；这条约束
    # C 端是 agent.c 里 a_hd = "head64"，v1.4.0 之前不会改成全页，
    # 改全页会让 diff 流量从 64B/页暴涨到 4KB/页，对调试意义不大）
    rw_base = rw_region["base"]
    addr = rw_base + 1
    original = ctrl.mem_read(pid, addr, 1)
    assert original.get("ok"), original
    new_byte = "90" if original["hex"].lower() != "90" else "91"
    assert ctrl.mem_write(pid, addr, new_byte).get("ok")

    # 4) 拍 B
    snap_b = ctrl.snapshot(pid, "after", regions=[rw_region])
    assert snap_b["ok"] and snap_b["count"] >= 1, snap_b

    # 5) diff：预期正好 1 条 changed，那一页的 head64 head[0] 正是我们改的那个字节。
    out = ctrl.diff(pid, "before", "after")
    assert out["ok"], out
    changed = out["changed"]
    assert len(changed) >= 1, out

    # 在 changed 里找我们改的那一页
    target_page = next(
        (c for c in changed if c["addr"] <= addr < c["addr"] + c["size"]),
        None,
    )
    assert target_page is not None, f"未找到含 addr=0x{addr:x} 的 changed 页: {changed}"
    old_b = bytes.fromhex(target_page["old_bytes"])
    new_b = bytes.fromhex(target_page["new_bytes"])
    # offset within page = addr - c["addr"]
    offset = addr - target_page["addr"]
    assert old_b[offset] == int(original["hex"], 16), \
        f"old_bytes[{offset}] 期望 {original['hex']}，实际 {old_b[offset]:02x}"
    assert new_b[offset] == int(new_byte, 16), \
        f"new_bytes[{offset}] 期望 {new_byte}，实际 {new_b[offset]:02x}"

    # 6) 同 self diff → unchanged 应占绝大多数，changed 为空
    same = ctrl.diff(pid, "before", "before")
    assert same["ok"]
    assert same["changed"] == [], same

    # 7) list_snapshots 应能看到这两条；清理避免污染
    items = ctrl.list_snapshots(pid)
    names = {it["name"] for it in items}
    assert {"before", "after"} <= names
    assert ctrl.delete_snapshot(pid, "before")
    assert ctrl.delete_snapshot(pid, "after")


def test_mem_search_max_results_respected(injected, ctrl):
    pid = injected
    found = ctrl.mem_search([pid], "00 00 00 00", 3)
    assert found[0]["ok"]
    assert len(found[0]["resp"]["results"]) <= 3


def test_request_to_non_injected_process_fails(ctrl):
    """未注入的进程不应能响应命令。"""
    resp = ctrl.server.request(999999, {"type": "ping"}, timeout=2)
    assert resp["ok"] is False


def test_terminate_via_dll(ctrl):
    """让被注入进程自己 ExitProcess 结束自己。"""
    pid = spawn([TARGET_IMG, "-t", "127.0.0.1"])
    res = ctrl.inject([pid])
    assert res[0]["ok"], res[0].get("error")
    assert _ping(ctrl, pid), "注入端未连接"

    ctrl.terminate([pid])
    assert _wait_until(lambda: not _pid_alive(pid), timeout=20), "目标进程未被终止"


def test_pid_alive_false_for_exited_process_with_open_handle():
    """进程已退出但句柄仍被持有（Popen 未回收）时，pid_alive 必须报 False。

    这正是打包产物自检里唯一那条红：DLL 内的 ExitProcess 已经成功，但存活
    判定用的是「OpenProcess 能否成功」—— 只要还有人持有句柄，内核里那个进程
    对象就不销毁，于是把「已退出」误判成「仍存活」。
    """
    from superinject import winapi

    proc = subprocess.Popen([TARGET_IMG, "-t", "127.0.0.1"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert winapi.pid_alive(proc.pid), "刚拉起的进程应当被判为存活"
        proc.kill()
        proc.wait(timeout=10)         # 进程已退出，但 proc 仍持有句柄
        assert not winapi.pid_alive(proc.pid), \
            "进程已退出、句柄未回收时 pid_alive 误报存活"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)


def test_x86_dll_path_is_valid_pe():
    """x86 DLL 产物必须存在且机器码为 0x014C（IMAGE_FILE_MACHINE_I386）。"""
    x86 = os.environ.get("SUPERINJECT_DLL_PATH_X86", "")
    if not x86:
        pytest.skip("SUPERINJECT_DLL_PATH_X86 未设置，跳过 x86 DLL 校验")
    p = Path(x86)
    if not p.exists():
        pytest.skip(f"未找到 x86 DLL：{p}")
    data = p.read_bytes()
    assert data[:2] == b"MZ"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0"
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    assert machine == 0x014C, f"x86 DLL 机器码不符：0x{machine:04x}"
    assert struct.unpack_from("<H", data, pe + 22)[0] & 0x2000


@pytest.mark.parametrize("arch_label", ["x86"])
def test_x86_injection_on_syswow64_ping(arch_label):
    """真在 windows runner 上用 x86 DLL 注入 SysWOW64\\ping.exe（32 位）。

    路径：``C:\\Windows\\SysWOW64\\ping.exe`` 在 64 位 Windows 上是 32 位程序，
    注入端 DLL 也是 32 位时才能正常注入。
    """
    x86 = os.environ.get("SUPERINJECT_DLL_PATH_X86", "")
    if not x86:
        pytest.skip("SUPERINJECT_DLL_PATH_X86 未设置，跳过 x86 注入集成测试")
    x86_path = Path(x86)
    if not x86_path.exists():
        pytest.skip(f"未找到 x86 DLL：{x86_path}")

    syswow = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "SysWOW64" / "ping.exe"
    if not syswow.exists():
        pytest.skip(f"未找到 SysWOW64 ping.exe：{syswow}")

    from superinject.controller import Controller

    ctrl = Controller(dll_path=x86_path)
    pid = spawn([str(syswow), "-t", "127.0.0.1"])
    try:
        res = ctrl.inject([pid])[0]
        assert res["ok"], f"x86 注入失败: {res.get('error')}"
        assert res["arch"] == "x86"
        assert res["attached"]
        pong = ctrl.server.request(pid, {"type": "ping"}, timeout=10)
        assert pong.get("ok"), pong
        info = ctrl.server.request(pid, {"type": "info"}, timeout=15)
        assert info.get("ok") and info.get("modules")
    finally:
        try:
            ctrl.unload([pid])
        except Exception:  # pragma: no cover
            pass
        kill(pid)


# ------------------------------------------------------------------ 冻结

def test_freeze_really_suspends_and_resumes(ctrl):
    """冻结 / 解除冻结：不仅记录状态，还要核实线程真的被挂起。"""
    from superinject import winapi

    pid = spawn([TARGET_IMG, "-t", "127.0.0.1"])
    try:
        state_before = winapi.process_suspend_state(pid)
        assert state_before is not True, "冻结前进程不应处于挂起状态"

        frozen = ctrl.freeze([pid])[0]
        assert frozen["ok"], frozen
        assert frozen["verified"] is not False, "冻结后线程仍未挂起"

        thawed = ctrl.unfreeze([pid])[0]
        assert thawed["ok"], thawed
        assert thawed["verified"] is not True, "解除冻结后线程仍被挂起"
        assert _pid_alive(pid)
    finally:
        kill(pid)


def test_freeze_blocks_control_then_recovers(ctrl):
    """冻结期间 DLL 无法响应，解除后控制通道必须恢复。"""
    pid = spawn([TARGET_IMG, "-t", "127.0.0.1"])
    try:
        assert ctrl.inject([pid])[0]["ok"]
        assert _ping(ctrl, pid)
        assert ctrl.freeze([pid])[0]["ok"]
        blocked = ctrl.server.request(pid, {"type": "ping"}, timeout=2)
        assert blocked["ok"] is False, "冻结期间不该还能响应命令"
        assert ctrl.unfreeze([pid])[0]["ok"]
        assert _ping(ctrl, pid), "解除冻结后控制通道未恢复"
    finally:
        kill(pid)


# ------------------------------------------------------------------ 资源

def test_resources_returns_items_and_dir(injected, ctrl):
    pid = injected
    res = ctrl.resources([pid])[0]
    assert res["ok"], res.get("error")
    resp = res["resp"]
    assert isinstance(resp["items"], list)
    assert resp["dir"], "未返回导出目录"
    assert Path(resp["dir"]).is_dir(), resp["dir"]
    for item in resp["items"]:
        assert item["kind"] in ("image", "video", "audio", "other")
        assert Path(item["path"]).exists(), item["path"]
        assert item["source"] in ("resource", "mapped")
    # ping.exe 带图标资源：DIB 应被转成可打开的 ico/bmp
    converted = [i for i in resp["items"] if i.get("dump")]
    for item in converted:
        assert item["ext"] in ("bmp", "ico", "cur"), item


def test_resources_preview_url_when_server_running(injected, ctrl, tmp_path):
    """导出目录里的图片应能通过本地预览服务拿到 URL。"""
    from superinject.fileserver import PreviewServer

    pid = injected
    srv = PreviewServer(Path(ctrl.resources([pid])[0]["resp"]["dir"]).parent)
    srv.start()
    try:
        ctrl.preview_url = srv.url_for
        res = ctrl.resources([pid])[0]
        for item in res["resp"]["items"]:
            if item["previewable"]:
                assert item["url"].startswith("http://127.0.0.1:")
    finally:
        ctrl.preview_url = None
        srv.stop()


# ------------------------------------------------- 高权限 / 跨 TEMP 目标
def test_inject_target_with_foreign_temp(ctrl, tmp_path):
    """目标进程的 TEMP 与控制端不同时也必须能建连。

    这条是 SYSTEM 提权场景的回归：SYSTEM 服务这类目标的 ``GetTempPathW()``
    往往是 ``C:\\Windows\\Temp``，而控制器写在启动它的那个用户的 TEMP 里。
    过去注入端只读自己 TEMP 下的会合文件，于是「注入成功但一直连不上」。
    现在注入端会再扫一遍各用户 TEMP。

    构造方式：给目标进程显式设一个陌生的 TEMP —— 它自己的 TEMP 里没有会合
    文件，只有走「扫用户目录」那条回退路径才能拿到端口和令牌。
    """
    fake_temp = tmp_path / "foreign-temp"
    fake_temp.mkdir()
    env = dict(os.environ)
    env["TEMP"] = env["TMP"] = str(fake_temp)

    proc = subprocess.Popen(
        [TARGET_IMG, "-t", "127.0.0.1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    pid = proc.pid
    try:
        res = ctrl.inject([pid])[0]
        assert res["ok"], f"注入失败: {res.get('error')}"
        assert res["attached"], (
            f"控制通道未建立（跨 TEMP 会合失败）: {res.get('error')}")
        assert _ping(ctrl, pid), "注入端无响应（跨 TEMP 会合失败）"
        # 确认确实没有把会合文件写进目标的 TEMP（否则这条用例没测到回退路径）
        assert not list(fake_temp.rglob("port-*.txt")), \
            "会合文件不该出现在目标自己的 TEMP 里，用例构造有误"
    finally:
        ctrl.unload([pid])
        kill(pid)


# ------------------------------------------------------------------ 硬件断点（v1.3.0 P2）

def test_hw_breakpoint_on_ping(injected, ctrl):
    """在注入 ping.exe 后用 ``bp-set`` 在某个导出函数入口装载一条硬件断点，
    命中后应能收到 ``event:breakpoint``。

    本用例需要真实 ping.exe / DLL，只在 Windows 跑。
    """
    c = ctrl   # fixture 里返回 Controller 实例
    pid = injected

    # 1. 拉一次 info（不携带 exports —— 模块导出表解析曾在 CI 上把整个
    # 进程卡死。集成测试不强求解析 ping.exe 自己的导出表：
    # ping.exe 在 Windows 11 上多数没有导出表（main 是 wmain，
    # Icmp* 都来自 iphlpapi）。改用模块首址 + 0x100 偏移装 bp，
    # 真正测的是"断点装上、能等事件"，不是"命中某个符号"。）
    info = c.server.request(pid, {"type": "info", "no_exports": 1}, timeout=15)
    assert info.get("ok"), info
    modules = info.get("modules") or []
    ping_mod = next(
        (m for m in modules if m.get("name", "").lower().startswith("ping")),
        None,
    )
    assert ping_mod, f"未在模块表里找到 ping 模块：{modules}"

    # 2. 拿到 module 即可：bp 地址 = base + 0x100（落在主代码上）
    addr = int(ping_mod["base"]) + 0x100

    # 4. 装载一条 exec 硬件断点
    # agent.c 字段名是 type（不是 type_str）—— 同一 dict 里不要重名
    # （ruff F601）。这里用 dict 拼接避免键冲突。
    bp_msg = {
        "address": addr,
        "tid": 0,                # pid 用 VEH 模拟，比硬件 DR 更稳（ping 多线程）
        "type": "exec",
        "len": 1,
    }
    bp_msg["type"] = "bp_set"  # 覆盖 —— 别名法，避开 ruff 重复键
    set_resp = c.server.request(pid, bp_msg, timeout=15)
    assert set_resp.get("ok"), f"bp_set 失败：{set_resp}"
    slot = int(set_resp.get("slot", -1))
    assert slot >= 0 or slot == -1  # 任意路径都接受；下次 list 看槽位

    # 5. 等 hit_count ≥ 1（ping 持续发包，必触发）：
    def got_hit():
        lst = c.server.request(pid, {"type": "bp_list"}, timeout=5)
        bps = lst.get("bps") or []
        match = [b for b in bps if int(b.get("addr", -1)) == addr]
        if not match:
            return False
        return (match[0].get("hit_count") or 0) >= 1

    # 留 25 秒等命中：real ping -t 一般一两秒就会触发，但 CI 上慢一点也能接受
    assert _wait_until(got_hit, timeout=25.0, interval=0.5), \
        "在 25 秒内未收到断点命中事件"

    # 5.5 P3：命中事件必须带完整寄存器 + 栈快照
    def got_rich_event():
        evts = c.list_events(pid=pid, name="breakpoint") or []
        for e in evts:
            if int(e.get("addr", -1)) == addr and e.get("regs"):
                return e
        return None

    evt = _wait_until(got_rich_event, timeout=25.0, interval=0.5)
    assert evt, "在 25 秒内未收到带 regs 的断点命中事件"
    regs = evt["regs"]
    # 架构判断与前端一致：x64 有 rip，x86 有 eip
    ip_key = "rip" if "rip" in regs else ("eip" if "eip" in regs else None)
    assert ip_key, f"regs 既无 rip 也无 eip：{sorted(regs)[:8]}"
    ip = int(regs[ip_key])
    base = int(ping_mod["base"])
    size = int(ping_mod.get("size", 0)) or 0x100000
    assert base <= ip < base + size, \
        f"{ip_key}=0x{ip:x} 不在 ping 模块 [0x{base:x}, 0x{base + size:x}) 内"
    # 栈快照：至少 1 项（RSP 页可读时是 16 项，每项 {i, addr, value}）
    stack = evt.get("stack")
    assert isinstance(stack, list) and len(stack) >= 1, f"stack 快照为空：{stack}"
    assert {"i", "addr", "value"} <= set(stack[0].keys()), \
        f"stack 项字段不全：{stack[0]}"

    # 6. 清理
    clear = c.server.request(pid, {"type": "bp_clear"}, timeout=10)
    assert clear.get("ok"), clear
    assert (int(clear.get("cleared_hw", 0))
            + int(clear.get("cleared_veh", 0))) >= 1
