"""注入控制器：把「注入检查 → 注入 → 建立通道 → 批量控制」串成一套业务能力。

前端只与本模块交互，不直接接触 Win32。
"""

from __future__ import annotations

import ctypes
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

from . import dll_manager, ipc, media, resconv, winapi
from .version import __version__

log = logging.getLogger("supinject.controller")

MAX_WORKERS = 8
DLL_NAME = dll_manager.DLL_FILENAME
ATTACH_TIMEOUT = 12.0
DETACH_TIMEOUT = 8.0
# 等目标进程把旧 DLL 真正卸载掉（FreeLibraryAndExitThread 的卸载是异步的）
UNLOAD_TIMEOUT = 8.0

# 注入所需的最小权限集合
INJECT_ACCESS = (
    winapi.PROCESS_CREATE_THREAD | winapi.PROCESS_QUERY_INFORMATION
    | winapi.PROCESS_VM_OPERATION | winapi.PROCESS_VM_WRITE | winapi.PROCESS_VM_READ
)


def native_arch() -> str:
    """本进程（也就决定了 DLL）的位数。"""
    return "x64" if ctypes.sizeof(ctypes.c_void_p) == 8 else "x86"


@dataclass
class Controller:
    dll_path: Optional[Path] = None
    server: ipc.AgentServer = field(default_factory=ipc.AgentServer)
    max_workers: int = MAX_WORKERS
    preview_base_url: str = ""
    preview_url: Optional[Callable[[str], str]] = None

    def __post_init__(self) -> None:
        if self.dll_path is None:
            self.dll_path = dll_manager.target_dll_path()
        self.server.on_attach = self._on_attach
        self.server.on_detach = self._on_detach
        self._lock = threading.Lock()
        self._injected: Dict[int, dict] = {}
        self._frozen: set[int] = set()
        self._change_cb: Optional[Callable[[], None]] = None

    # ---------------------------------------------------------- 事件

    def _on_attach(self, pid: int, info: dict) -> None:
        with self._lock:
            self._injected[pid] = dict(info)
        log.info("已连接注入端 pid=%s %s", pid, info.get("image"))

    def _on_detach(self, pid: int) -> None:
        with self._lock:
            self._injected.pop(pid, None)

    def on_change(self, callback: Optional[Callable[[], None]]) -> None:
        self._change_cb = callback

    def _fire(self) -> None:
        cb = self._change_cb
        if cb:
            try:
                cb()
            except Exception:  # pragma: no cover
                log.exception("状态回调失败")

    # ---------------------------------------------------------- 进程

    def list_processes(self) -> List[dict]:
        """列出全部进程（含 pid / 名称 / 路径 / 内存 / 注入状态）。"""
        items: List[dict] = []
        try:
            raw = winapi.enum_processes()
        except Exception as exc:  # pragma: no cover
            log.exception("枚举进程失败")
            return [{"error": str(exc)}]

        for pid, name in raw:
            try:
                path = winapi.process_path(pid)
            except Exception:
                path = ""
            try:
                mem = winapi.process_memory_mb(pid)
            except Exception:
                mem = 0.0
            items.append({
                "pid": pid,
                "name": name,
                "path": path,
                "mem_mb": mem,
                "injected": self.server.is_attached(pid),
                "frozen": pid in self._frozen,
            })
        items.sort(key=lambda x: x["name"].lower())
        return items

    def resolve_targets(self, pids: Iterable[int], names: Iterable[str] = ()
                        ) -> List[int]:
        """把 PID 列表和进程名列表解析成一组实际存在的 PID。

        同名进程（多标签浏览器等）全部保留，并尽量保持用户给出的顺序。
        """
        out: List[int] = []
        want_names = [n.strip().lower() for n in names if str(n).strip()]
        if want_names:
            lookup: Dict[str, List[int]] = {}
            for pid, name in winapi.enum_processes():
                lookup.setdefault(name.lower(), []).append(pid)
            for n in want_names:
                for pid in lookup.get(n, []):
                    if pid not in out:
                        out.append(pid)
        for p in pids:
            try:
                pid = int(p)
            except (TypeError, ValueError):
                continue
            if pid and pid not in out:
                out.append(pid)
        return out

    # ---------------------------------------------------------- 注入检查

    def preflight(self, pids: Iterable[int]) -> List[dict]:
        """注入检查：逐个 PID 判断能否注入，给出阻塞原因与提醒。"""
        pids = [int(p) for p in pids]
        try:
            names = dict(winapi.enum_processes())
        except Exception:  # pragma: no cover
            names = {}
        me = os.getpid()
        self_arch = native_arch()

        report: List[dict] = []
        for pid in pids:
            item = {
                "pid": pid, "name": names.get(pid, ""), "path": "", "arch": "",
                "accessible": False, "attached": False, "dll_loaded": False,
                "blocked": False, "reason": "", "warnings": [], "ok": True,
            }
            if pid <= 0:
                item.update(ok=False, blocked=True, reason="无效 PID")
            elif pid == me:
                item.update(ok=False, blocked=True, reason="不能注入 SuperInject 自身")
            else:
                item["name"] = item["name"] or winapi.process_name(pid)
                item["path"] = winapi.process_path(pid)
                if not item["name"]:
                    item.update(ok=False, blocked=True, reason="进程不存在或已退出")
                elif (item["name"].lower() in winapi.CRITICAL_PROCESSES
                      or pid in winapi.CRITICAL_PIDS):
                    item.update(ok=False, blocked=True,
                                reason="系统关键进程，注入会直接导致系统崩溃")
                else:
                    wow = winapi.is_wow64(pid)
                    item["arch"] = {True: "x86", False: "x64"}.get(wow, "")
                    if item["arch"] and item["arch"] != self_arch:
                        item.update(
                            ok=False, blocked=True,
                            reason=f"位数不匹配：目标进程 {item['arch']}，"
                                   f"本工具与 DLL 为 {self_arch}")
                    else:
                        h = winapi.open_process(pid, INJECT_ACCESS)
                        if h:
                            winapi.close_handle(h)
                            item["accessible"] = True
                        else:
                            item.update(
                                ok=False, blocked=True,
                                reason="无法打开进程（"
                                       f"{winapi.format_error()}），请确认已提权")
            if not item["blocked"]:
                item["attached"] = self.server.is_attached(pid)
                item["dll_loaded"] = winapi.module_loaded(pid, DLL_NAME)
                if item["dll_loaded"] and not item["attached"]:
                    item["warnings"].append(
                        "目标进程内已加载 SuperInjectAgent.dll 但控制通道未连接")
                if item["attached"]:
                    item["warnings"].append("已注入，将先卸载旧 DLL 再重新注入")
            report.append(item)
        return report

    # ---------------------------------------------------------- 注入

    def inject(self, pids: List[int], dll_path: Optional[str] = None,
               reinject: bool = True, check: bool = True) -> List[dict]:
        """批量注入：先做注入检查，再注入，最后确认控制通道已建立。"""
        path = Path(dll_path) if dll_path else self.dll_path
        pids = [int(p) for p in pids]
        if not path or not path.exists():
            return [{"pid": p, "ok": False, "injected": False,
                     "error": f"DLL 不存在: {path}"} for p in pids]

        checks = {c["pid"]: c for c in self.preflight(pids)} if check else {}
        results = self._run_parallel(
            pids, lambda pid: self._inject_one(pid, path, checks.get(pid), reinject))
        self._fire()
        return results

    def _inject_one(self, pid: int, path: Path, check: Optional[dict],
                    reinject: bool) -> dict:
        base = {"pid": pid, "injected": False, "attached": False, "reinjected": False}
        if check and check.get("blocked"):
            return {**base, "ok": False, "blocked": True, "error": check["reason"]}
        try:
            if self.server.is_attached(pid):
                if not reinject:
                    return {**base, "ok": False,
                            "error": "已注入且控制通道已连接（未开启重新注入）"}
                self.server.request(pid, {"type": "unload"}, timeout=8)
                if not self.server.wait_detach(pid, DETACH_TIMEOUT):
                    return {**base, "ok": False,
                            "error": "旧 DLL 卸载失败（目标可能被冻结或无响应）"}
                if not self._wait_module_gone(pid, UNLOAD_TIMEOUT):
                    return {**base, "ok": False,
                            "error": "旧 DLL 已断开但模块仍留在目标进程内"
                                     "（卸载是异步的，或仍有其它引用），"
                                     "此时再 LoadLibraryW 不会触发 DllMain，"
                                     "请重启目标进程后再注入"}
                base["reinjected"] = True
            elif winapi.module_loaded(pid, DLL_NAME):
                # 模块已在但没连上：agent 线程可能仍在建连，给它一点时间
                if not self.server.wait_attach(pid, 3.0):
                    return {**base, "ok": False,
                            "error": "目标进程内已存在 SuperInjectAgent.dll，"
                                     "但控制通道未建立（上次运行的残留）。"
                                     "请重启目标进程后再注入。"}

            self.server.register(pid)
            module = winapi.inject_dll(pid, str(path))
            if not module:
                return {**base, "ok": False,
                        "error": "LoadLibraryW 返回 0（位数不匹配 / 被安全软件拦截 /"
                                 " 目标进程已加载同名 DLL）"}

            attached = self.server.wait_attach(pid, ATTACH_TIMEOUT)
            result = {
                **base, "ok": attached, "injected": True, "attached": attached,
                "module": hex(module), "image": winapi.process_path(pid),
            }
            if not attached:
                result["error"] = (f"DLL 已注入，但 {ATTACH_TIMEOUT:.0f} 秒内未建立控制通道"
                                   "（目标可能被冻结、或处于受保护状态）")
            return result
        except Exception as exc:
            return {**base, "ok": False, "error": str(exc)}

    # ---------------------------------------------------------- 控制指令


    def _wait_module_gone(self, pid: int, timeout: float) -> bool:
        """等目标进程里真的看不到我们的 DLL 了。

        为什么必须等：卸载命令走的是 FreeLibraryAndExitThread，它先结束线程、
        再由加载器异步把模块摘掉 —— socket 断开只证明线程退了，模块可能还在
        映射里。这一瞬间 LoadLibraryW 拿到的是旧模块（引用计数 +1、不触发
        DllMain），于是重新注入永远建立不了控制通道（CI 上实测如此）。
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not winapi.module_loaded(pid, DLL_NAME):
                return True
            time.sleep(0.05)
        return not winapi.module_loaded(pid, DLL_NAME)

    def _control(self, pids: List[int], cmd: str, timeout: float = 15.0
                 ) -> List[dict]:
        """通过注入端 DLL 执行指令（批量）。"""
        out: List[dict] = []
        if not pids:
            return out
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(pids))) as pool:
            futures = {
                pool.submit(self.server.request, pid, {"type": cmd}, timeout): pid
                for pid in pids
            }
            for fut in as_completed(futures):
                pid = futures[fut]
                try:
                    resp = fut.result()
                except Exception as exc:  # pragma: no cover
                    resp = {"ok": False, "error": str(exc)}
                out.append({"pid": pid, "ok": bool(resp.get("ok")), "resp": resp,
                            "error": resp.get("error", "")})
        out.sort(key=lambda x: x["pid"])
        return out

    def unload(self, pids: List[int]) -> List[dict]:
        """卸载注入的 DLL，并等待控制通道断开（断开后才能干净地重新注入）。"""
        pids = [int(p) for p in pids]
        res = self._control(pids, "unload", timeout=8)
        by_pid = {r["pid"]: r for r in res}
        for pid in pids:
            detached = self.server.wait_detach(pid, 4.0)
            self.server.unregister(pid)
            self._frozen.discard(pid)
            if pid in by_pid:
                by_pid[pid]["detached"] = detached
                if by_pid[pid]["ok"] and not detached:
                    by_pid[pid]["error"] = "DLL 未在预期时间内卸载干净"
        self._fire()
        return res

    def terminate(self, pids: List[int]) -> List[dict]:
        """让被注入进程自己调用 ExitProcess 结束自己。"""
        pids = [int(p) for p in pids]
        res = self._control(pids, "terminate", timeout=8)
        for pid in pids:
            self.server.unregister(pid)
            self._frozen.discard(pid)
        self._fire()
        return res

    def freeze(self, pids: List[int]) -> List[dict]:
        """冻结进程：挂起全部线程使其完全无响应，并回报实际挂起状态。"""
        out = []
        for pid in pids:
            pid = int(pid)
            ok = winapi.suspend_process(pid)
            verified = winapi.process_suspend_state(pid) if ok else None
            if ok:
                self._frozen.add(pid)
            out.append({
                "pid": pid, "ok": ok, "verified": verified,
                "error": "" if ok else "NtSuspendProcess 失败（请确认已提权）",
            })
        self._fire()
        return out

    def unfreeze(self, pids: List[int]) -> List[dict]:
        out = []
        for pid in pids:
            pid = int(pid)
            ok = winapi.resume_process(pid)
            verified = winapi.process_suspend_state(pid) if ok else None
            if ok:
                self._frozen.discard(pid)
            out.append({
                "pid": pid, "ok": ok, "verified": verified,
                "error": "" if ok else "NtResumeProcess 失败（请确认已提权）",
            })
        self._fire()
        return out

    def ping(self, pids: List[int]) -> List[dict]:
        return self._control(pids, "ping", timeout=5)

    def info(self, pids: List[int]) -> List[dict]:
        return self._control(pids, "info", timeout=10)

    # ---------------------------------------------------------- 内存

    def mem_search(self, pids: List[int], pattern: str, max_results: int = 256
                   ) -> List[dict]:
        try:
            pat, mask = ipc.normalize_hex(pattern)
        except ValueError as exc:
            return [{"pid": p, "ok": False, "error": str(exc)} for p in pids]

        def one(pid: int) -> dict:
            resp = self.server.request(pid, {
                "type": "mem_search", "pattern": pat, "mask": mask,
                "max": int(max_results),
            }, timeout=60)
            return {"pid": pid, "ok": bool(resp.get("ok")), "resp": resp,
                    "error": resp.get("error", "")}

        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, len(pids)))) as pool:
            return list(pool.map(one, pids))

    def mem_read(self, pid: int, address: int, size: int = 64) -> dict:
        return self.server.request(pid, {
            "type": "mem_read", "address": int(address), "size": int(size),
        }, timeout=15)

    def mem_write(self, pid: int, address: int, hexdata: str) -> dict:
        try:
            ipc.normalize_hex(hexdata)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
        return self.server.request(pid, {
            "type": "mem_write", "address": int(address),
            "hex": hexdata.replace(" ", "").replace("?", "00"),
        }, timeout=15)

    def mem_regions(self, pid: int) -> dict:
        return self.server.request(pid, {"type": "mem_regions"}, timeout=30)

    # ---------------------------------------------------------- 资源

    def resources(self, pids: List[int]) -> List[dict]:
        """提取进程内的图片/音频/视频：PE 资源 + 内存映射文件，并准备好预览地址。"""
        def one(pid: int) -> dict:
            resp = self.server.request(pid, {"type": "resources"}, timeout=180)
            items = self._prepare_items(resp.get("items") or [])
            ok = bool(resp.get("ok"))
            return {
                "pid": pid, "ok": ok, "error": resp.get("error", ""),
                "resp": {**resp, "items": items},
            }

        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, len(pids)))) as pool:
            return list(pool.map(one, pids))

    def _prepare_items(self, raw_items: List[dict]) -> List[dict]:
        """把裸 DIB 转成可打开的图片，并为每个条目算好预览 URL。"""
        resolver = self.preview_url
        out: List[dict] = []
        for raw in raw_items:
            item = dict(raw)
            rtype = int(item.get("rtype") or 0)
            path = str(item.get("path") or "")
            if rtype in (resconv.RT_BITMAP, resconv.RT_ICON, resconv.RT_CURSOR) and path:
                converted = resconv.convert_dump(Path(path), rtype)
                if converted:
                    item["dump"] = path
                    item["path"] = str(converted)
                    item["ext"] = converted.suffix.lstrip(".")
            url = ""
            if resolver and item.get("path"):
                try:
                    url = resolver(str(item["path"]))
                except Exception:  # pragma: no cover - 预览服务不可用不影响导出
                    log.debug("生成预览地址失败", exc_info=True)
            out.append(media.build_preview_item(item, url))
        return out

    def open_path(self, path: str) -> bool:
        """在资源管理器中定位文件 / 打开目录。"""
        import subprocess

        try:
            p = Path(path)
            if p.is_file():
                subprocess.Popen(["explorer", "/select,", str(p).replace("/", "\\")])
                return True
            if p.is_dir():
                os.startfile(str(p))  # type: ignore[attr-defined]
                return True
        except Exception:
            log.exception("打开路径失败 %s", path)
        return False

    # ---------------------------------------------------------- 工具

    def _run_parallel(self, items: List[int],
                      fn: Callable[[int], dict]) -> List[dict]:
        if not items:
            return []
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(items))) as pool:
            return list(pool.map(fn, items))

    def status(self) -> dict:
        with self._lock:
            injected = dict(self._injected)
        frozen = []
        for pid in sorted(self._frozen):
            frozen.append({
                "pid": pid,
                "verified": winapi.process_suspend_state(pid),
            })
        return {
            "version": __version__,
            "dll_path": str(self.dll_path),
            "dll_exists": bool(self.dll_path and self.dll_path.exists()),
            "privilege": winapi.current_privilege(),
            "injected": injected,
            "frozen": frozen,
            "arch": native_arch(),
            "network": {"attached": sorted(self.server.attached_pids())},
        }
