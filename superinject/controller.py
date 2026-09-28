"""注入控制器：把「进程枚举 → 注入 → 批量控制」串成一套业务能力。

前端只与本模块交互，不直接接触 Win32。
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from . import dll_manager, ipc, winapi
from .version import __version__

log = logging.getLogger("supinject.controller")

MAX_WORKERS = 8


@dataclass
class Controller:
    dll_path: Optional[Path] = None
    server: ipc.PipeServer = field(default_factory=ipc.PipeServer)
    max_workers: int = MAX_WORKERS

    def __post_init__(self) -> None:
        if self.dll_path is None:
            self.dll_path = dll_manager.target_dll_path()
        self.server.on_attach = self._on_attach
        self.server.on_detach = self._on_detach
        self._lock = threading.Lock()
        self._injected: Dict[int, dict] = {}
        self._frozen: set[int] = set()

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
        cb = getattr(self, "_change_cb", None)
        if cb:
            try:
                cb()
            except Exception:  # pragma: no cover
                log.exception("状态回调失败")

    # ---------------------------------------------------------- 进程

    def list_processes(self) -> List[dict]:
        """列出全部进程（含 pid / 名称 / 路径 / 内存 / 注入状态）。"""
        self._fire()
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
                "injected": pid in self._injected or self.server.is_attached(pid),
                "frozen": pid in self._frozen,
            })
        items.sort(key=lambda x: x["name"].lower())
        return items

    def resolve_targets(self, pids: Iterable[int], names: Iterable[str] = ()
                        ) -> List[int]:
        """把 PID 列表和进程名列表解析成一组实际存在的 PID。"""
        out: List[int] = []
        want_names = [n.strip().lower() for n in names if str(n).strip()]
        if want_names:
            lookup = {name.lower(): pid for pid, name in winapi.enum_processes()}
            for n in want_names:
                pid = lookup.get(n)
                if pid:
                    out.append(pid)
        for p in pids:
            try:
                pid = int(p)
            except (TypeError, ValueError):
                continue
            if pid and pid not in out:
                out.append(pid)
        return out

    # ---------------------------------------------------------- 注入

    def inject(self, pids: List[int], dll_path: Optional[str] = None
               ) -> List[dict]:
        """批量注入。注入前先为每个目标建立管道监听。"""
        path = Path(dll_path) if dll_path else self.dll_path
        if not path or not path.exists():
            return [{"pid": p, "ok": False,
                     "error": f"DLL 不存在: {path}"} for p in pids]

        for pid in pids:
            self.server.register(pid)

        results = self._run_parallel(pids, lambda pid: self._inject_one(pid, path))
        self._fire()
        return results

    def _inject_one(self, pid: int, path: Path) -> dict:
        try:
            module = winapi.inject_dll(str(path))
            if module:
                return {"pid": pid, "ok": True, "module": hex(module),
                        "image": winapi.process_path(pid)}
            return {"pid": pid, "ok": False,
                    "error": "LoadLibraryW 返回 0（可能位数不匹配或已加载）"}
        except Exception as exc:
            return {"pid": pid, "ok": False, "error": str(exc)}

    # ---------------------------------------------------------- 控制指令

    def _control(self, pids: List[int], cmd: str, timeout: float = 15.0
                 ) -> List[dict]:
        """通过注入端 DLL 执行指令（批量）。"""
        out: List[dict] = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self.server.request, pid, {"type": cmd}, timeout): pid
                for pid in pids
            }
            from concurrent.futures import as_completed

            for fut in as_completed(futures):
                pid = futures[fut]
                try:
                    resp = fut.result()
                except Exception as exc:  # pragma: no cover
                    resp = {"ok": False, "error": str(exc)}
                out.append({"pid": pid, "ok": bool(resp.get("ok")), "resp": resp})
        out.sort(key=lambda x: x["pid"])
        return out

    def unload(self, pids: List[int]) -> List[dict]:
        res = self._control(pids, "unload", timeout=8)
        for pid in pids:
            self.server.unregister(pid)
            self._frozen.discard(pid)
        self._fire()
        return res

    def terminate(self, pids: List[int]) -> List[dict]:
        """让被注入进程自己调用 ExitProcess 结束自己。"""
        res = self._control(pids, "terminate", timeout=8)
        for pid in pids:
            self.server.unregister(pid)
        self._fire()
        return res

    def freeze(self, pids: List[int]) -> List[dict]:
        """冻结进程：挂起全部线程，使其完全无响应。"""
        out = []
        for pid in pids:
            ok = winapi.suspend_process(pid)
            if ok:
                self._frozen.add(pid)
            out.append({"pid": pid, "ok": ok,
                        "error": "" if ok else "NtSuspendProcess 失败"})
        self._fire()
        return out

    def unfreeze(self, pids: List[int]) -> List[dict]:
        out = []
        for pid in pids:
            ok = winapi.resume_process(pid)
            if ok:
                self._frozen.discard(pid)
            out.append({"pid": pid, "ok": ok,
                        "error": "" if ok else "NtResumeProcess 失败"})
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
            return {"pid": pid, "ok": bool(resp.get("ok")), "resp": resp}

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
        def one(pid: int) -> dict:
            resp = self.server.request(pid, {"type": "resources"}, timeout=120)
            return {"pid": pid, "ok": bool(resp.get("ok")), "resp": resp}

        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(1, len(pids)))) as pool:
            return list(pool.map(one, pids))

    def open_path(self, path: str) -> bool:
        """在资源管理器中定位文件。"""
        import os
        import subprocess

        try:
            if os.path.exists(path):
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
                return True
            if os.path.isdir(path):
                os.startfile(path)  # type: ignore[attr-defined]
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
        return {
            "version": __version__,
            "dll_path": str(self.dll_path),
            "dll_exists": bool(self.dll_path and self.dll_path.exists()),
            "injected": injected,
            "frozen": sorted(self._frozen),
        }
