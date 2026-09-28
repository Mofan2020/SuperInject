"""PyWebView GUI：把控制器能力暴露给前端，并负责启动自检流程。

启动顺序（对应需求）：
  自检1 权限(管理员/SYSTEM) → 自检2 DLL 校验替换 → 拉起 GUI → 后台检查更新
"""

from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Any, Optional

from . import dll_manager, elevate, updater, winapi
from .controller import Controller
from .version import APP_NAME, PROJECT_URL, __version__

log = logging.getLogger("supinject.gui")

WEB_DIR = Path(__file__).resolve().parent / "web"


class Api:
    """暴露给前端 JS 的接口（pywebview 的 js_api）。"""

    def __init__(self, window_holder: dict[str, Any]):
        self._holder = window_holder
        self.controller = Controller()
        self.dll_report: dict = {}
        self.update: dict = {}
        self.controller.on_change(self._broadcast_state)

    # -------------------------------------------------- 内部

    def _window(self):
        return self._holder.get("window")

    def _emit(self, event: str, payload: Any) -> None:
        w = self._window()
        if w is None:
            return
        try:
            import json

            w.evaluate_js(f"window.SI && window.SI.onEvent({event}, {json.dumps(payload, ensure_ascii=False)})")
        except Exception:  # pragma: no cover
            log.debug("事件派发失败", exc_info=True)

    def _broadcast_state(self) -> None:
        threading.Thread(target=lambda: self._emit("state", self.controller.status()),
                         daemon=True).start()

    # -------------------------------------------------- 启动信息

    def bootstrap(self) -> dict:
        """前端初始化时调用，一次性返回全部状态。"""
        return {
            "app": APP_NAME,
            "version": __version__,
            "url": PROJECT_URL,
            "is_admin": elevate.is_admin(),
            "identity": elevate.current_identity(),
            "dll": self.dll_report,
            "update": self.update,
            "status": self.controller.status(),
        }

    def list_processes(self) -> list:
        return self.controller.list_processes()

    # -------------------------------------------------- 注入

    def inject(self, pids: list, dll_path: str = "") -> list:
        return self.controller.inject([int(p) for p in pids], dll_path or None)

    # -------------------------------------------------- 控制

    def unload(self, pids: list) -> list:
        return self.controller.unload([int(p) for p in pids])

    def terminate(self, pids: list) -> list:
        return self.controller.terminate([int(p) for p in pids])

    def freeze(self, pids: list) -> list:
        return self.controller.freeze([int(p) for p in pids])

    def unfreeze(self, pids: list) -> list:
        return self.controller.unfreeze([int(p) for p in pids])

    def ping(self, pids: list) -> list:
        return self.controller.ping([int(p) for p in pids])

    def info(self, pids: list) -> list:
        return self.controller.info([int(p) for p in pids])

    # -------------------------------------------------- 内存

    def mem_search(self, pids: list, pattern: str, max_results: int = 256) -> list:
        return self.controller.mem_search([int(p) for p in pids], pattern,
                                          int(max_results))

    def mem_read(self, pid: int, address: str, size: int = 64) -> dict:
        from .ipc import parse_int

        return self.controller.mem_read(int(pid), parse_int(str(address)), int(size))

    def mem_write(self, pid: int, address: str, hexdata: str) -> dict:
        from .ipc import parse_int

        return self.controller.mem_write(int(pid), parse_int(str(address)), hexdata)

    def mem_regions(self, pid: int) -> dict:
        return self.controller.mem_regions(int(pid))

    # -------------------------------------------------- 资源

    def resources(self, pids: list) -> list:
        return self.controller.resources([int(p) for p in pids])

    def reveal(self, path: str) -> bool:
        return self.controller.open_path(path)

    # -------------------------------------------------- DLL / 更新

    def verify_dll(self, force: bool = False) -> dict:
        report = dll_manager.verify_and_sync(force=bool(force))
        data = {
            "ok": report.ok, "action": report.action, "path": str(report.path),
            "embedded_sha": report.embedded_sha, "disk_sha": report.disk_sha,
            "message": report.message,
        }
        self.dll_report = data
        self.controller.dll_path = report.path
        self._emit("dll", data)
        return data

    def check_update(self) -> dict:
        rel = updater.fetch_latest()
        if rel is None:
            return {"ok": False, "message": "无法连接 GitHub（可能被墙或离线）"}
        return {
            "ok": True,
            "current": __version__,
            "latest": rel.version,
            "has_newer": rel.has_newer,
            "url": rel.url,
            "notes": rel.notes,
            "asset": (rel.windows_asset() or {}).get("browser_download_url"),
        }

    def apply_update(self, url: str) -> dict:
        """下载并安装更新：解压后交由批处理在主程序退出后覆盖文件。"""

        def work():
            import tempfile

            try:
                self._emit("update-progress", {"stage": "下载中", "done": 0, "total": 0})
                tmp = Path(tempfile.mkdtemp(prefix="supinject_dl_"))
                zip_path = updater.download(
                    url, tmp / "update.zip",
                    lambda done, total: self._emit(
                        "update-progress",
                        {"stage": "下载中", "done": done, "total": total}),
                )
                self._emit("update-progress", {"stage": "解压中", "done": 1, "total": 1})
                src = updater.stage_update(zip_path)
                updater.write_update_script(src)
                self._emit("update-progress", {"stage": "安装中，请稍候…",
                                               "done": 1, "total": 1})
            except Exception as exc:  # pragma: no cover
                self._emit("update-error", {"message": str(exc)})

        threading.Thread(target=work, daemon=True).start()
        return {"ok": True, "message": "已开始下载更新，请稍候…"}
