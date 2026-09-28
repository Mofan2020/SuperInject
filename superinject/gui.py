"""PyWebView GUI：把控制器能力暴露给前端，并负责启动自检流程。

启动顺序（对应需求）：
  自检1 权限(管理员/SYSTEM) → 自检2 DLL 校验替换 → 拉起 GUI → 后台检查更新
"""

from __future__ import annotations

import json
import logging
import tempfile
import threading
from pathlib import Path
from typing import Any

from . import dll_manager, elevate, updater, winapi
from .controller import Controller
from .fileserver import PreviewServer
from .version import APP_NAME, PROJECT_URL, __version__

log = logging.getLogger("supinject.gui")

WEB_DIR = Path(__file__).resolve().parent / "web"


def export_root() -> Path:
    """注入端导出资源的根目录（与 native/agent.c 中的约定一致）。"""
    return Path(tempfile.gettempdir()) / "SuperInject"


class Api:
    """暴露给前端 JS 的接口（pywebview 的 js_api）。"""

    def __init__(self, window_holder: dict[str, Any]):
        self._holder = window_holder
        self.preview = PreviewServer(export_root())
        self.controller = Controller()
        self.controller.preview_url = self.preview.url_for
        self.dll_report: dict = {}
        self.update: dict = {}
        self.controller.on_change(self._broadcast_state)

    # -------------------------------------------------- 内部

    def _window(self):
        return self._holder.get("window")

    def _emit(self, event: str, payload: Any) -> None:
        """向前端派发事件。

        事件名必须当字符串字面量传进 JS —— 早期版本漏了 json.dumps，
        生成出 ``onEvent(state, …)`` 这种表达式，前端全部事件静默失效。
        """
        w = self._window()
        if w is None:
            return
        try:
            script = (f"window.SI && window.SI.onEvent({json.dumps(event)}, "
                      f"{json.dumps(payload, ensure_ascii=False, default=str)})")
            w.evaluate_js(script)
        except Exception:  # pragma: no cover
            log.debug("事件派发失败", exc_info=True)

    def _broadcast_state(self) -> None:
        threading.Thread(target=lambda: self._emit("state", self.controller.status()),
                         daemon=True).start()

    def _ensure_preview(self) -> None:
        if not self.preview.running:
            self.preview.start(export_root())
            self.controller.preview_base_url = self.preview.base_url

    # -------------------------------------------------- 启动信息

    def bootstrap(self) -> dict:
        """前端初始化时调用，一次性返回全部状态。"""
        return {
            "app": APP_NAME,
            "version": __version__,
            "url": PROJECT_URL,
            "privilege": winapi.current_privilege(),
            "is_admin": elevate.is_admin(),
            "identity": elevate.current_identity(),
            "arch": self.controller.status().get("arch", ""),
            "dll": self.dll_report,
            "update": self.update,
            "status": self.controller.status(),
        }

    def list_processes(self) -> list:
        return self.controller.list_processes()

    # -------------------------------------------------- 注入

    def preflight(self, pids: list) -> list:
        """注入检查：返回每个 PID 是否可注入及其原因。"""
        return self.controller.preflight([int(p) for p in pids])

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
        self._ensure_preview()
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

    # -------------------------------------------------- 收尾

    def shutdown(self) -> None:
        try:
            self.preview.stop()
        except Exception:  # pragma: no cover
            pass
        try:
            self.controller.server.shutdown()
        except Exception:  # pragma: no cover
            pass


def create_window(api: Api):
    """创建 pywebview 窗口（供 __main__ 调用）。"""
    import webview

    return webview.create_window(
        APP_NAME,
        str(WEB_DIR / "index.html"),
        js_api=api,
        width=1280, height=820, min_size=(1040, 640),
    )


def run_gui(api: Api, window, debug: bool = False) -> None:
    import webview

    try:
        webview.start(debug=debug, private_mode=False)
    finally:
        api.shutdown()


def update_checker(api: Api) -> updater.UpdateChecker:
    """启动时的后台更新检查。"""
    return updater.UpdateChecker(on_found=lambda rel: api._emit(
        "update-available",
        {"version": rel.version, "url": rel.url, "notes": rel.notes,
         "asset": (rel.windows_asset() or {}).get("browser_download_url")},
    ))
