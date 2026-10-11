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
from typing import Any, Optional

from . import dll_manager, elevate, mcp_consent, updater, winapi
from .controller import Controller
from .fileserver import PreviewServer
from .version import APP_NAME, PROJECT_URL, __version__

log = logging.getLogger("supinject.gui")

WEB_DIR = Path(__file__).resolve().parent / "web"

# 窗口默认/最小尺寸（逻辑像素）。上限不是为了好看，而是保证窗口永远塞得进屏幕。
DEFAULT_WINDOW = (1280, 860)
MIN_WINDOW = (720, 500)


def window_size(screen: Optional[tuple] = None) -> tuple[int, int]:
    """按屏幕可用区域算 GUI 初始尺寸（纯函数，方便测试）。

    规则：取「默认尺寸」与「屏幕 92%」的较小值，并保证不小于最小尺寸。
    这样小屏机器上窗口一定放得下，加上整页可滚动，所有功能区都能看到。
    """
    if not screen:
        return DEFAULT_WINDOW
    sw, sh = int(screen[0]), int(screen[1])
    if sw <= 0 or sh <= 0:
        return DEFAULT_WINDOW
    w = max(MIN_WINDOW[0], min(DEFAULT_WINDOW[0], int(sw * 0.92)))
    h = max(MIN_WINDOW[1], min(DEFAULT_WINDOW[1], int(sh * 0.92)))
    return w, h


def export_root() -> Path:
    """注入端导出资源的根目录（与 native/agent.c 中的约定一致）。"""
    return Path(tempfile.gettempdir()) / "SuperInject"


def storage_dir() -> Path:
    """WebView 的持久化目录（cookie / localStorage / 缓存）。

    显式指定而不是让它落到 %LOCALAPPDATA%：以 SYSTEM 运行时环境变量里的
    路径属于当前用户，交给 WebView 自己猜容易踩到权限问题。
    """
    return Path(tempfile.gettempdir()) / "SuperInject" / "webview"



class Api:
    """暴露给前端 JS 的接口（pywebview 的 js_api）。"""

    def __init__(self, window_holder: dict[str, Any]):
        self._holder = window_holder
        self.preview = PreviewServer(export_root())
        self.controller = Controller()
        self.controller.preview_url = self.preview.url_for
        self.dll_report: dict = {}
        self.update: dict = {}
        self.elevation: dict = {}
        # v1.3.0 P6：GUI 进程内的命名管道桥（给无 UAC 的 mcp-launcher 用）。
        self._mcp_server = None
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
            "elevation": self.elevation,
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

    # -------------------------------------------------- 内存快照 / diff

    def list_snapshots(self, pid: int) -> list:
        return self.controller.list_snapshots(int(pid))

    def snapshot(self, pid: int, name: str, regions: list = []) -> dict:
        # default=[] is safe here because the controller copies via list(regions)
        return self.controller.snapshot(int(pid), name, regions)

    def diff_snapshot(self, pid: int, name1: str, name2: str,
                      limit: int = 0) -> dict:
        return self.controller.diff(int(pid), name1, name2, limit=limit)

    def delete_snapshot(self, pid: int, name: str) -> bool:
        return self.controller.delete_snapshot(int(pid), name)

    # -------------------------------------------------- 硬件断点（v1.3.0 P2）

    def bp_set(self, pid: int, target: str, tid: int = 0,
               bp_type: str = "exec", size: int = 1) -> dict:
        """前端用：先拉一次 info + 模块 exports 再喂给 controller 解析
        ``module!symbol+0x42``；并把当前 symbols 索引挂在 Controller 上
        以便后续 bp_remove 复用。"""
        idx = self._build_bp_index(int(pid), target)
        return self.controller.breakpoint_set(
            int(pid), address=0, target=target,
            tid=int(tid), bp_type=str(bp_type), size=int(size),
            symbol_index=idx,
        )

    def bp_list(self, pid: int) -> dict:
        return self.controller.breakpoint_list(int(pid))

    def bp_remove(self, pid: int, target: str, tid: int = 0) -> dict:
        idx = self._build_bp_index(int(pid), target)
        return self.controller.breakpoint_remove(
            int(pid), address=0, target=target, tid=int(tid),
            symbol_index=idx,
        )

    def bp_clear(self, pid: int) -> dict:
        return self.controller.breakpoint_clear(int(pid))

    def _build_bp_index(self, pid: int, target: str):
        """给前端 / GUI 用的轻量级索引构造（解析失败返 None）。"""
        if not target or "!" not in target:
            return None
        import re as _re
        m = _re.match(r"\s*([^!\s]+)!", target or "")
        if not m:
            return None
        mod_name = m.group(1)
        try:
            info = self.controller.info([pid], no_exports=True, budget=0)
        except Exception:
            return None
        if not isinstance(info, list) or not info:
            return None
        modules = (info[0] or {}).get("modules", []) if isinstance(info[0], dict) else []
        from .symbols import build_module_index, merge_export_payload
        index = build_module_index(modules)
        found = next((k for k in index if k.lower() == mod_name.lower()), None)
        if not found:
            return index
        try:
            resp = self.controller.exports(int(pid), name=found, budget=512)
            if resp and resp.get("ok"):
                merge_export_payload(index, found, resp)
        except Exception:
            pass
        return index

    # -------------------------------------------------- 事件（崩溃 / patch / 断点）

    def list_events(self, pid: int = 0, name: str = "",
                    clear: bool = False) -> list:
        return self.controller.list_events(
            int(pid) if pid else None,
            name=name or None, clear=bool(clear),
        )

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

    # -------------------------------------------------- MCP 授权（v1.3.0 P5）

    def submit_consent(self, payload: dict) -> dict:
        """接前端授权表单 → 构造签名会话并落盘。

        表单字段（``consent.html`` / 主窗口模态框回传）：

        * ``pids``：逗号分隔 PID 白名单；
        * ``names``：逗号分隔进程名通配（大小写不敏感）；
        * ``capabilities``：能力分档列表（``read`` / ``write`` / ``dangerous``）；
        * ``ttl_seconds``：有效期秒数（缺省 30 分钟）。

        成功返回 ``{ok, summary, expires_at, path}``；任何校验 / 落盘失败返回
        ``{ok: False, error}`` 且**不落盘**（落盘在 ``save_consent`` 里是原子写，
        校验失败根本走不到那步）。
        """
        try:
            session = mcp_consent.session_from_form(payload or {})
        except mcp_consent.ConsentError as exc:
            return {"ok": False, "error": str(exc)}
        except (TypeError, ValueError) as exc:
            return {"ok": False, "error": f"表单格式错误: {exc}"}
        if not session.pid_allowlist and not session.name_glob:
            return {"ok": False,
                    "error": "PID 白名单与进程名通配不能同时为空（否则放行一切目标）"}
        try:
            path = mcp_consent.save_consent(session)
        except OSError as exc:
            return {"ok": False, "error": f"授权落盘失败: {exc}"}
        return {
            "ok": True,
            "summary": session.targets_summary(),
            "expires_at": session.expires_at,
            "path": str(path),
        }

    def mcp_status(self) -> dict:
        """MCP 授权 + 内嵌命名管道服务的当前状态（前端状态栏用）。

        consent 三态：``none``（无授权文件）/ ``valid``（有效）/ ``expired``
        （文件在但已过期或签名对不上）。

        ``server.running`` 反映 **真实的** :class:`~superinject.mcp_pipe.PipeBridgeServer`
        状态（v1.3.0 P6）：启用后 Agent 可用 ``SuperInject.exe mcp-launcher`` 无 UAC
        连接本进程；未启用时为 ``False``。
        """
        from .mcp_pipe import PIPE_NAME

        session = mcp_consent.load_consent()
        valid = session is not None and mcp_consent.is_valid(session)
        if session is None:
            state = "none"
        elif valid:
            state = "valid"
        else:
            state = "expired"
        consent = {
            "state": state,
            "valid": valid,
            "summary": session.targets_summary() if session else "",
            "expires_at": float(session.expires_at) if session else 0.0,
            "created_at": float(session.created_at) if session else 0.0,
            "capabilities": sorted(session.capabilities) if session else [],
            "pid_allowlist": sorted(session.pid_allowlist) if session else [],
            "name_glob": list(session.name_glob) if session else [],
        }
        server_obj = self._mcp_server
        running = bool(server_obj is not None and server_obj.running)
        return {
            "consent": consent,
            "server": {
                "running": running,
                "transport": "pipe",
                "pipe": PIPE_NAME,
                "launcher": "SuperInject.exe mcp-launcher",
                "note": "启用后 Agent 可用 `SuperInject.exe mcp-launcher` 无 UAC "
                        "连接本进程；直接跑 `SuperInject.exe mcp` 会走 UAC",
            },
        }

    def start_mcp_service(self, backend=None) -> dict:
        """启用内嵌命名管道服务：Agent 可用 ``SuperInject.exe mcp-launcher`` 无 UAC 连接。

        要求已有**有效**的 MCP 授权（consent）；无授权返回 ``{ok: False, error}``。
        连接受连接与每条连接的服务都在后台线程，**不阻塞 GUI 主线程**。

        ``backend`` 仅供测试注入（如 :class:`~superinject.mcp_pipe.SocketPipeBackend`）；
        前端调用时留空 → 按平台取默认后端（Windows 走 Win32 命名管道）。
        """
        from .mcp_pipe import PIPE_NAME, PipeBridgeServer

        session = mcp_consent.load_consent()
        if session is None or not mcp_consent.is_valid(session):
            return {"ok": False,
                    "error": "无有效 MCP 授权：请先点「授权…」再启用服务"}
        if self._mcp_server is not None and self._mcp_server.running:
            return {"ok": True, "running": True, "pipe": PIPE_NAME,
                    "note": "MCP 命名管道服务已在运行"}
        server = PipeBridgeServer(session, self.controller, backend=backend)
        try:
            server.start()
        except Exception as exc:  # 起监听失败（权限 / 名字被占等）
            return {"ok": False, "error": f"启动命名管道失败: {exc}"}
        self._mcp_server = server
        self._emit("mcp-server", {"running": True, "pipe": PIPE_NAME})
        return {
            "ok": True, "running": True, "pipe": PIPE_NAME,
            "launcher": "SuperInject.exe mcp-launcher",
            "note": "已启用：Agent 可用 `SuperInject.exe mcp-launcher` 无 UAC 连接本进程",
        }

    def stop_mcp_service(self) -> dict:
        """停止内嵌命名管道服务（幂等）。"""
        server = self._mcp_server
        self._mcp_server = None
        if server is None:
            return {"ok": True, "running": False, "stopped": False}
        try:
            server.stop()
        except Exception as exc:
            return {"ok": False, "error": f"停止命名管道服务失败: {exc}"}
        self._emit("mcp-server", {"running": False})
        return {"ok": True, "running": False, "stopped": True}

    def mcp_config_snippet(self, mode: str = "launcher") -> str:
        """复用 ``cli.mcp_config_snippet()``：Agent 端 ``mcpServers`` 配置片段。

        默认 ``mode="launcher"``（无 UAC）；传 ``mode="direct"`` 得到直连版。
        """
        from .cli import mcp_config_snippet as _snippet

        return _snippet(mode="direct" if mode == "direct" else "launcher")

    # -------------------------------------------------- 写 Agent 配置（v1.3.0 P7）

    def list_agent_targets(self) -> list:
        """可写入的 Agent 配置目标：``[{id, label, path, exists}]``。

        只探测、不创建任何目录（``exists`` 只表示配置文件在不在）。
        """
        from . import mcp_config_writer

        return mcp_config_writer.targets()

    def write_agent_config(self, target_id: str, mode: str = "launcher") -> dict:
        """把 SuperInject 条目合并进某个 Agent 的配置文件。

        **只能由用户在界面上点确认后触发**（前端先弹确认框），后端不做任何
        自动 / 静默写入。返回 ``{ok, path, action, backup, entry, error?}``：
        合并写入、写前备份、坏 JSON 不动原文件、内容一致则 ``unchanged``。
        """
        from . import mcp_config_writer

        return mcp_config_writer.write_config(
            target_id, mode="direct" if mode == "direct" else "launcher")

    def revoke_consent(self) -> dict:
        """删除本地 consent 文件（清授权）。文件本就不存在也算成功。"""
        path = mcp_consent.consent_path()
        try:
            if path.exists():
                path.unlink()
                return {"ok": True, "removed": True, "path": str(path)}
        except OSError as exc:
            return {"ok": False, "error": f"删除授权失败: {exc}"}
        return {"ok": True, "removed": False, "path": str(path)}

    # -------------------------------------------------- 收尾

    def shutdown(self) -> None:
        try:
            if self._mcp_server is not None:
                self._mcp_server.stop()
                self._mcp_server = None
        except Exception:  # pragma: no cover
            pass
        try:
            self.preview.stop()
        except Exception:  # pragma: no cover
            pass
        try:
            self.controller.server.shutdown()
        except Exception:  # pragma: no cover
            pass


def create_window(api: Api):
    """创建 pywebview 窗口（供 __main__ 调用）。

    尺寸按屏幕可用区域自适应：小屏上不会再出现「窗口比屏幕大、底部看不到」
    的情况（曾经的固定 1280x820 / min 1040x640 就是这个毛病）。
    """
    import webview

    width, height = window_size(winapi.screen_work_area())
    log.info("GUI 窗口尺寸 %sx%s（屏幕可用区域 %s）", width, height,
             winapi.screen_work_area())
    return webview.create_window(
        APP_NAME,
        str(WEB_DIR / "index.html"),
        js_api=api,
        width=width, height=height, min_size=MIN_WINDOW,
    )


def start_kwargs(debug: bool = False) -> dict:
    """webview.start 的参数（按版本能力裁剪，避免 TypeError）。"""
    import inspect

    import webview

    kwargs: dict = {"debug": debug, "private_mode": False}
    try:
        params = inspect.signature(webview.start).parameters
    except (TypeError, ValueError):  # pragma: no cover - 极端版本
        params = {}
    if "storage_path" in params:
        path = storage_dir()
        try:
            path.mkdir(parents=True, exist_ok=True)
            kwargs["storage_path"] = str(path)
        except OSError:  # pragma: no cover
            log.debug("创建 WebView 存储目录失败，交回默认位置", exc_info=True)
    return kwargs


def run_gui(api: Api, window, debug: bool = False) -> None:
    import webview

    try:
        webview.start(**start_kwargs(debug))
    finally:
        api.shutdown()


def update_checker(api: Api) -> updater.UpdateChecker:
    """启动时的后台更新检查。"""
    return updater.UpdateChecker(on_found=lambda rel: api._emit(
        "update-available",
        {"version": rel.version, "url": rel.url, "notes": rel.notes,
         "asset": (rel.windows_asset() or {}).get("browser_download_url")},
    ))
