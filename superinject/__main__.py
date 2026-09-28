"""程序入口：执行启动自检，然后拉起 GUI。"""

from __future__ import annotations

import ctypes
import logging
import os
import sys

from . import dll_manager, elevate
from .gui import WEB_DIR, Api
from .version import APP_NAME, __version__

BANNER = r"""
  ____        _         _____           _
 / ___|      | |       |_   _|         | |
 \___ \ _ __ | |_        | || |____ _ __| |_ __ _ _ __
  ___) | '_ \| __|       | || / _ \ '__| __/ _` | '_ \
 |____/| | | | |_        | ||  __/ |  | || (_| | | | |
       |_| |_|\__|       |_|\___|_|   |__\__,_|_| |_|
"""


def _console() -> bool:
    if getattr(sys, "frozen", False):
        return False
    return sys.stdout is not None and sys.stdout.isatty()


def setup_logging() -> None:
    handlers = []
    log_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.getcwd()), "SuperInject")
    try:
        os.makedirs(log_dir, exist_ok=True)
        handlers.append(logging.FileHandler(
            os.path.join(log_dir, "supinject.log"), encoding="utf-8"))
    except OSError:
        pass
    if _console():
        handlers.append(logging.StreamHandler())
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers or [logging.NullHandler()],
    )


def _set_app_user_model_id() -> None:
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Mofan2020.SuperInject.1")
    except Exception:
        pass


def main() -> int:
    setup_logging()
    log.info("%s %s 启动, pid=%s", APP_NAME, __version__, os.getpid())

    # ---- 自检1：权限（管理员 / SYSTEM）
    elev = elevate.ensure_admin(auto_relaunch=True)
    if not elev.ok:
        print("[自检1] " + elev.message)
        log.error("权限自检失败: %s", elev.message)
        return 1
    if elev.relaunched:
        log.info("已请求 UAC 提权，退出当前进程")
        return 0
    print(f"[自检1] 权限自检通过（{elev.identity}）")

    # ---- 自检2：DLL 校验（SHA256 全部运行时自动计算）
    report = dll_manager.verify_and_sync()
    api_holder: dict = {}
    from .gui import Api as _Api  # 延迟构造，避免提前初始化管道

    api = _Api(api_holder)
    api.dll_report = {
        "ok": report.ok, "action": report.action, "path": str(report.path),
        "embedded_sha": report.embedded_sha, "disk_sha": report.disk_sha,
        "message": report.message,
    }
    print(f"[自检2] {report.message}")
    if not report.ok:
        print("        " + report.message)

    # ---- 拉起 GUI
    try:
        import webview
    except ImportError:
        print("缺少依赖 pywebview，请先执行: pip install pywebview pywin32")
        return 2

    _set_app_user_model_id()
    window = webview.create_window(
        APP_NAME,
        str(WEB_DIR / "index.html"),
        js_api=api,
        width=1280, height=820, min_size=(1040, 640),
    )
    api_holder["window"] = window

    # ---- 后台检查更新
    from . import updater

    checker = updater.UpdateChecker(on_found=lambda rel: api._emit(
        "update-available",
        {"version": rel.version, "url": rel.url, "notes": rel.notes,
         "asset": (rel.windows_asset() or {}).get("browser_download_url")},
    ))
    checker.start(delay=1.5)

    print(f"[启动] GUI 已启动  版本 {__version__}")
    webview.start(debug=_console(), private_mode=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
