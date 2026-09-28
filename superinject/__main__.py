"""程序入口：执行启动自检，然后拉起 GUI（或跑无界面自检）。"""

from __future__ import annotations

import ctypes
import logging
import os
import sys

from . import dll_manager, elevate
from .version import APP_NAME, __version__

log = logging.getLogger("supinject")

BANNER = r"""
  ____        _         _____           _
 / ___|      | |       |_   _|         | |
 \___ \ _ __ | |_        | || |____ _ __| |_ __ _ _ __
  ___) | '_ \| __|       | || / _ \ '__| __/ _` | '_ \
 |____/| | | | |_        | ||  __/ |  | || (_| | | | |
       |_| |_| \__|       |_|\___|_|   |__\__,_|_| |_|
"""

USAGE = """用法: SuperInject [选项]

  （无参数）        执行启动自检并拉起图形界面
  --self-test      无界面自检：真跑一遍「校验 DLL → 注入 → 控制 → 卸载 → 终止」
  --report PATH    自检报告输出路径（默认写在程序目录下的 self-test-report.json）
  --keep-target    自检结束后保留目标进程（默认回收）
  -h, --help       显示本帮助

⚠️ 仅供开发人员调试程序使用，严禁滥用，违规使用者后果自负！
"""


def _console() -> bool:
    if getattr(sys, "frozen", False):
        return False
    return sys.stdout is not None and sys.stdout.isatty()


def setup_logging() -> None:
    handlers: list[logging.Handler] = []
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
        force=True,
    )


def _set_app_user_model_id() -> None:
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Mofan2020.SuperInject.1")
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    setup_logging()
    log.info("%s %s 启动, pid=%s, argv=%s", APP_NAME, __version__, os.getpid(), argv)

    if "-h" in argv or "--help" in argv:
        print(USAGE)
        return 0

    # ---- 无界面自检：供 CI 与用户验证打包产物
    if "--self-test" in argv:
        from . import selftest

        return selftest.run(argv)

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

    from .gui import Api, create_window, run_gui, update_checker

    api_holder: dict = {}
    api = Api(api_holder)
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
        import webview  # noqa: F401
    except ImportError:
        print("缺少依赖 pywebview，请先执行: pip install pywebview pywin32")
        return 2

    _set_app_user_model_id()
    window = create_window(api)
    api_holder["window"] = window

    # ---- 后台检查更新
    update_checker(api).start(delay=1.5)

    print(f"[启动] GUI 已启动  版本 {__version__}")
    run_gui(api, window, debug=_console())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
