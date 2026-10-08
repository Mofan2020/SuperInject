"""程序入口：执行启动自检，然后拉起 GUI（或跑无界面自检）。"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import sys
from pathlib import Path

from . import dll_manager, elevate
from .console import safe_print
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

  （无参数）        执行启动自检，提权到 SYSTEM 并拉起图形界面
  --as-admin       只提到管理员，不提权到 SYSTEM（调试普通进程时用）
  --self-test      无界面自检：真跑一遍「校验 DLL → 注入 → 控制 → 卸载 → 终止」
  --report PATH    自检报告输出路径（默认写在程序目录下的 self-test-report.json）
  --keep-target    自检结束后保留目标进程（默认回收）
  --system-probe F 以当前身份把身份信息写到文件 F 后退出（自检内部使用）
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


def run_system_probe(argv: list[str]) -> int:
    """``--system-probe <文件>``：把当前进程的身份写盘后退出。

    自检用它来证明「SYSTEM 提权真的创建出了一个 SYSTEM 进程」：
    父进程以 SYSTEM 拉起自己并带上这个参数，子进程只汇报身份，不启动 GUI。
    """
    out = ""
    for i, a in enumerate(argv):
        if a == "--system-probe" and i + 1 < len(argv):
            out = argv[i + 1]
    from . import system_token

    data = system_token.probe_identity()
    if not out:
        return 0
    path = Path(out)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2),
                        encoding="utf-8")
    except OSError as exc:  # pragma: no cover
        log.error("写入身份文件失败 %s: %s", path, exc)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    setup_logging()
    log.info("%s %s 启动, pid=%s, argv=%s", APP_NAME, __version__, os.getpid(), argv)

    # ---- 帮助：-h / --help 直接给文字退出，不进入任何业务路径
    if "-h" in argv or "--help" in argv:
        from . import cli
        safe_print(cli.HELP_TEXT)
        return 0

    # ---- CLI 模式：-c 单独走 cli.run()，不再拉 GUI；提升权等均交给 CLI 自己处理
    if "-c" in argv or "--cli" in argv:
        from . import cli
        return cli.run(argv)

    # ---- 身份探针：任何权限下都要能跑，且必须在提权逻辑之前
    if "--system-probe" in argv:
        return run_system_probe(argv)

    # ---- 无界面自检：供 CI 与用户验证打包产物
    if "--self-test" in argv:
        from . import selftest

        return selftest.run(argv)

    # ---- 自检1：权限（普通用户 → UAC；管理员 → SYSTEM）
    elev = elevate.ensure_privilege(argv, auto_relaunch=True)
    if elev.relaunched:
        safe_print(f"[自检1] {elev.message}")
        log.info("已重新启动（%s），退出当前进程", elev.message)
        return 0
    if not elev.ok:
        safe_print("[自检1] " + elev.message)
        log.error("权限自检失败: %s", elev.message)
        return 1
    if elev.degraded:
        safe_print(f"[自检1] {elev.message}")
        safe_print(f"        {elev.reason}")
        log.warning("SYSTEM 提权降级: %s / %s", elev.message, elev.reason)
    else:
        safe_print(f"[自检1] 权限自检通过（{elev.identity}）")

    # ---- 自检2：DLL 校验（SHA256 全部运行时自动计算）
    report = dll_manager.verify_and_sync()

    from .gui import Api, create_window, run_gui, update_checker

    api_holder: dict = {}
    api = Api(api_holder)
    api.elevation = elev.to_dict()
    api.dll_report = {
        "ok": report.ok, "action": report.action, "path": str(report.path),
        "embedded_sha": report.embedded_sha, "disk_sha": report.disk_sha,
        "message": report.message,
    }
    safe_print(f"[自检2] {report.message}")
    if not report.ok:
        safe_print("        " + report.message)

    # ---- 拉起 GUI
    try:
        import webview  # noqa: F401
    except ImportError:
        safe_print("缺少依赖 pywebview，请先执行: pip install pywebview pywin32")
        return 2

    _set_app_user_model_id()
    window = create_window(api)
    api_holder["window"] = window

    # ---- 后台检查更新
    update_checker(api).start(delay=1.5)

    safe_print(f"[启动] GUI 已启动  版本 {__version__}")
    run_gui(api, window, debug=_console())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
