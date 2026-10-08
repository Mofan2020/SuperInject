"""命令行模式（``-c``）入口。

提供「进程列表 / 注入 / 控制 / 内存读写 / 资源 / 卸载 / 终止」等操作的 CLI 入口，
输出默认走 ``--json`` 才切结构化，否则是 plain text。设计目的是让 Agent 与
自动化脚本可以稳定地驱动本工具，而不是每次都要开 GUI。

约定：

* ``-c``           启动 CLI 模式（不再拉起 GUI）。所有 ``<command>`` 由后续参数传入。
* ``-y``           一律同意免责申明/警告。需要 ``-c`` 同时存在才有效。
* ``-h`` / ``--help``  无需 ``-c`` 即可用，且不启动 GUI。
* ``--json``       输出结构化 JSON（默认 plain text）。
* ``--report PATH`` 把本条命令的执行报告写到文件（除 stdout 外）。

子命令集：

    list            列出进程（可按 --name / --path / --pid 过滤）
    preflight       注入检查（必须先过这一步）
    inject          注入一个或多个 PID（按目标位数自动选 DLL）
    freeze / unfreeze  冻结 / 解除（按 PID）
    info / ping     通过注入端查信息
    mem-search      内存搜索
    mem-read        读取（hex 输出）
    mem-write       写入
    unload / terminate
    open            资源管理器定位文件 / 打开目录
    status          当前控制器状态
    dll             DLL 自校验（强制释放 / 报告）

子命令风格优先（``si.exe -c -y inject 1234 5678``），但也支持把剩余参数
当作单串解析，便于写脚本时拼成一条命令（``si.exe -c -y 'inject 1234 --json'``）。
解析器对两种格式做兼容：sys.argv 第一个非 flag 之后的所有 token 视为子命令
正文，按空白切分即可。
"""

from __future__ import annotations

import argparse
import json
import logging
import shlex
import sys
from pathlib import Path
from typing import Any, List, Optional

from . import dll_manager, winapi
from .console import safe_print
from .controller import Controller
from .version import APP_NAME

log = logging.getLogger("supinject.cli")


HELP_TEXT = """\
用法: SuperInject -c -y <command>           # CLI 模式（Agent 友好）
       SuperInject -h | --help            # 帮助（无需 -c）
       SuperInject [其他参数]              # GUI 模式（保持原行为）

选项:
  -c                 启动 CLI 模式（必需；后面必须跟 <command>）
  -y                 一律同意所有免责申明/警告；需要 -c 存在才生效
  -h, --help         显示本帮助；不启动 GUI
  --json             输出结构化 JSON（默认 plain text）
  --report PATH      把命令执行报告（dict）写到 PATH
  --no-system        仅以管理员运行（跳过 SYSTEM 提权）
  --as-admin         同 --no-system

子命令:
  list [--name S] [--path P] [--pid N]
  preflight [--pid N]...
  inject [--pid N]... [--arch {x64|x86}]
  freeze / unfreeze --pid N...
  info / ping --pid N...
  mem-search --pid N --pattern HEX [--max N]
  mem-read --pid N --address 0xA --size N
  mem-write --pid N --address 0xA --hex "DE AD BE EF"
  unload --pid N...
  terminate --pid N...
  open PATH
  status
  dll [--force]

示例:
  SuperInject -c -y list --path "C:\\Program Files\\Google\\Chrome\\Application"
  SuperInject -c -y inject 1234
  SuperInject -c -y freeze --pid 1234
  SuperInject -c -y mem-read --pid 1234 --address 0x401000 --size 64
  SuperInject -c -y 'inject 1234 --json'

⚠️ 本工具仅供开发人员调试程序使用，严禁滥用，违规使用者后果自负！
"""


def _is_yes(argv: List[str]) -> bool:
    return "-y" in argv or "--yes" in argv


def parse(argv: List[str]) -> tuple[argparse.Namespace, Optional[str], List[str]]:
    """把 ``argv`` 解析成结构化参数（不跑业务）。

    返回 (顶层参数, 子命令名, 子命令剩余参数)。
    顶层只识别 ``-c`` / ``-y`` / ``-h``；输出格式相关 flag（``--json`` / ``--report`` /
    ``--no-system`` / ``--as-admin``）从原 argv 中**插值提取**，允许出现在
    ``<command>`` 之前或之后；其余传给子命令解析器。

    子命令参数用二次 ``argparse`` 解析，``build_subparser`` 见 ``_build_subparser``。
    """
    ns, rest = _pre_parser().parse_known_args(argv)

    # 提取顶层输出 / 提权相关的 flag（位置无要求）
    extra = argparse.Namespace(json=False, report="", no_system=False,
                               as_admin=False)
    cleaned: list[str] = []
    i = 0
    while i < len(rest):
        a = rest[i]
        if a == "--json":
            extra.json = True
        elif a == "--report":
            if i + 1 < len(rest):
                extra.report = rest[i + 1]
                i += 1
        elif a == "--no-system":
            extra.no_system = True
        elif a == "--as-admin":
            extra.as_admin = True
        else:
            cleaned.append(a)
        i += 1

    # 把 extra 合并进 ns，方便外部像读 ns.json / ns.report 那样取
    for k, v in vars(extra).items():
        setattr(ns, k, v)

    sub = None
    sub_args: list[str] = []
    if cleaned:
        # 支持「单串 DSL」：``si.exe -c -y 'inject 1234 --json'``
        # 此时 cleaned == ['inject 1234 --json']，再 shlex 切一次。
        if len(cleaned) == 1 and " " in cleaned[0]:
            try:
                cleaned = shlex.split(cleaned[0])
            except ValueError:
                pass
        sub = cleaned[0]
        sub_args = cleaned[1:]
    return ns, sub, sub_args


def _pre_parser() -> argparse.ArgumentParser:
    """最顶层解析器：只识别 ``-c`` / ``-y`` / ``-h``，其余一律交给子命令。"""
    p = argparse.ArgumentParser(prog=APP_NAME, add_help=False)
    p.add_argument("-c", "--cli", action="store_true",
                   help="CLI 模式（不拉起 GUI）")
    p.add_argument("-y", "--yes", action="store_true",
                   help="同意所有免责申明")
    p.add_argument("-h", "--help", action="store_true",
                   help="显示帮助")
    return p


def _build_subparser() -> argparse.ArgumentParser:
    """子命令解析器（依赖 ``-c`` 已经被识别）。"""
    p = argparse.ArgumentParser(prog=APP_NAME, add_help=False)
    sub = p.add_subparsers(dest="cmd", required=False)

    def add_pid_filter(sp, allow_positional: bool = False):
        sp.add_argument("--pid", type=int, action="append", default=[],
                        help="按 PID 过滤（可重复）")
        if allow_positional:
            sp.add_argument("pids", nargs="*", type=int, default=[],
                            help="PID（位置参数）")
        sp.add_argument("--name", default="",
                        help="按进程名过滤（不区分大小写、子串匹配）")
        sp.add_argument("--path", default="",
                        help="按进程路径过滤（不区分大小写、子串匹配）")

    def add_pid_positional(sp, *, allow_positional: bool = True):
        sp.add_argument("--pid", type=int, action="append", default=[],
                        help="PID（可重复）")
        if allow_positional:
            sp.add_argument("pids", nargs="*", type=int, default=[],
                            help="PID（位置参数）")

    sp = sub.add_parser("list", help="列出进程")
    add_pid_filter(sp, allow_positional=True)
    sp.add_argument("--injected-only", action="store_true",
                    help="只显示已注入的进程")

    sp = sub.add_parser("preflight", help="注入检查")
    add_pid_filter(sp, allow_positional=True)

    sp = sub.add_parser("inject", help="注入")
    add_pid_filter(sp, allow_positional=True)
    sp.add_argument("--arch", choices=("x64", "x86"),
                    help="强制使用某一位数的 DLL（默认按目标进程自动判定）")

    sp = sub.add_parser("freeze", help="冻结进程")
    add_pid_positional(sp)
    sp = sub.add_parser("unfreeze", help="解除冻结")
    add_pid_positional(sp)
    sp = sub.add_parser("info", help="查询模块列表")
    add_pid_positional(sp)
    sp = sub.add_parser("ping", help="连通性自检")
    add_pid_positional(sp)
    sp = sub.add_parser("unload", help="卸载注入的 DLL")
    add_pid_positional(sp)
    sp = sub.add_parser("terminate", help="终止进程（让 DLL 内 ExitProcess）")
    add_pid_positional(sp)

    sp = sub.add_parser("mem-search", help="按模式扫描内存")
    sp.add_argument("--pid", type=int, required=True)
    sp.add_argument("--pattern", required=True,
                    help="十六进制模式，如 '4D 5A ?? ??'")
    sp.add_argument("--max", type=int, default=64)

    sp = sub.add_parser("mem-read", help="读取内存")
    sp.add_argument("--pid", type=int, required=True)
    sp.add_argument("--address", required=True,
                    help="起始地址（支持 0x 前缀与十进制）")
    sp.add_argument("--size", type=int, default=64)

    sp = sub.add_parser("mem-write", help="写入内存")
    sp.add_argument("--pid", type=int, required=True)
    sp.add_argument("--address", required=True,
                    help="起始地址（支持 0x 前缀与十进制）")
    sp.add_argument("--hex", required=True, help="写入字节的十六进制串")

    sp = sub.add_parser("open", help="资源管理器定位文件")
    sp.add_argument("path")

    sp = sub.add_parser("status", help="控制器状态")
    sp = sub.add_parser("dll", help="DLL 自校验")
    sp.add_argument("--force", action="store_true")

    return p


def _subparser_for(cmd: str) -> argparse.ArgumentParser:
    """从 ``_build_subparser()`` 拿单个子命令的解析器。

    用 argparse 私有 API 是因为它没有公开的「只解析单个 subparser」入口。
    私有 API 在 CPython 3.x 各版本稳定。
    """
    p = _build_subparser()
    sub_action = p._subparsers._group_actions[0]  # type: ignore[attr-defined]
    choices = sub_action.choices  # type: ignore[union-attr]
    if choices is None or cmd not in choices:
        raise KeyError(cmd)
    return choices[cmd]  # type: ignore[index]


def _parse_sub(cmd: str, sub_args: List[str]) -> argparse.Namespace:
    parser = _subparser_for(cmd)
    return parser.parse_args(sub_args)


def _normalize_pids(args) -> List[int]:
    out: list[int] = []
    for pid in (getattr(args, "pid", []) or []):
        if pid and pid not in out:
            out.append(pid)
    if hasattr(args, "pids") and args.pids:
        for pid in args.pids:
            if pid and pid not in out:
                out.append(pid)
    return out


def _filter_processes(items, args) -> list:
    name = (getattr(args, "name", "") or "").strip().lower()
    path = (getattr(args, "path", "") or "").strip().lower()
    pids = set(getattr(args, "pid", []) or [])
    injected_only = bool(getattr(args, "injected_only", False))

    out = []
    for it in items:
        if name and name not in str(it.get("name", "")).lower():
            continue
        if path and path not in str(it.get("path", "")).lower():
            continue
        if pids and int(it.get("pid", 0)) not in pids:
            continue
        if injected_only and not it.get("injected"):
            continue
        out.append(it)
    return out


def _dump_payload(payload: Any, json_mode: bool, report_path: str = "") -> int:
    """把执行结果打印出去；返回退出码。"""
    if report_path:
        try:
            Path(report_path).write_text(
                json.dumps(payload, ensure_ascii=False, indent=2),
                encoding="utf-8")
        except OSError as exc:
            safe_print(f"[cli] 报告写盘失败 {report_path}: {exc}", "stderr")
    if json_mode:
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        safe_print(text, "stdout")
        if isinstance(payload, dict):
            return 0 if payload.get("ok", True) else 2
        return 0
    return _dump_plain(payload)


def _dump_plain(payload: Any) -> int:
    """``--json`` 没给时的默认格式。"""
    failed = False
    if isinstance(payload, dict):
        ok = payload.get("ok", True)
        if ok is False:
            failed = True
        kind = payload.get("kind") or payload.get("type") or "result"
        safe_print(f"[{kind}] {'OK' if not failed else 'FAIL'}  "
                   f"{payload.get('message') or payload.get('error') or '-'}")
        for k in ("count", "version", "privilege"):
            if k in payload:
                safe_print(f"  {k}: {payload[k]}")
        for arr_key in ("items", "results", "regions", "modules"):
            arr = payload.get(arr_key)
            if isinstance(arr, list):
                safe_print(f"  {arr_key} ({len(arr)}):")
                for x in arr[:10]:
                    safe_print(f"    - {x}")
                if len(arr) > 10:
                    safe_print(f"    ... 还有 {len(arr) - 10} 条")
        for k, v in payload.items():
            if k in {"ok", "kind", "type", "message", "error",
                     "count", "version", "privilege", "items", "results",
                     "regions", "modules"}:
                continue
            safe_print(f"  {k}: {v}")
    elif isinstance(payload, list):
        safe_print(f"[list] {len(payload)} 条")
        for it in payload[:20]:
            safe_print(f"  - {it}")
        if len(payload) > 20:
            safe_print(f"  ... 还有 {len(payload) - 20} 条")
    else:
        safe_print(str(payload))
    return 2 if failed else 0


def _ensure_controller(dll_path: Optional[Path] = None) -> Controller:
    c = Controller()
    if dll_path is not None:
        c.dll_path = dll_path
    return c


def _resolve_dll_for_pid(ctrl: Controller, pid: int, arch: str = "") -> tuple[Optional[Path], str]:
    """挑 DLL：先看 arch 强制，否则看目标位数。

    返回 (path, chosen_arch)。path 为 None 表示该位数暂未内嵌。
    """
    target_arch = (arch or "").strip().lower()
    if not target_arch:
        wow = winapi.is_wow64(pid)
        target_arch = "x86" if wow else "x64"
    path = dll_manager.dll_for_arch(target_arch)
    return path, target_arch


def _check_yes_or_exit(yes: bool) -> int:
    if yes:
        return 0
    safe_print("[cli] ⚠️ 本工具仅供开发人员调试程序使用，严禁滥用！")
    safe_print("[cli] 如已了解并继续，请加 -y 一律同意（本提示将不再出现）。")
    return 3


def _skip_elevation() -> bool:
    """测试用：跳过 elevate.ensure_privilege 调用。"""
    return False


def _ensure_elevation(argv: List[str], want_system: bool):
    """统一调用 elevate；返回 ElevationResult。

    之所以包一层：CLI 的提权流程与 GUI 共用同一份实现；为了让测试能在
    非 Windows 下也跑，把 ``elevate.ensure_privilege`` 隔离出来用桩替换。
    """
    from . import elevate as _elev
    eargv = list(argv)
    if not want_system and not any(a in _elev.NO_SYSTEM_FLAGS for a in eargv):
        eargv.append("--as-admin")
    return _elev.ensure_privilege(eargv, auto_relaunch=True,
                                  want_system=want_system)


def run(argv: Optional[List[str]] = None) -> int:
    """CLI 主入口。返回退出码。"""
    argv = list(sys.argv[1:] if argv is None else argv)

    # 顶层帮助无需 -c
    if argv and argv[0] in ("-h", "--help"):
        safe_print(HELP_TEXT)
        return 0

    pre, sub, sub_args = parse(argv)
    if not pre.cli:
        # 没有 -c 时不该走这里；上游 __main__ 已经分流。
        safe_print("[cli] 缺少 -c；如需 CLI 模式请加 -c；否则不要传 -c")
        return 64

    if sub is None:
        safe_print("[cli] -c 已设置，但缺少子命令。可用：list / inject / freeze / "
                   "mem-read / ... （-h 看帮助）")
        return 64

    rc = _check_yes_or_exit(pre.yes)
    if rc:
        return rc

    if not winapi.IS_WINDOWS:
        safe_print("[cli] 仅 Windows 可用", "stderr")
        return 4

    # ---- 提权：CLI 也需要管理员/SYSTEM 才能注入。
    if not _skip_elevation():
        want_system = not (pre.no_system or pre.as_admin)
        elev = _ensure_elevation(argv, want_system)
        if elev.relaunched:
            safe_print(f"[cli] {elev.message}")
            log.info("CLI 已重新启动（%s），退出当前进程", elev.message)
            return 0
        if not elev.ok:
            safe_print("[cli] " + elev.message, "stderr")
            log.error("CLI 权限自检失败: %s", elev.message)
            return 1
        if elev.degraded:
            safe_print(f"[cli] {elev.message}  原因: {elev.reason or '-'}")

    # 顶层提取完成后检查子命令是否已知；未知的给友好提示而不是 KeyError。
    try:
        args = _parse_sub(sub, sub_args)
    except KeyError:
        payload = {"ok": False, "kind": "error",
                   "error": f"未知子命令: {sub!r}（-h 看帮助）"}
        return _dump_payload(payload, pre.json, pre.report)

    try:
        payload = _dispatch(sub, args, pre)
    except KeyboardInterrupt:
        safe_print("[cli] 用户中断", "stderr")
        return 130
    except SystemExit:
        # argparse 解析失败时自己 exit 2 —— 把 usage 转成 dict 排版展示。
        return 2
    except Exception as exc:  # pragma: no cover - 兜底必有报告
        log.exception("CLI 异常")
        payload = {"ok": False, "kind": "error", "error": f"{type(exc).__name__}: {exc}"}

    return _dump_payload(payload, pre.json, pre.report)


def _dispatch(sub: str, args: argparse.Namespace, pre) -> Any:
    if sub in ("list", "preflight"):
        ctrl = _ensure_controller()
        if sub == "list":
            items = ctrl.list_processes()
            items = _filter_processes(items, args)
            return items
        pids = _normalize_pids(args)
        if not pids:
            return {"ok": False, "kind": "preflight",
                    "error": "缺少 --pid"}
        return ctrl.preflight(pids)

    if sub == "inject":
        pids = _normalize_pids(args)
        if not pids:
            return {"ok": False, "kind": "inject", "error": "缺少 --pid"}
        ctrl = _ensure_controller()
        arch = getattr(args, "arch", "") or ""
        # 对每个 PID 分别挑 DLL，再按目标 DLL 分组批量注入
        groups: dict[str, list[int]] = {}
        for pid in pids:
            _, a = _resolve_dll_for_pid(ctrl, pid, arch)
            groups.setdefault(a, []).append(pid)
        out: list[dict] = []
        for a, pids_a in groups.items():
            ctrl_a = _ensure_controller(dll_manager.dll_for_arch(a))
            out.extend(ctrl_a.inject(pids_a, dll_path=str(ctrl_a.dll_path)
                                     if ctrl_a.dll_path else None))
        return {"ok": all(r.get("ok") for r in out), "kind": "inject",
                "count": len(out), "results": out}

    if sub == "freeze":
        return {"ok": True, "kind": "freeze",
                "results": _ensure_controller().freeze(_normalize_pids(args))}
    if sub == "unfreeze":
        return {"ok": True, "kind": "unfreeze",
                "results": _ensure_controller().unfreeze(_normalize_pids(args))}
    if sub == "ping":
        return {"ok": True, "kind": "ping",
                "results": _ensure_controller().ping(_normalize_pids(args))}
    if sub == "info":
        return {"ok": True, "kind": "info",
                "results": _ensure_controller().info(_normalize_pids(args))}
    if sub == "unload":
        return {"ok": True, "kind": "unload",
                "results": _ensure_controller().unload(_normalize_pids(args))}
    if sub == "terminate":
        return {"ok": True, "kind": "terminate",
                "results": _ensure_controller().terminate(_normalize_pids(args))}

    if sub == "mem-search":
        return {"ok": True, "kind": "mem-search",
                "results": _ensure_controller().mem_search(
                    [int(args.pid)], args.pattern, int(args.max))}
    if sub == "mem-read":
        from .ipc import parse_int
        return _ensure_controller().mem_read(int(args.pid),
                                             parse_int(str(args.address)),
                                             int(args.size))
    if sub == "mem-write":
        from .ipc import parse_int
        return _ensure_controller().mem_write(int(args.pid),
                                              parse_int(str(args.address)),
                                              str(args.hex))

    if sub == "open":
        ok = _ensure_controller().open_path(args.path)
        return {"ok": ok, "kind": "open", "path": args.path}

    if sub == "status":
        return _ensure_controller().status()

    if sub == "dll":
        rep = dll_manager.verify_and_sync(force=bool(args.force))
        return {"ok": rep.ok, "kind": "dll", "action": rep.action,
                "message": rep.message,
                "embedded_sha": rep.embedded_sha, "disk_sha": rep.disk_sha,
                "path": str(rep.path)}

    return {"ok": False, "kind": "error",
            "error": f"未知子命令: {sub!r}（-h 看帮助）"}
