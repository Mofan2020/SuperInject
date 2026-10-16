"""MCP 工具路由：把 :class:`~superinject.controller.Controller` 的方法映射成
MCP tool（name / description / inputSchema / capability / handler）。

分档（每个工具一个 ``capability``）：

* ``read``（会话自动授权）—— 枚举 / 读取 / 检查类，不改变目标状态（``inject``
  虽会加载 DLL，但按项目既定分档归入 read，与 CLI 的「注入是主流程」一致）；
* ``write``（需用户勾选）—— 会改变目标进程状态（写内存、冻结、patch、断点）；
* ``dangerous``（需用户勾选）—— 会终止目标进程。

两个硬约束：

1. **越权不抛异常** —— 能力不足或目标不在白名单时，返回结构化字典
   ``{"error": "consent_denied", "tool": ..., "capability": ...}``，让 MCP 客户端
   能看到拒绝原因而不是拿到一个栈回溯。
2. **description 面向 Agent** —— 写清「做什么 / 副作用 / 是否需要注入端在线」，
   不写免责声明（那属于 README）。

依赖：仅标准库 + 本项目模块（controller / mcp_consent / ipc / winapi / dll_manager）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import dll_manager, ipc, mcp_consent, winapi

if TYPE_CHECKING:  # pragma: no cover - 仅类型标注
    from .controller import Controller

Handler = Callable[["Controller", Dict[str, Any]], Any]


# --------------------------------------------------------------------------- schema 片段

_ADDR = {"type": ["integer", "string"],
         "description": "Address: decimal int or 0x-prefixed hex string."}
_PID = {"type": "integer", "description": "Target process id."}
_PIDS = {"type": "array", "items": {"type": "integer"},
         "description": "One or more target process ids."}


def _schema(properties: Dict[str, Any],
            required: Sequence[str] = ()) -> Dict[str, Any]:
    return {"type": "object", "properties": dict(properties),
            "required": list(required)}


# --------------------------------------------------------------------------- handler 辅助


def _arg_pids(args: Dict[str, Any]) -> List[int]:
    """合并 ``pid`` / ``pids`` 两种写法，保序去重。"""
    out: List[int] = []
    if args.get("pid") is not None and str(args.get("pid")).strip() != "":
        try:
            out.append(int(args["pid"]))
        except (TypeError, ValueError):
            pass
    for item in args.get("pids") or []:
        try:
            out.append(int(item))
        except (TypeError, ValueError):
            continue
    seen: set[int] = set()
    uniq: List[int] = []
    for pid in out:
        if pid not in seen:
            seen.add(pid)
            uniq.append(pid)
    return uniq


def _arg_int(args: Dict[str, Any], key: str, default: int = 0) -> int:
    value = args.get(key)
    if value is None or str(value).strip() == "":
        return default
    return int(value)


def _arg_addr(args: Dict[str, Any], key: str, default: int = 0) -> int:
    value = args.get(key)
    if value is None or str(value).strip() == "":
        return default
    return ipc.parse_int(str(value))


def _default_proc_name(pid: int) -> str:
    try:
        return winapi.process_name(pid) or ""
    except Exception:  # pragma: no cover - 目标已退出等
        return ""


# --------------------------------------------------------------------------- handlers: read


def _h_list_processes(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    """按 path/name/pid 过滤进程列表。透传给 controller，源头过滤
    （不再在 MCP 层做二次过滤 —— 之前是 controller API 太薄）。"""
    name = str(args.get("name") or "").strip()
    path = str(args.get("path") or "").strip()
    try:
        return ctrl.list_processes(
            name_substr=name,
            path_substr=path,
            arch=str(args.get("arch") or ""),
            only_injected=bool(args.get("only_injected", False)),
        )
    except TypeError:
        # 兼容老 controller（v1.3.0 之前 API 无 path_substr/arch）
        items = ctrl.list_processes()
        wanted = set(_arg_pids(args))
        out = []
        for it in items:
            if name and name.lower() not in str(it.get("name", "")).lower():
                continue
            if path and path.lower() not in str(it.get("path", "")).lower():
                continue
            if wanted and int(it.get("pid", 0)) not in wanted:
                continue
            out.append(it)
        return out


def _h_preflight(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.preflight(_arg_pids(args))


def _h_inject(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.inject(_arg_pids(args), arch=str(args.get("arch") or ""))


def _h_info(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.info(_arg_pids(args),
                     no_exports=bool(args.get("no_exports", False)),
                     budget=_arg_int(args, "budget", 64))


def _h_exports(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.exports(_arg_int(args, "pid"), name=str(args.get("name") or ""),
                        base=_arg_addr(args, "base"),
                        budget=_arg_int(args, "budget", 256))


def _h_threads(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.threads(_arg_int(args, "pid"))


def _h_mem_read(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.mem_read(_arg_int(args, "pid"), _arg_addr(args, "address"),
                         _arg_int(args, "size", 64))


def _h_mem_regions(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.mem_regions(_arg_int(args, "pid"))


def _h_resources(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.resources(_arg_pids(args))


def _h_events(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    pid = _arg_int(args, "pid", 0) or None
    return ctrl.list_events(pid=pid, name=str(args.get("name") or "") or None,
                            clear=bool(args.get("clear", False)))


def _h_dumps(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    pids = _arg_pids(args)
    if not pids:
        base = ipc.work_dir()
        if base.is_dir():
            pids = [int(d.name) for d in sorted(base.iterdir())
                    if d.is_dir() and d.name.isdigit()]
    items: List[dict] = []
    for pid in pids:
        directory = ipc.work_dir() / str(int(pid))
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("dump-*.dmp"),
                           key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                st = path.stat()
            except OSError:
                continue
            items.append({"pid": pid, "path": str(path), "size": st.st_size,
                          "mtime": int(st.st_mtime * 1000)})
    return items


def _h_status(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.status()


def _h_dll(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    report = dll_manager.verify_and_sync(force=bool(args.get("force", False)))
    return {"ok": report.ok, "action": report.action, "message": report.message,
            "embedded_sha": report.embedded_sha, "disk_sha": report.disk_sha,
            "path": str(report.path)}


def _h_ping(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.ping(_arg_pids(args))


def _h_list_handles(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    """枚举目标进程打开的句柄（lsof 视角）。

    返回结构见 ``Controller.list_handles``：``items``（扁平列表）+ ``by_category``
    （按 Win32 对象类型分到中文大类：文件/管道/设备/网络/注册表/同步/进程/内存/GUI）。
    """
    pids = _arg_pids(args)
    if not pids:
        return {"ok": False, "error": "list_handles 需要 pid"}
    return ctrl.list_handles(pids[0])


def _h_snapshot(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    regions = []
    for region in args.get("regions") or []:
        if isinstance(region, dict):
            regions.append({"base": ipc.parse_int(str(region.get("base", 0))),
                            "size": ipc.parse_int(str(region.get("size", 0)))})
    return ctrl.snapshot(_arg_int(args, "pid"), str(args.get("name") or ""),
                         regions=regions)


def _h_diff(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.diff(_arg_int(args, "pid"), str(args.get("a") or ""),
                     str(args.get("b") or ""), limit=_arg_int(args, "limit", 0))


# --------------------------------------------------------------------------- handlers: write


def _h_mem_write(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.mem_write(_arg_int(args, "pid"), _arg_addr(args, "address"),
                          str(args.get("hex") or ""))


def _h_mem_search(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.mem_search(_arg_pids(args), str(args.get("pattern") or ""),
                           _arg_int(args, "max", 256))


def _h_thread_suspend(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.thread_suspend(_arg_int(args, "pid"), _arg_int(args, "tid"))


def _h_thread_resume(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.thread_resume(_arg_int(args, "pid"), _arg_int(args, "tid"))


def _h_freeze(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.freeze(_arg_pids(args))


def _h_unfreeze(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.unfreeze(_arg_pids(args))


def _h_patch_inject(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.patch_inject(_arg_int(args, "pid"), _arg_addr(args, "address"),
                             str(args.get("hex") or ""))


def _h_patch_revert(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.patch_revert(_arg_int(args, "pid"), _arg_addr(args, "address"))


def _h_patch_clear(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.patch_clear(_arg_int(args, "pid"))


def _bp_args(args: Dict[str, Any]) -> Tuple[int, str]:
    target = str(args.get("target") or "").strip()
    address = 0
    if args.get("address") is not None and str(args.get("address")).strip() != "":
        address = ipc.parse_int(str(args["address"]))
    return address, target


def _h_breakpoint_set(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    address, target = _bp_args(args)
    return ctrl.breakpoint_set(_arg_int(args, "pid"), address=address,
                               target=target, tid=_arg_int(args, "tid"),
                               bp_type=str(args.get("type") or "exec"),
                               size=_arg_int(args, "size", 1))


def _h_breakpoint_list(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.breakpoint_list(_arg_int(args, "pid"))


def _h_breakpoint_remove(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    address, target = _bp_args(args)
    return ctrl.breakpoint_remove(_arg_int(args, "pid"), address=address,
                                  target=target, tid=_arg_int(args, "tid"))


def _h_breakpoint_clear(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.breakpoint_clear(_arg_int(args, "pid"))


def _h_unload(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.unload(_arg_pids(args))


# --------------------------------------------------------------------------- handlers: dangerous


def _h_terminate(ctrl: "Controller", args: Dict[str, Any]) -> Any:
    return ctrl.terminate(_arg_pids(args))


# --------------------------------------------------------------------------- 工具表


@dataclass(frozen=True)
class ToolSpec:
    """一条 MCP tool 定义。

    ``target_args`` 列出「携带目标 PID 的参数名」，:func:`call_tool` 会先按会话
    白名单逐个校验；不含目标的工具（如 ``status``）留空。
    """

    name: str
    description: str
    input_schema: Dict[str, Any]
    capability: str
    handler: Handler
    target_args: Tuple[str, ...] = ()


_TOOLS: Tuple[ToolSpec, ...] = (
    # ---------------------------------------------------------------- read
    ToolSpec(
        "list_processes",
        "List processes on the host, optionally filtered by name substring, "
        "path substring (case-insensitive — the **primary way to find a "
        "process by its image path**, e.g. by an .exe location or a parent "
        "directory), architecture (x64 / x86), or pid. Read-only; no side "
        "effects. Does not require the injector (target DLL) to be loaded.",
        _schema({"name": {"type": "string"},
                 "path": {"type": "string",
                           "description": "Case-insensitive substring of the "
                                          "process image path, e.g. "
                                          "'Program Files\\\\Google' or "
                                          "'C:\\\\Windows\\\\System32'."},
                 "arch": {"type": "string", "enum": ["x64", "x86"]},
                 "only_injected": {"type": "boolean"},
                 "pid": _PID, "pids": _PIDS}),
        "read", _h_list_processes,
    ),
    ToolSpec(
        "preflight",
        "Check whether each target pid can be injected (exists, arch match, "
        "openable, not a protected system process). Read-only probe, injects "
        "nothing. Use before inject. Does not require the injector online.",
        _schema({"pid": _PID, "pids": _PIDS}, ("pids",)),
        "read", _h_preflight, ("pid", "pids"),
    ),
    ToolSpec(
        "inject",
        "Inject the SuperInject agent DLL into the target pid(s) via "
        "CreateRemoteThread+LoadLibraryW and wait for the control channel. "
        "SIDE EFFECT: loads a DLL into the target and starts a background "
        "thread in it. Auto-selects x64/x86 DLL unless arch is given. Requires "
        "administrator/SYSTEM. Safe to call on an already-injected target "
        "(it unloads the old DLL first). Does not need the injector online "
        "beforehand.",
        _schema({"pid": _PID, "pids": _PIDS,
                 "arch": {"type": "string", "enum": ["x64", "x86"]}},
                ("pids",)),
        "read", _h_inject, ("pid", "pids"),
    ),
    ToolSpec(
        "info",
        "Return the target's module list (with optional export tables). "
        "Read-only. REQUIRES the injector to be online (call inject first) and "
        "the target to be responsive.",
        _schema({"pid": _PID, "pids": _PIDS,
                 "no_exports": {"type": "boolean"},
                 "budget": {"type": "integer"}}, ("pids",)),
        "read", _h_info, ("pid", "pids"),
    ),
    ToolSpec(
        "exports",
        "Return a single module's export table, selected by module name or "
        "base address. Read-only. REQUIRES the injector online.",
        _schema({"pid": _PID, "name": {"type": "string"}, "base": _ADDR,
                 "budget": {"type": "integer"}}, ("pid",)),
        "read", _h_exports, ("pid",),
    ),
    ToolSpec(
        "threads",
        "List all threads of the target process (tid, state, suspend count, "
        "name). Read-only. REQUIRES the injector online.",
        _schema({"pid": _PID}, ("pid",)),
        "read", _h_threads, ("pid",),
    ),
    ToolSpec(
        "mem_read",
        "Read raw bytes from the target address space, returned as hex. "
        "Read-only. REQUIRES the injector online.",
        _schema({"pid": _PID, "address": _ADDR, "size": {"type": "integer"}},
                ("pid", "address")),
        "read", _h_mem_read, ("pid",),
    ),
    ToolSpec(
        "mem_regions",
        "Return the target's virtual memory region map (base/size/protect/"
        "state). Read-only. REQUIRES the injector online.",
        _schema({"pid": _PID}, ("pid",)),
        "read", _h_mem_regions, ("pid",),
    ),
    ToolSpec(
        "resources",
        "Extract PE resources and memory-mapped media (images/audio/video) "
        "from the target; returns file paths and preview URLs. Read-only "
        "w.r.t. the target, but writes extracted files to disk. REQUIRES the "
        "injector online.",
        _schema({"pid": _PID, "pids": _PIDS}, ("pids",)),
        "read", _h_resources, ("pid", "pids"),
    ),
    ToolSpec(
        "events",
        "Read buffered controller events (crash dumps, patch landings, "
        "breakpoint hits). Read-only; set clear=true to drain the queue. "
        "Without pid, returns events for all processes. Does not require the "
        "injector online.",
        _schema({"pid": _PID, "name": {"type": "string"},
                 "clear": {"type": "boolean"}}),
        "read", _h_events, ("pid",),
    ),
    ToolSpec(
        "dumps",
        "List crash minidumps written under the SuperInject temp dir, "
        "optionally filtered by pid. Read-only. Does not require the injector "
        "online.",
        _schema({"pid": _PID, "pids": _PIDS}),
        "read", _h_dumps, ("pid", "pids"),
    ),
    ToolSpec(
        "status",
        "Return controller status: version, dll path, privilege, injected and "
        "frozen pid sets, arch, and which pids have a live control channel. "
        "Read-only, no target needed.",
        _schema({}),
        "read", _h_status,
    ),
    ToolSpec(
        "dll",
        "Self-check the agent DLL: recompute its SHA256 and compare with the "
        "embedded copy; set force=true to overwrite the on-disk DLL when they "
        "differ. SIDE EFFECT: may rewrite the DLL file on disk. No target "
        "needed.",
        _schema({"force": {"type": "boolean"}}),
        "read", _h_dll,
    ),
    ToolSpec(
        "ping",
        "Connectivity self-check against the injector in each target; returns "
        "round-trip success per pid. Read-only. REQUIRES the injector online.",
        _schema({"pid": _PID, "pids": _PIDS}, ("pids",)),
        "read", _h_ping, ("pid", "pids"),
    ),
    ToolSpec(
        "list_handles",
        "Enumerate the open handles of a target process (lsof-style view: "
        "files, pipes, devices, network sockets, registry keys, sync objects, "
        "process/thread handles, memory sections, GUI objects). Each entry "
        "carries the handle value, Win32 object type, full name (when the "
        "object has one), and access mask. Returns {items, by_category, count}. "
        "Read-only. REQUIRES the injector online.",
        _schema({"pid": _PID}, ("pid",)),
        "read", _h_list_handles, ("pid",),
    ),
    ToolSpec(
        "snapshot",
        "Take a memory snapshot of the target (4KB page SHA256 + first 64 "
        "bytes) and persist it to disk for later diff. SIDE EFFECT: writes a "
        "snapshot file under the SuperInject data dir. REQUIRES the injector "
        "online. Give a unique name; use diff to compare two snapshots.",
        _schema({"pid": _PID, "name": {"type": "string"},
                 "regions": {"type": "array",
                             "items": {"type": "object",
                                       "properties": {"base": _ADDR,
                                                      "size": _ADDR}}}},
                ("pid", "name")),
        "read", _h_snapshot, ("pid",),
    ),
    ToolSpec(
        "diff",
        "Compare two previously stored snapshots (by name) and return the "
        "changed pages with head64 hex before/after. Read-only. REQUIRES the "
        "injector online.",
        _schema({"pid": _PID, "a": {"type": "string"}, "b": {"type": "string"},
                 "limit": {"type": "integer"}}, ("pid", "a", "b")),
        "read", _h_diff, ("pid",),
    ),

    # ---------------------------------------------------------------- write
    ToolSpec(
        "mem_write",
        "Write the given hex bytes to the target address, temporarily "
        "flipping page protection if needed. SIDE EFFECT: mutates target "
        "memory (can modify code). REQUIRES the injector online.",
        _schema({"pid": _PID, "address": _ADDR, "hex": {"type": "string"}},
                ("pid", "address", "hex")),
        "write", _h_mem_write, ("pid",),
    ),
    ToolSpec(
        "mem_search",
        "Scan the target's memory for a hex pattern (supports ?? wildcards), "
        "e.g. '4D 5A ?? ??'. Read-only in effect but scans the whole address "
        "space, so it is classified as a write-capability operation. REQUIRES "
        "the injector online.",
        _schema({"pid": _PID, "pids": _PIDS, "pattern": {"type": "string"},
                 "max": {"type": "integer"}}, ("pattern",)),
        "write", _h_mem_search, ("pid", "pids"),
    ),
    ToolSpec(
        "thread_suspend",
        "Suspend a single thread of the target. SIDE EFFECT: freezes that "
        "thread until resumed. REQUIRES the injector online.",
        _schema({"pid": _PID, "tid": {"type": "integer"}}, ("pid", "tid")),
        "write", _h_thread_suspend, ("pid",),
    ),
    ToolSpec(
        "thread_resume",
        "Resume a single previously suspended thread. SIDE EFFECT: unfreezes "
        "that thread. REQUIRES the injector online.",
        _schema({"pid": _PID, "tid": {"type": "integer"}}, ("pid", "tid")),
        "write", _h_thread_resume, ("pid",),
    ),
    ToolSpec(
        "freeze",
        "Suspend ALL threads of each target process (NtSuspendProcess). SIDE "
        "EFFECT: the target becomes completely unresponsive until unfreeze. "
        "REQUIRES the injector online.",
        _schema({"pid": _PID, "pids": _PIDS}, ("pids",)),
        "write", _h_freeze, ("pid", "pids"),
    ),
    ToolSpec(
        "unfreeze",
        "Resume all threads of each previously frozen target. SIDE EFFECT: "
        "makes the target responsive again. REQUIRES the injector online.",
        _schema({"pid": _PID, "pids": _PIDS}, ("pids",)),
        "write", _h_unfreeze, ("pid", "pids"),
    ),
    ToolSpec(
        "patch_inject",
        "Install a trampoline code patch at the target address: writes a "
        "5-byte jump to a freshly allocated RWX stub then jumps back. SIDE "
        "EFFECT: modifies target code (up to 32 patches per process). REQUIRES "
        "the injector online.",
        _schema({"pid": _PID, "address": _ADDR, "hex": {"type": "string"}},
                ("pid", "address", "hex")),
        "write", _h_patch_inject, ("pid",),
    ),
    ToolSpec(
        "patch_revert",
        "Restore a single code patch to its original bytes and free its "
        "trampoline. SIDE EFFECT: rewrites target code. REQUIRES the injector "
        "online.",
        _schema({"pid": _PID, "address": _ADDR}, ("pid", "address")),
        "write", _h_patch_revert, ("pid",),
    ),
    ToolSpec(
        "patch_clear",
        "Restore ALL code patches in the target. SIDE EFFECT: rewrites target "
        "code. REQUIRES the injector online.",
        _schema({"pid": _PID}, ("pid",)),
        "write", _h_patch_clear, ("pid",),
    ),
    ToolSpec(
        "breakpoint_set",
        "Set a hardware breakpoint (DR0-DR3) on a thread, or a VEH-simulated "
        "one when slots run out. Target is an address (0x401000) or "
        "module!symbol+offset. tid=0 means process-wide VEH. SIDE EFFECT: "
        "alters threads' debug registers / patches code for VEH. Hit events "
        "are pushed to the event stream. REQUIRES the injector online.",
        _schema({"pid": _PID, "address": _ADDR, "target": {"type": "string"},
                 "tid": {"type": "integer"},
                 "type": {"type": "string",
                          "enum": ["exec", "read", "write", "rw"]},
                 "size": {"type": "integer", "enum": [1, 2, 4, 8]}},
                ("pid",)),
        "write", _h_breakpoint_set, ("pid",),
    ),
    ToolSpec(
        "breakpoint_list",
        "List all breakpoints currently installed in the target, with hit "
        "counts and hardware/VEH slot usage. Read-only in effect but grouped "
        "with the write-capability breakpoint tools. REQUIRES the injector "
        "online.",
        _schema({"pid": _PID}, ("pid",)),
        "write", _h_breakpoint_list, ("pid",),
    ),
    ToolSpec(
        "breakpoint_remove",
        "Remove a single breakpoint by address or module!symbol. SIDE EFFECT: "
        "clears debug registers / restores patched bytes. REQUIRES the "
        "injector online.",
        _schema({"pid": _PID, "address": _ADDR, "target": {"type": "string"},
                 "tid": {"type": "integer"}}, ("pid",)),
        "write", _h_breakpoint_remove, ("pid",),
    ),
    ToolSpec(
        "breakpoint_clear",
        "Remove ALL breakpoints from the target. SIDE EFFECT: clears debug "
        "registers / restores patched bytes. REQUIRES the injector online.",
        _schema({"pid": _PID}, ("pid",)),
        "write", _h_breakpoint_clear, ("pid",),
    ),
    ToolSpec(
        "unload",
        "Unload the injected agent DLL from each target and wait for the "
        "control channel to close. SIDE EFFECT: stops all debugging features "
        "for that process until re-injected. REQUIRES the injector online.",
        _schema({"pid": _PID, "pids": _PIDS}, ("pids",)),
        "write", _h_unload, ("pid", "pids"),
    ),

    # ---------------------------------------------------------------- dangerous
    ToolSpec(
        "terminate",
        "Terminate the target process from inside (the injected DLL calls "
        "ExitProcess). SIDE EFFECT: the process exits and all its unsaved "
        "state is lost. REQUIRES the injector online.",
        _schema({"pid": _PID, "pids": _PIDS}, ("pids",)),
        "dangerous", _h_terminate, ("pid", "pids"),
    ),
)

_TOOLS_BY_NAME: Dict[str, ToolSpec] = {t.name: t for t in _TOOLS}


# --------------------------------------------------------------------------- 公共 API


def all_tools() -> List[ToolSpec]:
    """返回全部工具定义（不过滤授权）。"""
    return list(_TOOLS)


def tool_for(name: str) -> Optional[ToolSpec]:
    return _TOOLS_BY_NAME.get(str(name))


def list_tools(session: Optional[mcp_consent.ConsentSession]) -> List[Dict[str, Any]]:
    """按会话授权的能力分档过滤工具，返回 MCP ``tools/list`` 结构。"""
    caps = session.capabilities if session is not None else set()
    out: List[Dict[str, Any]] = []
    for spec in _TOOLS:
        if spec.capability in caps:
            out.append({"name": spec.name, "description": spec.description,
                        "inputSchema": spec.input_schema})
    return out


def _check_targets(session: Optional[mcp_consent.ConsentSession], spec: ToolSpec,
                   args: Dict[str, Any],
                   resolve_name: Optional[Callable[[int], str]]) -> Optional[Dict[str, Any]]:
    """逐个校验携带的目标 PID；任一不在白名单 → 返回 ``consent_denied``。"""
    for key in spec.target_args:
        raw = args.get(key)
        if raw is None:
            continue
        pids = raw if isinstance(raw, (list, tuple, set)) else [raw]
        for pid in pids:
            try:
                pid_i = int(pid)
            except (TypeError, ValueError):
                continue
            proc_name = (resolve_name(pid_i) if resolve_name
                         else _default_proc_name(pid_i))
            if not mcp_consent.check_target(session, pid_i, proc_name):
                return {"error": "consent_denied", "tool": spec.name,
                        "capability": spec.capability, "pid": pid_i,
                        "reason": f"目标 PID {pid_i} 不在授权白名单内"}
    return None


def call_tool(session: Optional[mcp_consent.ConsentSession], name: str,
              arguments: Optional[Dict[str, Any]], controller: "Controller",
              *, resolve_name: Optional[Callable[[int], str]] = None) -> Any:
    """路由一次 ``tools/call``。

    返回 handler 本身的结果（dict / list / ...）。**越权不抛异常**，而是：

    * 未知工具 → ``{"error": "unknown_tool", "tool": name}``；
    * 能力不足 → ``{"error": "consent_denied", "tool": name, "capability": cap}``；
    * 目标不在白名单 → 同上，附 ``pid`` 与 ``reason``。
    """
    spec = _TOOLS_BY_NAME.get(str(name))
    if spec is None:
        return {"error": "unknown_tool", "tool": name}
    if not mcp_consent.check_capability(session, spec.capability):
        return {"error": "consent_denied", "tool": spec.name,
                "capability": spec.capability,
                "reason": f"会话未授权 {spec.capability} 能力分档"}
    denied = _check_targets(session, spec, dict(arguments or {}), resolve_name)
    if denied is not None:
        return denied
    return spec.handler(controller, dict(arguments or {}))
