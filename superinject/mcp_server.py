"""MCP server：把 Controller 能力通过 JSON-RPC over **stdio** 暴露给 AI Agent。

传输只有 stdio（不实现 TCP / 远程）—— 4 字节长度 + JSON 帧那套是
DLL↔控制器之间的事，MCP 这边按规范走「一行一个 JSON-RPC 消息」。

实现分两条路：

1. **官方 mcp Python SDK**（``pip install mcp``）—— 装了就用
   :func:`_run_sdk`，它是 MCP 官方 stdio server，协议细节（capabilities 协商、
   分帧）都交给 SDK。
2. **裸 stdio JSON-RPC 降级**（:func:`run_stdio`）—— SDK 未安装、API 与预期不符，
   或调用方显式传入 stdin/stdout 流（测试）时使用；只实现 ``initialize`` /
   ``tools/list`` / ``tools/call`` 三个方法，够 Agent 起连接与调工具。

**硬约束：stdout 只能出 JSON-RPC 帧。** 所有日志走 ``logging``（默认 handler 绑
stderr），本模块绝不 ``print`` 到 stdout。
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any, Dict, Optional

from . import mcp_router
from .mcp_consent import ConsentSession
from .version import __version__

log = logging.getLogger("supinject.mcp")

# 降级路径默认声称的协议版本；``initialize`` 时优先回显客户端请求的版本。
DEFAULT_PROTOCOL_VERSION = "2025-06-18"

_SERVER_NAME = "superinject"


# --------------------------------------------------------------------------- 消息构造


def _result(mid: Any, result: Dict[str, Any]) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid: Any, code: int, message: str) -> Dict[str, Any]:
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": int(code), "message": str(message)}}


def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def _emit(stream: Any, obj: Dict[str, Any]) -> None:
    """往 stdout 写一帧。**唯一**允许写 stdout 的地方。"""
    stream.write(_json_dumps(obj) + "\n")
    stream.flush()


# --------------------------------------------------------------------------- 协议处理


def handle_message(session: ConsentSession, controller: Any,
                   message: Any) -> Optional[Dict[str, Any]]:
    """把一条 JSON-RPC 消息处理成一条响应（或 ``None`` 表示不回应）。

    纯函数、无 IO —— 便于单测。通知（``notifications/*`` 或无 ``id``）返回
    ``None``（JSON-RPC 规定通知不应答）。
    """
    if not isinstance(message, dict):
        return _error(None, -32600, "invalid request")
    mid = message.get("id")
    method = message.get("method")
    if not method:
        # 没有 method：可能是客户端发来的响应，或坏包
        return _error(mid, -32600, "invalid request") if mid is not None else None

    # 通知一律不回应
    if str(method).startswith("notifications/"):
        return None

    params = message.get("params") or {}
    if not isinstance(params, dict):
        params = {}

    if method == "initialize":
        protocol = params.get("protocolVersion") or DEFAULT_PROTOCOL_VERSION
        response = _result(mid, {
            "protocolVersion": protocol,
            "serverInfo": {"name": _SERVER_NAME, "version": __version__},
            "capabilities": {"tools": {}},
        })
    elif method == "ping":
        response = _result(mid, {})
    elif method == "tools/list":
        response = _result(mid, {"tools": mcp_router.list_tools(session)})
    elif method == "tools/call":
        name = params.get("name")
        if not name:
            response = _error(mid, -32602, "missing tool name")
        else:
            out = mcp_router.call_tool(session, str(name),
                                       params.get("arguments") or {}, controller)
            is_error = isinstance(out, dict) and "error" in out
            response = _result(mid, {
                "content": [{"type": "text", "text": _json_dumps(out)}],
                "isError": bool(is_error),
            })
    else:
        response = _error(mid, -32601, f"method not found: {method}")

    return None if mid is None else response


# --------------------------------------------------------------------------- 降级：裸 stdio


def run_stdio(session: ConsentSession, controller: Any = None, *,
              stdin: Any = None, stdout: Any = None) -> int:
    """裸 stdio JSON-RPC 主循环（SDK 不可用 / 测试时的路径）。

    逐行读 stdin，每行一条 JSON-RPC；处理结果写回 stdout。读到 EOF 返回 0。
    """
    if controller is None:
        controller = _controller()
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout

    for raw in stdin:
        line = raw.strip() if isinstance(raw, str) else str(raw).strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            _emit(stdout, _error(None, -32700, "parse error"))
            continue
        response = handle_message(session, controller, message)
        if response is not None:
            _emit(stdout, response)
    return 0


def _controller() -> Any:
    from .controller import Controller
    return Controller()


# --------------------------------------------------------------------------- 官方 SDK


def sdk_available() -> bool:
    """官方 mcp SDK 是否可用（API 面满足最低要求）。"""
    try:
        import mcp.types  # noqa: F401
        from mcp.server import Server  # noqa: F401
        from mcp.server.stdio import stdio_server  # noqa: F401
    except Exception:
        return False
    return True


def _run_sdk(session: ConsentSession, controller: Any = None) -> int:
    """用官方 mcp SDK 起 stdio server。任何版本差异都会抛给 :func:`run` 兜底。"""
    import asyncio

    import mcp.types as types
    from mcp.server import Server
    from mcp.server.stdio import stdio_server

    if controller is None:
        controller = _controller()
    server = Server(_SERVER_NAME, version=__version__)

    @server.list_tools()
    async def _list_tools() -> list:
        return [types.Tool(**tool) for tool in mcp_router.list_tools(session)]

    @server.call_tool()
    async def _call_tool(name: str, arguments: Optional[dict]) -> list:
        out = await asyncio.to_thread(
            mcp_router.call_tool, session, name, arguments or {}, controller)
        return [types.TextContent(type="text", text=_json_dumps(out))]

    async def _serve() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream,
                             server.create_initialization_options())

    asyncio.run(_serve())
    return 0


# --------------------------------------------------------------------------- 入口


def run(transport: str = "stdio", session: Optional[ConsentSession] = None,
        controller: Any = None, *, use_sdk: Optional[bool] = None,
        stdin: Any = None, stdout: Any = None) -> int:
    """起 MCP server。返回退出码。

    * ``transport`` 目前只支持 ``"stdio"``（远程传输明确不做）；
    * ``session`` 是已授权的 :class:`~superinject.mcp_consent.ConsentSession`；
    * ``use_sdk`` 为 ``None`` 时自动探测：装了官方 SDK 且没有显式传入
      ``stdin``/``stdout`` 流就用 SDK，否则走裸 stdio 降级；
    * 显式传 ``stdin``/``stdout``（测试）时强制走降级路径 —— SDK 会自己包
      ``sys.stdin``/``stdout``，不吃外部流。
    """
    if transport != "stdio":
        raise ValueError(f"不支持的传输: {transport!r}（只做 stdio）")
    if session is None:
        raise ValueError("run() 需要一个已授权的 ConsentSession")

    forced_fallback = stdin is not None or stdout is not None
    if use_sdk is None:
        use_sdk = sdk_available() and not forced_fallback

    if use_sdk:
        try:
            return _run_sdk(session, controller)
        except Exception:  # pragma: no cover - 版本差异兜底
            log.exception("官方 mcp SDK 路径失败，降级到裸 stdio JSON-RPC")

    log.debug("MCP server 走裸 stdio JSON-RPC 路径")
    return run_stdio(session, controller, stdin=stdin, stdout=stdout)
