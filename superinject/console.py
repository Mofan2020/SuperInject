"""控制台输出的小工具。

为什么需要它：SuperInject 打包成 ``--windowed``（GUI 子系统）后没有控制台，
Windows 上 ``sys.stdout`` / ``sys.stderr`` 可能是 ``None``，此时 ``print()`` 会抛
``AttributeError: 'NoneType' object has no attribute 'write'``。而启动自检的一串
``print("[自检1] …")`` 恰恰发生在 GUI 启动**之前** —— 一旦抛异常，用户看到的就是
「双击没反应」，且因为窗口都没起来，日志也难看到。

所以：凡是「有更好去处」的输出（GUI / 日志文件）都允许静默失败，但**绝不能因此
崩掉进程**。``selftest`` 与 ``__main__`` 都走这里。
"""

from __future__ import annotations

import sys


def _stream(name: str):
    """取输出流；窗口化打包下可能是 None。"""
    return getattr(sys, name, None)


def safe_print(text: str, stream: str = "stdout") -> bool:
    """尽力打印；无控制台时静默跳过。返回是否真的写出去了。"""
    target = _stream(stream)
    if target is None:
        return False
    try:
        print(text, file=target)
    except (AttributeError, ValueError, OSError):
        # 句柄失效（管道关闭、GUI 子系统无控制台）等一律忽略
        return False
    return True
