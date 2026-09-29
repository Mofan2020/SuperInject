"""``--windowed`` 打包下的控制台输出保护。

Windows GUI 子系统的进程没有控制台，``sys.stdout`` / ``sys.stderr`` 可能是
``None``，此时 ``print()`` 抛 ``AttributeError``。启动自检的一串输出恰好发生在
GUI 起来**之前**，一旦抛出异常就是「双击没反应」，非常难查。这里的用例锁住
「无控制台时输出必须静默失败、绝不能抛」。
"""

from __future__ import annotations

import io

import pytest

from superinject.console import safe_print


def test_safe_print_writes_to_stdout(monkeypatch):
    buf = io.StringIO()
    monkeypatch.setattr("sys.stdout", buf)
    assert safe_print("hello") is True
    assert buf.getvalue() == "hello\n"


def test_safe_print_survives_none_stdout(monkeypatch):
    """窗口化打包：sys.stdout 为 None 时不得抛异常。"""
    monkeypatch.setattr("sys.stdout", None)
    assert safe_print("会被丢掉") is False


def test_safe_print_survives_none_stderr(monkeypatch):
    monkeypatch.setattr("sys.stderr", None)
    assert safe_print("x", "stderr") is False


@pytest.mark.parametrize("exc", [ValueError("closed"), OSError("bad handle")])
def test_safe_print_swallows_write_errors(monkeypatch, exc):
    class Boom:
        def write(self, _):
            raise exc

    monkeypatch.setattr("sys.stdout", Boom())
    assert safe_print("x") is False


def test_main_help_survives_no_console(monkeypatch, tmp_path):
    """真跑一遍入口：无控制台时 ``--help`` 仍然要干净退出（返回 0 而不是抛）。

    这就是「双击没反应」那条路径的最小复现 —— 过去 ``main()`` 里的裸 print
    在 sys.stdout=None 时会抛 AttributeError，GUI 还没起来进程就死了。
    """
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr("sys.stdout", None)
    from superinject import __main__ as m

    assert m.main(["--help"]) == 0


def test_main_module_uses_safe_print_everywhere():
    """__main__ 里不允许再出现裸 print —— 那正是启动崩溃的来源。

    这条不是「读源码断言格式」，而是断言一个行为契约：该模块的输出必须全部
    经过保护层。用 AST 提取调用名，比字符串匹配更抗重命名/换行。
    """
    import ast
    from pathlib import Path

    src = Path(__file__).resolve().parent.parent / "superinject" / "__main__.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    offenders = [
        node.lineno for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        and node.func.id == "print"
    ]
    assert not offenders, f"__main__.py 第 {offenders} 行还有裸 print(...)"
