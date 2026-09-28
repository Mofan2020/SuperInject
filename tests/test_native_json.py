"""native JSON 层自测：用本机 C 编译器真的编译并运行一遍。

存在的理由（真实事故，不是理论风险）：
`si_json_array_push` 与 `obj_set` 曾经无条件互相回调 —— 数组分支里 obj_set 又
调回 si_json_array_push，两个函数无限互递归。结果是任何「真的往数组里塞过元素」
的命令都会永久卡死：`info`（模块表）、`mem_regions`（内存区）、`mem_search`
（匹配结果）在真实注入后全部无响应，而数组恰好为空的 `resources` 看起来正常，
把问题伪装成「传输层随机挂死」。CI 上排查了很久，最后靠注入端日志 + 这个自测
才定性（旧版编译出来直接段错误/死循环）。

没有可用 C 编译器时跳过（本机与 CI 一般都有 cc/clang/cl）。
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "native"
TEST_C = Path(__file__).resolve().parent / "native" / "test_si_json.c"
JSON_C = NATIVE / "superinject_json.c"
WATCHDOG_SECONDS = 120


def _find_vs_cl() -> str | None:
    """cl.exe 通常不在 PATH 上，按 MSVC 安装布局找一份。"""
    if os.name != "nt":
        return None
    bases = [
        Path(r"C:\Program Files\Microsoft Visual Studio"),
        Path(r"C:\Program Files (x86)\Microsoft Visual Studio"),
    ]
    for base in bases:
        if not base.is_dir():
            continue
        found = sorted(base.glob("**/VC/Tools/MSVC/*/bin/Hostx64/x64/cl.exe"))
        if found:
            return str(found[-1])
    return None


def _find_compiler() -> tuple[str, bool] | None:
    for name in (os.environ.get("CC"), "cc", "gcc", "clang"):
        if not name:
            continue
        path = shutil.which(name)
        if path:
            return path, False
    cl = _find_vs_cl()
    if cl:
        return cl, True
    return None


@pytest.fixture(scope="module")
def compiler() -> tuple[str, bool]:
    found = _find_compiler()
    if not found:
        pytest.skip("本机没有可用的 C 编译器（cc/gcc/clang/cl），跳过 native JSON 自测")
    return found


def test_native_json_selftest(compiler, tmp_path):
    cc, is_msvc = compiler
    exe = tmp_path / ("test_si_json.exe" if os.name == "nt" else "test_si_json")

    if is_msvc:
        build = [cc, "/nologo", "/W3", "/I", str(NATIVE),
                 str(TEST_C), str(JSON_C), f"/Fe:{exe}"]
    else:
        build = [cc, "-std=c99", "-Wall", "-Wextra", "-Werror", "-I", str(NATIVE),
                 str(TEST_C), str(JSON_C), "-o", str(exe)]

    built = subprocess.run(build, capture_output=True, text=True, timeout=300)
    assert built.returncode == 0, f"编译失败:\n{built.stdout}\n{built.stderr}"
    assert exe.exists(), "编译未产出可执行文件"

    # 死循环回归在这里表现为「跑不完」：超时即失败，而不是把 CI 挂死。
    run = subprocess.run([str(exe)], capture_output=True, text=True,
                         timeout=WATCHDOG_SECONDS)
    assert run.returncode == 0, (
        "native JSON 自测失败（数组 push / 序列化 / 解析）：\n"
        f"{run.stdout}\n{run.stderr}")
    assert "SI_JSON_SELFTEST_OK" in run.stdout, run.stdout
