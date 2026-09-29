#!/usr/bin/env python3
"""一键构建：编译 DLL → 内嵌 → PyInstaller 打包成 SuperInject.exe。

用法（Windows）：
    python build/build_native.py && python build/make_payload.py && python build/build_exe.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(script: str) -> int:
    print(f"\n=== {script} ===")
    return subprocess.run([sys.executable, str(ROOT / "build" / script)],
                          cwd=ROOT).returncode


def pyinstaller() -> int:
    # --onefile：产物只有一个 SuperInject.exe，不再有 _internal 目录。
    # 运行时 PyInstaller 会把 web 资源解到临时目录，程序用 __file__ 定位，
    # 与 onedir 行为一致（dll_manager 也会把内置 DLL 释放到 exe 同目录）。
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", "SuperInject",
        "--windowed",
        "--onefile",
        "--add-data", "superinject/web;superinject/web",
        "--collect-submodules", "webview",
        "--hidden-import", "webview.platforms.edgechromium",
        str(ROOT / "run_superinject.py"),
    ]
    print("\n=== pyinstaller ===\n" + " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT).returncode


def verify_build() -> int:
    """确认真的是单文件产物：只有一个 exe，且没有 _internal 目录。"""
    exe = ROOT / "dist" / "SuperInject.exe"
    internal = ROOT / "dist" / "SuperInject"
    problems = []
    if not exe.exists():
        problems.append(f"未生成 {exe}")
    if internal.exists():
        problems.append(f"仍存在目录 {internal}（应只有单个 exe）")
    for p in problems:
        print("[构建校验] " + p)
    if problems:
        return 1
    print(f"[构建校验] 单文件产物 OK: {exe} ({exe.stat().st_size} 字节)，无 _internal")
    return 0


def main() -> int:
    for s in ("build_native.py", "make_payload.py"):
        rc = run(s)
        if rc != 0:
            print(f"{s} 失败，终止构建")
            return rc
    rc = pyinstaller()
    if rc != 0:
        return rc
    return verify_build()


if __name__ == "__main__":
    raise SystemExit(main())
