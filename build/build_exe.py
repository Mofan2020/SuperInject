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
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", "SuperInject",
        "--windowed",
        "--onedir",
        "--add-data", "superinject/web;superinject/web",
        "--collect-submodules", "webview",
        "--hidden-import", "webview.platforms.edgechromium",
        str(ROOT / "run_superinject.py"),
    ]
    print("\n=== pyinstaller ===\n" + " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT).returncode


def main() -> int:
    for s in ("build_native.py", "make_payload.py"):
        rc = run(s)
        if rc != 0:
            print(f"{s} 失败，终止构建")
            return rc
    return pyinstaller()


if __name__ == "__main__":
    raise SystemExit(main())
