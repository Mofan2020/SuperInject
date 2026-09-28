#!/usr/bin/env python3
"""编译 native/agent.c -> native/build/SuperInjectAgent.dll

优先使用 MinGW-w64（GitHub Actions ubuntu 预装），找不到时回退 MSVC cl.exe。
用法：
    python build/build_native.py
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "native"
OUT_DIR = NATIVE / "build"
DLL = OUT_DIR / "SuperInjectAgent.dll"
SOURCES = [NATIVE / "agent.c", NATIVE / "superinject_json.c"]


def _which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def build_mingw() -> bool:
    cc = _which("x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc")
    if not cc:
        return False
    target = "x86_64" if "x86_64" in cc else "i686"
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        cc, "-shared", "-O2", "-Wall", "-Wextra", "-DUNICODE", "-D_UNICODE",
        f"-lmingw32", "-static-libgcc",
        *[str(s) for s in SOURCES],
        "-o", str(DLL),
        "-ladvapi32", "-lshell32", "-luser32",
    ]
    print("[build_native] MinGW:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return True


def build_msvc() -> bool:
    if platform.system() != "Windows":
        return False
    cl = shutil.which("cl")
    if not cl:
        return False
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        "cl", "/nologo", "/LD", "/O2", "/W3", "/DUNICODE", "/D_UNICODE",
        *[str(s) for s in SOURCES],
        f"/Fe:{DLL}", "/link", "advapi32.lib", "shell32.lib", "user32.lib",
    ]
    print("[build_native] MSVC:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return True


def main() -> int:
    for s in SOURCES:
        if not s.exists():
            print(f"缺少源文件: {s}")
            return 1
    ok = False
    if os.environ.get("SUPERINJECT_FORCE_MINGW"):
        ok = build_mingw()
    if not ok:
        ok = build_mingw()
    if not ok:
        ok = build_msvc()
    if not ok:
        print("未找到可用的 C 编译器（x86_64-w64-mingw32-gcc 或 MSVC cl.exe）")
        return 2
    if not DLL.exists():
        print("编译未产出 DLL")
        return 3
    print(f"[build_native] OK -> {DLL}  ({DLL.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
