#!/usr/bin/env python3
"""编译 native/agent.c -> native/build/SuperInjectAgent.dll

优先使用 MinGW-w64（GitHub Actions ubuntu 预装），找不到时回退 MSVC cl.exe。
用法：
    python build/build_native.py

默认要求产出 x86-64 DLL：注入端位数必须与控制器（Python 进程）一致，
32 位 DLL 注入 64 位进程会直接失败。确实需要 32 位时设置
SUPERINJECT_ALLOW_32BIT=1。
"""

from __future__ import annotations

import os
import platform
import shutil
import struct
import subprocess
import sys
from pathlib import Path

# Windows 控制台默认 cp1252，直接 print 中文会 UnicodeEncodeError 把构建打挂
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover - 输出被重定向/无控制台
        pass

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "native"
OUT_DIR = NATIVE / "build"
DLL = OUT_DIR / "SuperInjectAgent.dll"
SOURCES = [NATIVE / "agent.c", NATIVE / "superinject_json.c"]
IMAGE_FILE_MACHINE_AMD64 = 0x8664


def _which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _verify_arch() -> int:
    """校验产物是 64 位 PE DLL（除非显式允许 32 位）。"""
    if not DLL.exists():
        print(f"编译未产出 {DLL}")
        return 3
    data = DLL.read_bytes()
    if data[:2] != b"MZ":
        print("产物不是有效的 PE 文件")
        return 4
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        print("产物缺少 PE 签名")
        return 4
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    characteristics = struct.unpack_from("<H", data, pe + 22)[0]
    if not characteristics & 0x2000:
        print("产物不是 DLL（缺少 IMAGE_FILE_DLL 标志）")
        return 4
    if machine != IMAGE_FILE_MACHINE_AMD64 and not os.environ.get(
            "SUPERINJECT_ALLOW_32BIT"):
        print(f"产物是 32 位（machine=0x{machine:04x}），"
              "控制器为 64 位时无法注入；如确需 32 位请设 SUPERINJECT_ALLOW_32BIT=1")
        return 5
    print(f"[build_native] OK -> {DLL}  ({DLL.stat().st_size} bytes, "
          f"machine=0x{machine:04x})")
    return 0


def build_mingw() -> bool:
    cc = _which("x86_64-w64-mingw32-gcc", "i686-w64-mingw32-gcc")
    if not cc:
        return False
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        cc, "-shared", "-O2", "-Wall", "-Wextra", "-DUNICODE", "-D_UNICODE",
        "-lmingw32", "-static-libgcc",
        *[str(s) for s in SOURCES],
        "-o", str(DLL),
        "-lws2_32", "-ladvapi32", "-lshell32", "-luser32",
    ]
    print("[build_native] MinGW:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return True


def build_msvc() -> bool:
    if platform.system() != "Windows":
        return False
    if not shutil.which("cl"):
        return False
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    cmd = [
        "cl", "/nologo", "/LD", "/O2", "/W3", "/DUNICODE", "/D_UNICODE",
        *[str(s) for s in SOURCES],
        f"/Fe:{DLL}", "/link", "ws2_32.lib", "advapi32.lib", "shell32.lib", "user32.lib",
    ]
    print("[build_native] MSVC:", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return True


def main() -> int:
    for s in SOURCES:
        if not s.exists():
            print(f"缺少源文件: {s}")
            return 1
    if os.environ.get("SUPERINJECT_FORCE_MINGW"):
        ok = build_mingw()
    else:
        ok = build_mingw() or build_msvc()
    if not ok:
        print("未找到可用的 C 编译器（x86_64-w64-mingw32-gcc 或 MSVC cl.exe）")
        return 2
    return _verify_arch()


if __name__ == "__main__":
    raise SystemExit(main())
