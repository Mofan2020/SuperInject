#!/usr/bin/env python3
"""编译 native/agent.c -> native/build/SuperInjectAgent.dll（本机开发用）

**发布件不由这里构建**：CI 在 windows runner 上用 MSVC 编译（见 ci.yml 的
native-msvc，那是唯一的产线），集成测试与打包用的都是那一份。这个脚本是给
本地开发用的 —— macOS 上跑不了 cl.exe，只能靠 MinGW-w64 交叉编译出 DLL 来
自测 C 代码与注入链路。

顺序：有 MSVC cl.exe 就用它（尽量贴近发布件），否则用 MinGW-w64。
强制 MinGW 时设置 SUPERINJECT_FORCE_MINGW=1。
用法：
    python build/build_native.py            # 默认：仅 x64
    SUPERINJECT_BUILD_X86=1 python build/build_native.py   # 同时编 x86

默认要求产出 x86-64 DLL：注入端位数必须与控制器（Python 进程）一致，
32 位 DLL 注入 64 位进程会直接失败。确实需要 32 位时设置
SUPERINJECT_ALLOW_32BIT=1 / SUPERINJECT_BUILD_X86=1。
"""

from __future__ import annotations

import os
import platform
import shutil
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / "native"
OUT_DIR = NATIVE / "build"
DLL = OUT_DIR / "SuperInjectAgent.dll"
DLL_X86 = OUT_DIR / "SuperInjectAgent_x86.dll"
SOURCES = [NATIVE / "agent.c", NATIVE / "superinject_json.c"]
IMAGE_FILE_MACHINE_AMD64 = 0x8664
IMAGE_FILE_MACHINE_I386 = 0x014C


def _which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _verify_arch(dll_path: Path, want_x86: bool) -> int:
    """校验产物是 64 位（默认）或 32 位 PE DLL。"""
    if not dll_path.exists():
        print(f"编译未产出 {dll_path}")
        return 3
    data = dll_path.read_bytes()
    if data[:2] != b"MZ":
        print(f"{dll_path} 不是有效的 PE 文件")
        return 4
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        print(f"{dll_path} 缺少 PE 签名")
        return 4
    machine = struct.unpack_from("<H", data, pe + 4)[0]
    characteristics = struct.unpack_from("<H", data, pe + 22)[0]
    if not characteristics & 0x2000:
        print(f"{dll_path} 不是 DLL（缺少 IMAGE_FILE_DLL 标志）")
        return 4
    want_machine = IMAGE_FILE_MACHINE_I386 if want_x86 else IMAGE_FILE_MACHINE_AMD64
    if machine != want_machine:
        print(f"{dll_path} 位数不符：machine=0x{machine:04x}（期望 0x{want_machine:04x}）")
        return 5
    print(f"[build_native] {'x86' if want_x86 else 'x64'} OK -> {dll_path}  "
          f"({dll_path.stat().st_size} bytes, machine=0x{machine:04x})")
    return 0


def build_mingw(*, want_x86: bool) -> bool:
    prefix = "i686-w64-mingw32" if want_x86 else "x86_64-w64-mingw32"
    cc = _which(f"{prefix}-gcc")
    if not cc:
        return False
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = DLL_X86 if want_x86 else DLL
    cmd = [
        cc, "-shared", "-O2", "-Wall", "-Wextra", "-DUNICODE", "-D_UNICODE",
        "-lmingw32", "-static-libgcc",
        *[str(s) for s in SOURCES],
        "-o", str(out),
        "-lws2_32", "-ladvapi32", "-lshell32", "-luser32",
    ]
    print(f"[build_native] MinGW ({'x86' if want_x86 else 'x64'}):", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return True


def build_msvc(*, want_x86: bool) -> bool:
    if platform.system() != "Windows":
        return False
    if not shutil.which("cl"):
        return False
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = DLL_X86 if want_x86 else DLL
    cmd = [
        "cl", "/nologo", "/LD", "/O2", "/W3", "/DUNICODE", "/D_UNICODE",
        *[str(s) for s in SOURCES],
        f"/Fe:{out}", "/link", "ws2_32.lib", "advapi32.lib",
        "shell32.lib", "user32.lib",
    ]
    print(f"[build_native] MSVC ({'x86' if want_x86 else 'x64'}):", " ".join(cmd))
    subprocess.run(cmd, check=True)
    return True


def _build_one(*, want_x86: bool, force_mingw: bool) -> bool:
    if force_mingw:
        return build_mingw(want_x86=want_x86)
    return build_msvc(want_x86=want_x86) or build_mingw(want_x86=want_x86)


def main() -> int:
    for s in SOURCES:
        if not s.exists():
            print(f"缺少源文件: {s}")
            return 1

    force_mingw = bool(os.environ.get("SUPERINJECT_FORCE_MINGW"))
    build_x86 = bool(os.environ.get("SUPERINJECT_BUILD_X86")
                     or os.environ.get("SUPERINJECT_ALLOW_32BIT"))

    rc = 0
    if not _build_one(want_x86=False, force_mingw=force_mingw):
        print("未找到可用的 C 编译器（x86_64-w64-mingw32-gcc 或 MSVC cl.exe）")
        return 2
    rc = _verify_arch(DLL, want_x86=False) or rc

    if build_x86:
        if not _build_one(want_x86=True, force_mingw=force_mingw):
            print("⚠️  x86 编译器不可用（需要 i686-w64-mingw32-gcc 或 32 位 MSVC）；跳过")
        rc_x86 = _verify_arch(DLL_X86, want_x86=True)
        if rc_x86:
            rc = rc_x86
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
