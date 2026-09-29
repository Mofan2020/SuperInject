#!/usr/bin/env python3
"""检查注入端 DLL 的导入表：只允许依赖系统 DLL。

为什么需要它：这个 DLL 会被 LoadLibrary 到**别人的进程**里。用户机器上没装
VC++ 运行库是常态，一旦导入 `VCRUNTIME140.dll` / `MSVCP140.dll` 之类，
`LoadLibrary` 会直接失败 —— 表现为「注入失败」，而且原因极难从症状看出来。

原来 CI 里靠「再用 mingw 交叉编译一遍」间接盯这件事（mingw 默认只链
msvcrt.dll）。但真正该断言的是**结果**：DLL 的导入表里只有系统 DLL。

用法::

    python build/check_dll_imports.py native/build/SuperInjectAgent.dll
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

# 一定存在的系统 DLL（Windows 自带）。没在这个清单里也不算错，
# 只要不落在下面的禁用前缀里即可。
#
# api-ms-win-* 是 Windows 的 API Set（含 UCRT：api-ms-win-crt-*），Windows 10+
# 随系统提供喂给用户 —— 本项目最低支持 Win10 x64（见 README），所以放行；
# 而不带版本号的 msvcrt.dll 更是每个 Windows 都有。真正要求「用户额外装东西」的
# 是 vcruntime140 / msvcp140 / msvcr120 这类 VC++ 运行库，那才是要拦的。
KNOWN_SYSTEM = {
    "kernel32.dll", "advapi32.dll", "ws2_32.dll", "msvcrt.dll",
    "shell32.dll", "user32.dll", "ole32.dll", "oleaut32.dll",
    "ntdll.dll", "ucrtbase.dll", "shlwapi.dll", "gdi32.dll",
}

# 需要「用户机器额外装东西」的依赖 —— 出现在导入表里就是 bug。
# 注意 msvcrt.dll（无版本号）是系统自带的，不能拦；要拦的是 msvcr120 这种带版本号的。
FORBIDDEN_PREFIXES = (
    "vcruntime",     # VC++ 运行库（装了 VS / 发行包才有）
    "msvcp",         # C++ 运行库
    "python",        # 打包没打干净
    "concrt", "vccorlib",
)
# 带版本号的 CRT（msvcr100/msvcr120…）才需要额外安装
FORBIDDEN_RE = re.compile(r"^msvcr\d", re.IGNORECASE)
# 明确放行：无版本号的 msvcrt.dll 是 Windows 自带
ALWAYS_OK = {"msvcrt.dll"}
# Windows 的 API Set（api-ms-win-crt-* / api-ms-win-core-* …）：Win10+ 系统自带
ALWAYS_OK_RE = re.compile(r"^api-ms-win-", re.IGNORECASE)


def _sections(data: bytes, pe: int) -> list[tuple[int, int, int]]:
    """返回 [(虚拟地址 RVA, 文件偏移, 大小), ...]"""
    nsec = struct.unpack_from("<H", data, pe + 6)[0]
    opt_size = struct.unpack_from("<H", data, pe + 20)[0]
    base = pe + 24 + opt_size
    out = []
    for i in range(nsec):
        off = base + i * 40
        vsize, vaddr = struct.unpack_from("<II", data, off + 8)
        raw_size, raw_ptr = struct.unpack_from("<II", data, off + 16)
        out.append((vaddr, raw_ptr, max(vsize, raw_size)))
    return out


def _rva_to_offset(sections, rva: int) -> int | None:
    for vaddr, raw_ptr, size in sections:
        if vaddr <= rva < vaddr + size:
            return raw_ptr + (rva - vaddr)
    return None


def imported_dlls(path: Path) -> list[str]:
    """解析 PE 导入表，返回导入的 DLL 名（保序去重）。"""
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"{path} 不是 PE 文件")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"{path} 缺少 PE 签名")
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    dd_off = pe + (24 + 112 if magic == 0x20B else 24 + 96)  # PE32+ / PE32
    import_rva = struct.unpack_from("<I", data, dd_off + 8)[0]
    if import_rva == 0:
        return []

    sections = _sections(data, pe)
    names: list[str] = []
    off = _rva_to_offset(sections, import_rva)
    if off is None:
        raise ValueError("导入表 RVA 无法映射到文件偏移")
    while True:
        # IMAGE_IMPORT_DESCRIPTOR: 20 字节，全 0 结束
        chunk = data[off:off + 20]
        if len(chunk) < 20 or chunk == b"\0" * 20:
            break
        name_rva = struct.unpack_from("<I", data, off + 12)[0]
        off += 20
        if name_rva == 0:
            continue
        n_off = _rva_to_offset(sections, name_rva)
        if n_off is None:
            continue
        end = data.index(b"\0", n_off)
        name = data[n_off:end].decode("ascii", "replace")
        if name and name.lower() not in [n.lower() for n in names]:
            names.append(name)
    return names


def check(path: Path) -> list[str]:
    """返回问题列表（空 = 通过）。"""
    problems = []
    names = imported_dlls(path)
    for name in names:
        low = name.lower()
        if low in ALWAYS_OK or ALWAYS_OK_RE.match(low):
            continue
        for bad in FORBIDDEN_PREFIXES:
            if low.startswith(bad) or FORBIDDEN_RE.match(low):
                problems.append(
                    f"导入了 {name}：用户机器不装 VC++ 运行库时 LoadLibrary 会失败")
                break
        else:
            if low not in KNOWN_SYSTEM:
                problems.append(f"导入了未登记的非系统 DLL {name}（确认它是否随系统提供）")
    return problems


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2
    path = Path(argv[1])
    if not path.exists():
        print(f"找不到 {path}")
        return 2
    names = imported_dlls(path)
    print(f"{path} 导入表: {', '.join(names) or '(无)'}")
    problems = check(path)
    for p in problems:
        print(f"[FAIL] {p}")
    if problems:
        return 1
    print("OK: 只依赖系统 DLL")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
