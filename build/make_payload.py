#!/usr/bin/env python3
"""把编译好的 DLL 以 base64 内嵌进 ``superinject/embedded/dll_payload.py``。

同时内嵌两份：

* ``DATA_B64``     —— ``SuperInjectAgent.dll`` (x64)
* ``DATA_B64_X86`` —— ``SuperInjectAgent_x86.dll`` (x86，未找到则留空串)

注意：这里只写字节，**不写任何 SHA 常量** —— 校验用的哈希全部在运行时计算。
"""

from __future__ import annotations

import base64
import datetime
import sys
from pathlib import Path

# Windows 控制台默认 cp1252，直接 print 中文会 UnicodeEncodeError 把构建打挂
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover - 输出被重定向/无控制台
        pass

ROOT = Path(__file__).resolve().parent.parent
DLL_X64 = ROOT / "native" / "build" / "SuperInjectAgent.dll"
DLL_X86 = ROOT / "native" / "build" / "SuperInjectAgent_x86.dll"
TARGET = ROOT / "superinject" / "embedded" / "dll_payload.py"


def _wrap(data: bytes) -> str:
    if not data:
        return '""'
    b64 = base64.b64encode(data).decode("ascii")
    chunks = [b64[i:i + 96] for i in range(0, len(b64), 96)]
    return "\n" + "\n".join(f'    "{c}"' for c in chunks)


def main() -> int:
    missing = []
    if not DLL_X64.exists():
        missing.append(str(DLL_X64))
    if not DLL_X86.exists():
        missing.append(str(DLL_X86))
    if DLL_X64 not in (None,) and not DLL_X64.exists() and DLL_X86 not in (None,) and not DLL_X86.exists():
        # 两个都没有才报错（否则单 x64 仍能继续编译，只是没有 x86 支持）
        print(f"未找到 {DLL_X64}，请先运行 python build/build_native.py")
        return 1

    data_x64 = DLL_X64.read_bytes() if DLL_X64.exists() else b""
    data_x86 = DLL_X86.read_bytes() if DLL_X86.exists() else b""
    body_x64 = _wrap(data_x64)
    body_x86 = _wrap(data_x86)
    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    template = f'''"""自动生成，请勿手工编辑。

由 build/make_payload.py 生成于 {stamp}。
此处只保存 DLL 字节；完整性校验由 superinject.dll_manager 在运行时计算 SHA256。

x86 DLL 未编译时 ``DATA_B64_X86`` 为空串，控制器会按「该位数暂不可用」处理。
"""

DATA_B64 = (
{body_x64}
)

DATA_B64_X86 = (
{body_x86}
)
'''
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(template, encoding="utf-8")
    if data_x64:
        print(f"[make_payload] x64 已内嵌 {len(data_x64)} 字节")
    if data_x86:
        print(f"[make_payload] x86 已内嵌 {len(data_x86)} 字节")
    elif missing:
        print(f"[make_payload] ⚠️  缺少 x86 DLL（{DLL_X86}）；仅 x64 可用")
    print(f"[make_payload] -> {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
