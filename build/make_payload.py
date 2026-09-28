#!/usr/bin/env python3
"""把编译好的 DLL 以 base64 内嵌进 superinject/embedded/dll_payload.py。

注意：这里只写字节，**不写任何 SHA 常量**——校验用的哈希全部在运行时计算。
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

# Windows 控制台默认 cp1252，直接 print 中文会 UnicodeEncodeError 把构建打挂
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover - 输出被重定向/无控制台
        pass

ROOT = Path(__file__).resolve().parent.parent
DLL = ROOT / "native" / "build" / "SuperInjectAgent.dll"
TARGET = ROOT / "superinject" / "embedded" / "dll_payload.py"

TEMPLATE = '''"""自动生成，请勿手工编辑。

由 build/make_payload.py 生成于 {stamp}。
此处只保存 DLL 字节；完整性校验由 superinject.dll_manager 在运行时计算 SHA256。
"""

DATA_B64 = (
{data}
)
'''


def main() -> int:
    if not DLL.exists():
        print(f"未找到 {DLL}，请先运行 python build/build_native.py")
        return 1
    data = DLL.read_bytes()
    b64 = base64.b64encode(data).decode("ascii")
    chunks = [b64[i:i + 96] for i in range(0, len(b64), 96)]
    body = "\n".join(f'    "{c}"' for c in chunks)
    import datetime

    stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(TEMPLATE.format(stamp=stamp, data=body), encoding="utf-8")
    print(f"[make_payload] 已内嵌 {len(data)} 字节 -> {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
