"""PE 资源里的裸 DIB 转成能直接打开的 BMP / ICO / CUR。

被注入进程里取出的 ``RT_BITMAP`` / ``RT_ICON`` / ``RT_CURSOR`` 资源是裸的
``BITMAPINFOHEADER`` 数据，直接存盘是打不开的（没有 BMP 文件头 / ICO 目录）。
这里在控制器侧补上文件头，得到的图片就能在 GUI 里直接预览。

纯字节处理 + 纯逻辑，可在任意平台单测。
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Optional

RT_CURSOR = 1
RT_BITMAP = 2
RT_ICON = 3

BITMAPINFOHEADER_SIZE = 40
BI_BITFIELDS = 3


def parse_dib(data: bytes) -> Optional[dict]:
    """解析 BITMAPINFOHEADER，返回宽高/位深/调色板等信息。"""
    if len(data) < BITMAPINFOHEADER_SIZE:
        return None
    (bi_size,) = struct.unpack_from("<I", data, 0)
    if bi_size < BITMAPINFOHEADER_SIZE or bi_size > len(data):
        return None
    (width, height) = struct.unpack_from("<ii", data, 4)
    (planes, bit_count) = struct.unpack_from("<HH", data, 12)
    (compression,) = struct.unpack_from("<I", data, 16)
    if width <= 0 or height == 0 or bit_count == 0:
        return None

    extra = 0
    if compression == BI_BITFIELDS and bi_size == BITMAPINFOHEADER_SIZE:
        extra = 12                      # 3 个 DWORD 掩码，在调色板之前
    palette = 0
    if bit_count <= 8:
        palette = (1 << bit_count) * 4
    return {
        "bi_size": bi_size,
        "width": width,
        "height": height,
        "planes": planes,
        "bit_count": bit_count,
        "compression": compression,
        "palette_bytes": palette,
        "extra_bytes": extra,
    }


def dib_to_bmp(data: bytes) -> Optional[bytes]:
    """给裸 DIB 补上 BITMAPFILEHEADER，得到标准 .bmp。"""
    info = parse_dib(data)
    if info is None:
        return None
    # 像素偏移是相对「加了文件头之后」的完整 BMP 而言的，所以拿 14 + len(data) 做上界
    offset = 14 + info["bi_size"] + info["extra_bytes"] + info["palette_bytes"]
    if offset > len(data) + 14:
        return None
    header = b"BM" + struct.pack("<IHHI", 14 + len(data), 0, 0, offset)
    return header + data


def _icon_dir_entry(count: int, icon_type: int, entries: list[tuple]) -> bytes:
    head = struct.pack("<HHH", 0, icon_type, count)
    body = b""
    for width, height, color_count, planes, bit_count, size, offset in entries:
        body += struct.pack("<BBBBHHII", width, height, color_count,
                            0, planes, bit_count, size, offset)
    return head + body


def dib_to_ico(data: bytes, *, is_cursor: bool = False) -> Optional[bytes]:
    """把 RT_ICON / RT_CURSOR 的裸 DIB 包成单入口的 .ico / .cur。

    ICON / CURSOR 的 DIB 高度是「图像高度 + AND 掩码高度」，否则图标会被拉长。
    CURSOR 资源前 4 字节是热点坐标，对应到 ICO 目录里的 planes/bitCount 字段。
    """
    hot_x = hot_y = 0
    if is_cursor:
        if len(data) < 4:
            return None
        (hot_x, hot_y) = struct.unpack_from("<HH", data, 0)
        data = data[4:]

    info = parse_dib(data)
    if info is None:
        return None

    width = info["width"]
    height = info["height"] // 2 if info["height"] > 1 else info["height"]
    color_count = (1 << info["bit_count"]) if info["bit_count"] < 8 else 0

    icon_type = 2 if is_cursor else 1
    planes = hot_x if is_cursor else info["planes"]
    bit_count = hot_y if is_cursor else info["bit_count"]

    entry = (
        0 if width >= 256 else width,
        0 if height >= 256 else height,
        0 if color_count >= 256 else color_count,
        planes,
        bit_count,
        len(data),
        6 + 16,                 # ICONDIR(6) + 一个 ICONDIRENTRY(16)
    )
    return _icon_dir_entry(1, icon_type, [entry]) + data


def convert_dump(path: Path, rtype: int) -> Optional[Path]:
    """把 DLL 导出的 ``.dib`` 就地转换成 BMP / ICO / CUR，返回新文件路径。"""
    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError:
        return None

    if rtype == RT_BITMAP:
        out = dib_to_bmp(data)
        suffix = ".bmp"
    elif rtype == RT_ICON:
        out = dib_to_ico(data)
        suffix = ".ico"
    elif rtype == RT_CURSOR:
        out = dib_to_ico(data, is_cursor=True)
        suffix = ".cur"
    else:
        return None

    if not out:
        return None
    target = path.with_suffix(suffix)
    try:
        target.write_bytes(out)
    except OSError:
        return None
    return target
