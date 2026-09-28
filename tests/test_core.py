"""纯逻辑单元测试：版本比较、管道帧协议、十六进制模式解析。"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject.ipc import decode_frames, encode_frame, normalize_hex, parse_int
from superinject.version import compare_version, pipe_name


# ------------------------------------------------------------------ 版本

@pytest.mark.parametrize("a,b,expect", [
    ("1.0.0", "1.0.0", 0),
    ("1.0.1", "1.0.0", 1),
    ("1.0.0", "1.0.1", -1),
    ("v2.0", "1.9.9", 1),
    ("1.2", "1.2.0", 0),
    ("1.10", "1.9", 1),
    ("1.0.0", "1.0", 0),
])
def test_compare_version(a, b, expect):
    assert compare_version(a, b) == expect


def test_pipe_name():
    assert pipe_name(1234, 5678) == r"\\.\pipe\SuperInject-1234-5678"


# ------------------------------------------------------------------ 帧协议

def test_encode_decode_roundtrip():
    msg = {"type": "mem_read", "address": 0x7FFE00, "id": 3}
    frame = encode_frame(msg)
    size = struct.unpack_from("<I", frame, 0)[0]
    assert size == len(frame) - 4

    frames, rest = decode_frames(bytearray(frame))
    assert frames == [msg]
    assert rest == bytearray()


def test_decode_multiple_and_partial():
    buf = bytearray()
    buf.extend(encode_frame({"type": "ping", "id": 1}))
    buf.extend(encode_frame({"type": "ping", "id": 2}))
    frames, rest = decode_frames(buf)
    assert [f["id"] for f in frames] == [1, 2]
    assert rest == bytearray()


def test_decode_partial_frame_waits():
    frame = encode_frame({"type": "ping", "id": 9})
    buf = bytearray(frame[:-3])
    frames, rest = decode_frames(buf)
    assert frames == [] and len(rest) == len(frame) - 3
    buf.extend(frame[-3:])
    frames, rest = decode_frames(buf)
    assert frames[0]["id"] == 9


def test_decode_unicode_payload():
    msg = {"type": "note", "text": "内存 ❄ freeze"}
    frames, _ = decode_frames(bytearray(encode_frame(msg)))
    assert frames[0]["text"] == "内存 ❄ freeze"


def test_decode_rejects_bad_length():
    with pytest.raises(ValueError):
        decode_frames(bytearray(struct.pack("<I", 0)))


# ------------------------------------------------------------------ 十六进制

def test_normalize_hex_plain():
    pat, mask = normalize_hex("4D 5A 90 00")
    assert pat == "4d5a9000"
    assert mask == "ffffffff"


def test_normalize_hex_wildcard():
    pat, mask = normalize_hex("4D 5A ?? ??")
    assert pat == "4d5a0000"
    assert mask == "ffff0000"


def test_normalize_hex_forms():
    assert normalize_hex("4d5a90")[0] == "4d5a90"
    assert normalize_hex("4d,5a,90")[0] == "4d5a90"


def test_normalize_hex_rejects_garbage():
    with pytest.raises(ValueError):
        normalize_hex("zz")
    with pytest.raises(ValueError):
        normalize_hex("   ")


def test_parse_int():
    assert parse_int("0x1F40", 0) == 8000
    assert parse_int("1234") == 1234
    assert parse_int("bad", 42) == 42
