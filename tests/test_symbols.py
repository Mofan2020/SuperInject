"""``symbols.py`` 的离线单测 — 纯 Python，无 Windows 依赖。"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject import symbols


def test_build_index_collects_exports_per_module():
    info = {
        "modules": [
            {"name": "user32.dll", "path": r"C:\Windows\System32\user32.dll",
             "base": 0x7FFE0000, "size": 0x100000, "exports_count": 2,
             "exports": [
                 {"name": "MessageBoxW", "rva": 0x1234, "ord": 1234},
                 {"name": "GetForegroundWindow", "rva": 0x2500, "ord": 5678},
             ]},
            {"name": "kernel32.dll", "path": r"C:\Windows\System32\kernel32.dll",
             "base": 0x7FFC0000, "size": 0x80000},
        ]
    }
    idx = symbols.build_module_index(info["modules"])
    assert set(idx) == {"user32.dll", "kernel32.dll"}
    assert idx["user32.dll"]["base"] == 0x7FFE0000
    assert idx["user32.dll"]["exports_count"] == 2
    # kernel32 没传 exports = 没拉过
    assert idx["kernel32.dll"]["exports"] == []


def test_resolve_address_finds_module_and_offset():
    idx = symbols.build_module_index([{
        "name": "demo.dll", "base": 0x10000, "size": 0x20000,
        "exports": [
            {"name": "CreateThing", "rva": 0x1500, "ord": 1},
            {"name": "", "rva": 0x200, "ord": 2},
        ],
    }])
    # 不在区间内
    assert symbols.resolve_address(idx, 0x50000) is None
    # 区间内但无导出
    hit = symbols.resolve_address(idx, 0x10100)
    assert hit and hit[0] == "demo.dll" and hit[1] == 0x100 and hit[2] is None
    # 区间内并落在符号上
    hit = symbols.resolve_address(idx, 0x11500)
    assert hit and hit[0] == "demo.dll" and hit[1] == 0x1500
    assert hit[2] == "CreateThing"
    # rva==0x200 也在区间
    hit = symbols.resolve_address(idx, 0x10200)
    assert hit and hit[2] is None   # 这条名字是空字符串（ordinal-only）


def test_format_address_uses_module_and_offset():
    idx = symbols.build_module_index([{
        "name": "demo.dll", "base": 0x10000, "size": 0x20000,
        "exports": [{"name": "Create", "rva": 0x100, "ord": 1}],
    }])
    assert symbols.format_address(idx, 0x10100).startswith("demo")
    assert "Create" in symbols.format_address(idx, 0x10100)
    assert symbols.format_address(idx, 0x99999) == "0x99999"


def test_lookup_export_substring_and_limit():
    idx = symbols.build_module_index([{
        "name": "user32.dll", "base": 0x10000, "size": 0x10000,
        "exports": [
            {"name": "MessageBoxW", "rva": 0x100, "ord": 1},
            {"name": "MessageBoxA", "rva": 0x110, "ord": 2},
            {"name": "GetForegroundWindow", "rva": 0x200, "ord": 3},
        ],
    }])
    out = symbols.lookup_export(idx, "user32.dll", "message")
    assert {o["name"] for o in out} == {"MessageBoxW", "MessageBoxA"}
    capped = symbols.lookup_export(idx, "user32.dll", "", limit=2)
    assert len(capped) == 2
    assert symbols.lookup_export(idx, "no-such-module", "") == []


def test_merge_export_payload_updates_index():
    idx = symbols.build_module_index([
        {"name": "kernel32.dll", "base": 0x20000, "size": 0x10000},
    ])
    n = symbols.merge_export_payload(idx, "kernel32.dll", {
        "count": 3,
        "exports": [
            {"name": "LoadLibraryW", "rva": 0x100, "ord": 1},
            {"name": "LoadLibraryA", "rva": 0x110, "ord": 2},
            {"name": "GetProcAddress", "rva": 0x200, "ord": 3},
        ],
    })
    assert n == 3
    assert idx["kernel32.dll"]["exports_count"] == 3
    # 现在能解析出符号了
    hit = symbols.resolve_address(idx, 0x20100)
    assert hit and hit[2] == "LoadLibraryW"
