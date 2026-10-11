"""模块导出表 → 符号解析 / 反向查找。

不做 PDB / symsrv / dbghelp 依赖。只用 ``info`` 与 ``exports`` 命令拿到的
``[name, rva, ord]`` 列表在控制器侧维护一张"module+exports"索引，提供：

* ``build_module_index(modules_response, ...)`` —— 把 info 响应整理成索引；
* ``resolve_address(index, addr)`` —— 给定地址，找出它属于哪个模块下的
  ``module+<offset>`` 形式（不解决符号的话就直接 ``module+0x123``）；
* ``lookup_export(index, module_name, name_substr)`` —— 给定模块名，按
  名字子串匹配导出（GUI 模糊搜索框用）。

接口足够薄，不强加任何 PE 解析逻辑；这样单元测试只需造假的 info 响应就
能跑，Windows 上的真集成测试不需要再说一遍 PE 解析。
"""
from __future__ import annotations

import re
from typing import Dict, Iterable, List, Optional, Tuple

ADDR_FMT_RE = re.compile(r"^(0x)?([0-9a-fA-F]+)$")


def parse_int(text: str, default: int = 0) -> int:
    """与 ipc.parse_int 一致；这里复制一份避免额外 import（这模块本来就轻）。"""
    t = str(text).strip().lower().replace("_", "")
    m = ADDR_FMT_RE.match(t)
    if not m:
        try:
            return int(t)
        except ValueError:
            return default
    return int(m.group(2), 16) if m.group(1) else int(m.group(2), 10)


def build_module_index(modules: Iterable[dict]) -> Dict[str, dict]:
    """把 ``info`` 响应里的 ``modules`` 字段组装成 ``{name: module}``。

    每个 module dict 自带 ``exports`` 数组时也保留下来 —— GUI 默认不显示，
    需要时按需 ``fetch_module_exports`` 单独拉。
    """
    out: Dict[str, dict] = {}
    for m in modules:
        name = str(m.get("name") or "")
        if not name:
            continue
        out[name] = {
            "name": name,
            "path": str(m.get("path") or ""),
            "base": int(m.get("base") or 0),
            "size": int(m.get("size") or 0),
            "exports": list(m.get("exports") or []),
            "exports_count": int(m.get("exports_count") or 0),
        }
    return out


def resolve_address(index: Dict[str, dict], address: int
                    ) -> Optional[Tuple[str, int, Optional[str]]]:
    """在 ``index`` 里找一个地址落在哪个模块区间里。

    返回 ``(module_name, offset, export_name_or_None)``，找不到模块返回 None。
    注意：``exports`` 列出的 rva 是相对模块基址的，相加与 ``base+offset`` 相等
    才认为这一导出与给定地址一致。
    """
    if address <= 0:
        return None
    for mod in index.values():
        base = mod["base"]
        size = mod["size"]
        if base and base <= address < base + max(size, 0):
            offset = address - base
            name: Optional[str] = None
            for exp in mod.get("exports") or []:
                if int(exp.get("rva") or 0) == offset and exp.get("name"):
                    name = str(exp["name"])
                    break
            return (mod["name"], offset, name)
    return None


def format_address(index: Dict[str, dict], address: int) -> str:
    """``module!symbol+0x42`` 形式；无符号时 ``module+0x123``。"""
    if address <= 0:
        return "?"
    hit = resolve_address(index, address)
    if hit is None:
        return f"0x{address:x}"
    mod_name, offset, sym = hit
    if sym:
        return f"{mod_name}!{sym}+0x{offset - 0:x}"
    return f"{mod_name}+0x{offset:x}"


def lookup_export(index: Dict[str, dict], module_name: str,
                  name_substr: str, *, limit: int = 64) -> List[dict]:
    """在 ``index[module_name].exports`` 里模糊匹配 ``name_substr``。

    返回 ``[{name, rva, ord, module}, ...]``。若 ``name_substr`` 为空则返回前
    ``limit`` 条。
    """
    mod = index.get(module_name)
    if not mod:
        return []
    needle = (name_substr or "").lower()
    out: List[dict] = []
    for exp in mod.get("exports") or []:
        nm = str(exp.get("name") or "")
        if needle and needle not in nm.lower():
            continue
        out.append({**exp, "module": module_name})
        if len(out) >= limit:
            break
    return out


def merge_export_payload(index: Dict[str, dict], module_name: str,
                         payload: dict) -> int:
    """把 ``exports`` 命令返回的 exports 数组注入 ``index[module_name]``。

    没有该模块时建一个空条目。返回新导出条数。
    """
    items = list(payload.get("exports") or [])
    mod = index.setdefault(module_name, {
        "name": module_name,
        "path": "",
        "base": 0,
        "size": 0,
        "exports": [],
        "exports_count": 0,
    })
    mod["exports"] = items
    mod["exports_count"] = int(payload.get("count") or len(items))
    return mod["exports_count"]


# P2 硬件断点：把 ``module!symbol+0x42`` 这种字符串解析回地址。
#
# 形式与限制：
#   ``module``                模块名（不计大小写）
#   ``module+0x42``           无符号：模块基址 + 该偏移
#   ``module!symbol``         符号入口（导出表匹配第一个）
#   ``module!symbol+0x42``    符号入口 + 偏移
#   ``0x401000``              原始 16/10 进制整数 —— 直接返回
#
# 失败返回 ``None``，让 Controller 决定是否 fallback 到原始数字地址。
#
# 正则说明：先按 ``!`` 切成 module / rest；rest 段再按可选 ``+offset`` 切。
# 这样 ``foo.dll!bar+0x42`` 不会因为 ``+`` 在两个字符组里都要排除而配失败。
_SYMBOL_REST_RE = re.compile(
    r"^(?P<sym>[^+]*)"
    r"(?P<off>\s*\+\s*0x[0-9a-fA-F]+|\s*\+\s*\d+)?\s*$"
)


def resolve_symbol(index: Dict[str, dict], target: str
                   ) -> Optional[Tuple[int, str, int, Optional[str]]]:
    """解析 ``module!symbol+offset`` 形式的字符串，返回 ``(addr, module,
    offset, symbol_or_None)``。

    - 字符串看起来像纯数字（"0x401000" / "4198400"） → 直接转 int 返回；
    - 含 ``!`` 或 ``+`` 时按 *module[!symbol][+offset]* 解析；
    - 该模块尚未有 ``exports`` 列表时按 offset 形式可用（只按 base+offset）；
    - 找不到模块 / 找不到符号 → 返回 None。
    """
    if target is None:
        return None
    text = str(target).strip()
    if not text:
        return None
    # 纯数字地址 → 直接返回
    if re.fullmatch(r"(0x)?[0-9a-fA-F]+", text):
        addr = parse_int(text, 0)
        return (addr, "", 0, None) if addr else None

    # 先按 ``!`` 切；rest 段再细分。
    if "!" in text:
        mod_name, _, rest = text.partition("!")
    elif "+" in text:
        # 没有 ``!`` —— 模块名 + 偏移
        mod_name, _, rest = text.partition("+")
        rest = "+" + rest
    else:
        # 单段（纯模块名，没有 ! 和 +） —— base + 0
        mod_name = text
        rest = ""

    mod_name = mod_name.strip()
    if not mod_name:
        return None
    m = _SYMBOL_REST_RE.match(rest or "")
    if not m:
        return None
    sym_name = (m.group("sym") or "").strip()
    off_text = (m.group("off") or "").strip()
    offset = parse_int(off_text.replace("+", "").strip() or "0", 0) if off_text else 0

    # 不计大小写匹配 module 名
    lookup = {k.lower(): v for k, v in index.items()}
    mod = lookup.get(mod_name.lower())
    if not mod:
        return None
    base = int(mod.get("base") or 0)
    if not base:
        return None
    if sym_name:
        # 在模块导出里找名字完全匹配的（名字包含子串也行 —— 给"模糊匹配"留口）
        for exp in mod.get("exports") or []:
            name = str(exp.get("name") or "")
            if not name:
                continue
            if name == sym_name or sym_name.lower() in name.lower():
                rva = int(exp.get("rva") or 0)
                return (base + rva + offset, mod["name"], offset, name)
        return None
    return (base + offset, mod["name"], offset, None)
