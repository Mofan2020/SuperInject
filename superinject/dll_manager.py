"""内置 DLL 的完整性校验与自动修复。

设计要点（对应需求「自检2」）：

* 打包进 exe 的 DLL 以字节形式内嵌在 ``superinject.embedded.dll_payload`` 中；
  同时内嵌两份：``x64`` 与 ``x86``，分别放在 ``DATA_B64`` 与 ``DATA_B64_X86``；
* SHA256 **完全由程序运行时计算**，源码与配置里都不出现任何手写哈希；
* 启动时计算「内嵌 DLL 的 SHA」与「磁盘上 DLL 的 SHA」并比较，
  不一致（或文件缺失）时自动用内嵌副本覆盖。
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

DLL_FILENAME = "SuperInjectAgent.dll"
DLL_FILENAME_X86 = "SuperInjectAgent_x86.dll"

# 哪个 arch 对应哪个磁盘文件名（不存在则视为「该位数未内嵌」）。
DLL_FILENAMES = {"x64": DLL_FILENAME, "x86": DLL_FILENAME_X86}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: os.PathLike | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    action: str                       # ok / replaced / created / failed
    embedded_sha: str = ""
    disk_sha: str = ""
    path: Optional[Path] = None
    message: str = ""
    details: dict = field(default_factory=dict)


def _base_dir() -> Path:
    """exe 所在目录（PyInstaller 冻结后为 sys.executable 的目录）。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def _writable_dir(base: Path) -> Path:
    """返回一个确实可写的目录：优先 ``base``，不行就退到用户目录。

    单文件 exe 经常被放进 Program Files、只读共享盘或压缩包解出来的目录，
    这时把内置 DLL 释放到 exe 旁边会直接失败（写文件报拒绝访问）。
    这里先探测再决定，保证自检2 在任何位置都能把 DLL 释放出来。
    """
    try:
        base.mkdir(parents=True, exist_ok=True)
        probe = base / ".si_write_probe"
        probe.write_bytes(b"")
        probe.unlink()
        return base
    except OSError:
        fallback = Path(os.environ.get("LOCALAPPDATA")
                        or tempfile.gettempdir()) / "SuperInject"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def target_dll_path(arch: str = "x64") -> Path:
    env = os.environ.get("SUPERINJECT_DLL_PATH")
    if env and arch.lower() == "x64":
        return Path(env)
    env_x86 = os.environ.get("SUPERINJECT_DLL_PATH_X86")
    if env_x86 and arch.lower() == "x86":
        return Path(env_x86)
    return _writable_dir(_base_dir()) / DLL_FILENAMES.get(arch.lower(), DLL_FILENAME)


def dll_for_arch(arch: str) -> Optional[Path]:
    """返回对应 arch 的 DLL 路径（含环境变量/开发构建回退）。

    None 表示该位数 DLL 不可用（既未内嵌，也没有本地构建产物）。
    """
    arch = arch.lower()
    if arch not in DLL_FILENAMES:
        return None
    target = target_dll_path(arch)
    if target.exists():
        return target
    if arch == "x86":
        dev = _dev_build_dll_x86()
        if dev and dev.exists():
            return dev
    return None


def embedded_bytes(arch: str = "x64") -> Optional[bytes]:
    """取出内嵌的 DLL 字节；未打包的开发环境下返回 None。

    ``arch`` 取 ``"x64"`` / ``"x86"``。``x86`` 未内嵌时返回 None（不抛），
    调用方按「该位数暂不可用」处理。
    """
    try:
        from .embedded import dll_payload  # type: ignore
    except Exception:
        return None
    key = "DATA_B64_X86" if arch.lower() == "x86" else "DATA_B64"
    data = getattr(dll_payload, key, "") or ""
    if not data:
        return None
    try:
        return base64.b64decode(data)
    except Exception:
        return None


def available_arches() -> list[str]:
    """运行时可用的内嵌 DLL 位数列表。"""
    out = []
    for a in ("x64", "x86"):
        if embedded_bytes(a):
            out.append(a)
    return out


def _dev_build_dll() -> Optional[Path]:
    """开发模式下的 fallback：native/build/SuperInjectAgent.dll"""
    p = Path(__file__).resolve().parent.parent / "native" / "build" / DLL_FILENAME
    return p if p.exists() else None


def _dev_build_dll_x86() -> Optional[Path]:
    p = Path(__file__).resolve().parent.parent / "native" / "build" / DLL_FILENAME_X86
    return p if p.exists() else None


def _atomic_write(target: Path, data: bytes) -> Optional[str]:
    """写入目标文件；若被占用则先改名再写。返回 None 表示成功。"""
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd, tmp = tempfile.mkstemp(dir=str(target.parent), suffix=".tmp")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.replace(tmp, target)
            return None
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except (PermissionError, OSError):
        # 目标可能仍被已注入的进程占用：改名让路，再写入
        try:
            backup = target.with_suffix(target.suffix + ".old")
            if backup.exists():
                backup.unlink()
            os.replace(target, backup)
        except OSError:
            pass
        try:
            target.write_bytes(data)
        except OSError as exc:
            return f"写入失败: {exc}"
        try:
            backup = target.with_suffix(target.suffix + ".old")
            if backup.exists():
                backup.unlink()
        except OSError:
            pass
        return None


def verify_and_sync(path: Optional[os.PathLike | str] = None,
                    force: bool = False,
                    arch: str = "x64") -> VerifyResult:
    """自检2：校验磁盘上的 DLL 与内嵌副本是否一致，必要时自动替换。

    ``arch`` 默认 ``"x64"``；x86 调用方单独跑这个函数。
    """
    arch = arch.lower()
    target = Path(path) if path else target_dll_path(arch)
    emb = embedded_bytes(arch)
    source_desc = "内置副本"

    if emb is None:
        if arch == "x64":
            dev = _dev_build_dll()
        elif arch == "x86":
            dev = _dev_build_dll_x86()
        else:
            dev = None
        if dev is None:
            return VerifyResult(
                ok=False, action="failed", path=target,
                message=f"未找到 {arch} 内嵌 DLL，且尚未编译 native/agent.c。"
                        "请运行 python build/build_native.py 或使用 Release 版。",
            )
        emb = dev.read_bytes()
        source_desc = f"开发构建产物 {dev}"

    embedded_sha = sha256_bytes(emb)
    exists = target.exists()
    disk_sha = sha256_file(target) if exists else ""

    if exists and not force and disk_sha == embedded_sha:
        return VerifyResult(ok=True, action="ok", embedded_sha=embedded_sha,
                            disk_sha=disk_sha, path=target,
                            message="DLL 校验通过")

    if force:
        action = "replaced"
        msg = "已强制重写 DLL"
    elif not exists:
        action = "created"
        msg = "已释放内置 DLL"
    else:
        action = "replaced"
        msg = f"DLL 校验不一致（磁盘 {disk_sha[:12]}… ≠ 内置 {embedded_sha[:12]}…），已自动替换"

    err = _atomic_write(target, emb)
    if err:
        return VerifyResult(ok=False, action="failed", embedded_sha=embedded_sha,
                            disk_sha=disk_sha, path=target,
                            message=f"{msg}失败：{err}"
                                    "（请以管理员身份运行，或关闭仍在运行的目标进程）")

    final_sha = sha256_file(target)
    return VerifyResult(ok=True, action=action, embedded_sha=embedded_sha,
                        disk_sha=final_sha, path=target,
                        message=msg, details={"source": source_desc})


def backup_dll(path: Optional[os.PathLike | str] = None) -> Optional[Path]:
    """备份当前磁盘上的 DLL，便于回滚。"""
    target = Path(path) if path else target_dll_path()
    if not target.exists():
        return None
    dest = target.with_suffix(target.suffix + ".bak")
    shutil.copy2(target, dest)
    return dest
