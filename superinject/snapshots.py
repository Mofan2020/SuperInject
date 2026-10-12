"""内存快照的落盘与索引（P1 内存快照 / diff 用）。

DLL 侧的 ``mem_snapshot`` 命令只把结果以 JSON 形式返回，不落盘；
控制器侧拿回来之后由这里管：

* 每 PID 一份 ``_index.json``（记录快照名 / 时间 / 大小 / SHA256）；
* 每个快照单独一份 ``<name>.json``（带所有 page 详情）方便后续 diff 喂回 DLL。

路径约定：

* Windows：``%LOCALAPPDATA%\\SuperInject\\snapshots\\<pid>\\<name>.json``
  —— ``os.environ['LOCALAPPDATA']``，缺省回退到 ``%USERPROFILE%/AppData/Local``。
* macOS / Linux：``~/.local/share/SuperInject/snapshots/<pid>/<name>.json``
  —— 用 ``platformdirs`` 是新依赖，本项目阶段不引；直接 ``Path.home()`` 自己拼。

依赖：标准库（json / dataclasses / datetime / pathlib）。

写盘尽量**原子**：先写临时再 ``os.replace``；落盘失败立刻抛，
不让前端在快照不完整时还误以为成功。
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional


def snapshot_root(is_windows: Optional[bool] = None) -> Path:
    """当前平台的快照根目录。

    Windows 时 ``LOCALAPPDATA`` 直接用；缺省时回退 ``~/AppData/Local``。
    非 Windows 一律 ``$HOME/.local/share/SuperInject/snapshots``（``HOME`` 缺
    省时回退 :func:`pathlib.Path.home`，Windows 上**也**认 ``HOME`` 兜底
    —— 这条对测试是必须的：``Path.home()`` 在 Windows 上读 ``USERPROFILE``，
    不认 ``HOME``，没有这条兜底 ``is_windows=False`` 的跨平台测试就站不住）。

    ``is_windows`` 只给测试用：让两条分支都能在**任意平台**上被验证。
    不要改用 ``monkeypatch.setattr(os, "name", "posix")`` 之类的做法 —— 那会
    骗过 pathlib，让它在 Windows 上去实例化 ``PosixPath`` 并直接抛
    ``NotImplementedError``（本项目的 windows runner 就是这么红的）。
    """
    if is_windows is None:
        is_windows = os.name == "nt"
    if is_windows:
        base = os.environ.get("LOCALAPPDATA", "").strip()
        if not base:
            base = str(Path.home() / "AppData" / "Local")
        return Path(base) / "SuperInject" / "snapshots"
    home = os.environ.get("HOME") or str(Path.home())
    return Path(home) / ".local" / "share" / "SuperInject" / "snapshots"


@dataclass
class SnapshotIndexEntry:
    """_index.json 里的一条记录。"""

    name: str
    created_at: str         # ISO8601（datetime.isoformat(timespec="seconds")）
    bytes: int = 0
    sha256: str = ""        # 整个快照的全局 SHA256（所有 page sha 串起来 hash 一次）
    pages: int = 0

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "created_at": self.created_at,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "pages": self.pages,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SnapshotIndexEntry":
        return cls(
            name=str(d.get("name", "")),
            created_at=str(d.get("created_at", "")),
            bytes=int(d.get("bytes", 0)),
            sha256=str(d.get("sha256", "")),
            pages=int(d.get("pages", 0)),
        )


@dataclass
class SnapshotStore:
    """按 PID 组织快照：每个 PID 一个目录，目录内是 ``<name>.json`` + ``_index.json``。

    不放线程锁 —— 调用方是控制器单线程（前端的 API 调用天然串行）；
    测试里如果你多线程并发 save，需要自己加锁。
    """

    root: Path = field(default_factory=snapshot_root)

    def pid_dir(self, pid: int) -> Path:
        d = self.root / str(int(pid))
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _index_path(self, pid: int) -> Path:
        return self.pid_dir(pid) / "_index.json"

    def _snap_path(self, pid: int, name: str) -> Path:
        if not name or "/" in name or "\\" in name:
            raise ValueError(f"快照名不合法: {name!r}")
        return self.pid_dir(pid) / f"{name}.json"

    def save(self, pid: int, snapshot: dict) -> Path:
        """把 ``mem_snapshot`` 的返回值原样落盘。

        返回 ``<name>.json`` 的绝对路径。索引里多了 / 改了同步追加。
        """
        name = str(snapshot.get("name", "")).strip()
        if not name:
            raise ValueError("snapshot 缺少 name 字段")
        target = self._snap_path(pid, name)
        _atomic_write_json(target, snapshot)

        # 更新索引（按 name 去重；同名覆盖要刷新 created_at）
        idx = self._read_index(pid)
        now = _now_iso()
        new_entry = SnapshotIndexEntry(
            name=name,
            created_at=now,
            bytes=int(snapshot.get("bytes", 0)),
            sha256=str(snapshot.get("sha256", "")),
            pages=int(snapshot.get("count", 0)),
        )
        replaced = False
        for i, e in enumerate(idx):
            if e.name == name:
                idx[i] = new_entry
                replaced = True
                break
        if not replaced:
            idx.append(new_entry)
        self._write_index(pid, idx)
        return target

    def load(self, pid: int, name: str) -> dict:
        """读单个快照的完整 JSON（带 pages），用于 diff 的输入。"""
        path = self._snap_path(pid, name)
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise KeyError(f"snapshot not found: pid={pid} name={name}") from exc

    def list(self, pid: int) -> List[SnapshotIndexEntry]:
        """返回按 ``created_at`` 升序的索引列表（旧 → 新）。"""
        return list(self._read_index(pid))

    def delete(self, pid: int, name: str) -> bool:
        """删除一个快照（也清掉索引项）。返回是否真的删了什么。"""
        path = self._snap_path(pid, name)
        existed = path.exists()
        try:
            path.unlink()
        except FileNotFoundError:
            existed = False
        idx = [e for e in self._read_index(pid) if e.name != name]
        if len(idx) != sum(1 for _ in self._read_index(pid)):
            self._write_index(pid, idx)
        return existed

    def diff(self, pid: int, name1: str, name2: str) -> dict:
        """读两个已存快照的 pages 列出来；不带 bytes —— byte 级 diff 由
        mem_diff 命令在 DLL 侧算。

        返回 ``{"a": {<snap>}, "b": {<snap>}, "pages_a": [...], "pages_b": [...]}``。
        """
        a = self.load(pid, name1)
        b = self.load(pid, name2)
        return {
            "a": a,
            "b": b,
            "pages_a": list(a.get("pages") or []),
            "pages_b": list(b.get("pages") or []),
        }

    # ---------------------------------------------------------- 索引

    def _read_index(self, pid: int) -> List[SnapshotIndexEntry]:
        path = self._index_path(pid)
        if not path.exists():
            return []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(raw, list):
            return []
        out: List[SnapshotIndexEntry] = []
        for r in raw:
            if isinstance(r, dict):
                out.append(SnapshotIndexEntry.from_dict(r))
        return out

    def _write_index(self, pid: int, entries: List[SnapshotIndexEntry]) -> None:
        path = self._index_path(pid)
        data = [e.to_dict() for e in entries]
        _atomic_write_json(path, data)


def _now_iso() -> str:
    """ISO8601 秒精度的 UTC 字符串（写入索引时统一格式）。"""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _atomic_write_json(path: Path, payload: object) -> None:
    """原子写 JSON：同名临时文件 → ``os.replace`` 替换正式文件。

    中途崩在临时文件阶段不会留下半截 ``<name>.json``，下次 ``list``
    还能干净；这一行承上启下，test_snapshots 里也验证。
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=".tmp_", suffix=".json", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
