"""启动时的后台更新检查（GitHub Releases）。

流程：后台线程请求 GitHub 最新 Release → 与当前版本比较 → 有新版则通知前端，
由用户确认后再下载 → 解压到临时目录 → 关闭本程序后由生成的批处理脚本完成替换。
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
import threading
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from .version import GITHUB_API, GITHUB_RELEASES, GITHUB_RELEASES_API, __version__, compare_version

log = logging.getLogger("supinject.updater")

USER_AGENT = "SuperInject-Updater"


@dataclass
class ReleaseInfo:
    version: str
    url: str
    assets: list[dict]
    notes: str = ""
    prerelease: bool = False
    published_at: str = ""

    @property
    def has_newer(self) -> bool:
        return compare_version(self.version, __version__) > 0

    def windows_asset(self) -> Optional[dict]:
        for a in self.assets:
            name = a.get("name", "").lower()
            if name.endswith(".zip") and "win" in name:
                return a
        for a in self.assets:
            if a.get("name", "").lower().endswith(".zip"):
                return a
        return None


def _get_json(url: str, timeout: float):
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _to_release(data: dict) -> Optional[ReleaseInfo]:
    if not isinstance(data, dict) or data.get("draft"):
        return None
    tag = (data.get("tag_name") or data.get("name") or "").strip()
    if not tag:
        return None
    return ReleaseInfo(
        version=re.sub(r"^v", "", tag),
        url=data.get("html_url") or GITHUB_RELEASES,
        assets=data.get("assets") or [],
        notes=(data.get("body") or "")[:4000],
        prerelease=bool(data.get("prerelease")),
        published_at=str(data.get("published_at") or data.get("created_at") or ""),
    )


def fetch_latest(timeout: float = 8.0) -> Optional[ReleaseInfo]:
    """查询 GitHub 最新 Release，失败返回 None（不阻塞启动）。

    优先列 Release 列表：``/releases/latest`` 在没有「正式版」时（例如仓库只发过
    预发布版本）会直接返回 404，只看它会把「有更新」误判成「没有 Release」。
    因此这里先拉列表、跳过 draft、按发布时间取最新，列表接口不可用时才退回 latest。
    """
    errors: list[str] = []
    try:
        data = _get_json(GITHUB_RELEASES_API, timeout)
        if isinstance(data, list):
            candidates = [r for r in data if not r.get("draft")]
            candidates.sort(key=lambda r: str(r.get("published_at")
                                               or r.get("created_at") or ""),
                            reverse=True)
            for raw in candidates:
                info = _to_release(raw)
                if info:
                    return info
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        errors.append(f"list: {exc}")

    try:
        data = _get_json(GITHUB_API, timeout)
        info = _to_release(data if isinstance(data, dict) else {})
        if info:
            return info
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        errors.append(f"latest: {exc}")

    log.info("更新检查失败: %s", "; ".join(errors) or "无可用 Release")
    return None


def download(url: str, dest: Path,
             progress: Optional[Callable[[int, int], None]] = None) -> Path:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length") or 0)
        done = 0
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(1 << 16)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
    return dest


def extract(zip_path: Path, dest: Path) -> Path:
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)
    # 若 zip 内只有一层同名目录，则取之
    entries = list(dest.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def _install_dir() -> Path:
    import sys

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def stage_update(zip_path: Path) -> Path:
    """解压新版到临时目录，返回包含新版可执行文件的目录。"""
    tmp = Path(tempfile.mkdtemp(prefix="supinject_update_"))
    return extract(zip_path, tmp)


def write_update_script(src_dir: Path, exe_name: str = "SuperInject.exe",
                        pid: Optional[int] = None) -> Path:
    """生成一个等待主程序退出后再覆盖的批处理，并立即启动它。"""
    pid = pid or os.getpid()
    bat = Path(tempfile.gettempdir()) / f"supinject_update_{pid}.cmd"
    bat.write_text(
        "@echo off\r\n"
        "chcp 65001 >nul\r\n"
        f"echo 正在更新 SuperInject...\r\n"
        f"ping -n 3 127.0.0.1 >nul\r\n"
        f'for /f "tokens=2" %%p in (\'tasklist /fi "PID eq {pid}" /nh\') do taskkill /PID {pid} /F >nul 2>&1\r\n'
        f"timeout /t 2 /nobreak >nul\r\n"
        f'xcopy /Y /I /E /Q "{src_dir}\\*" "{_install_dir()}" >nul\r\n'
        f'echo 更新完成，正在重新启动...\r\n'
        f'start "" "{_install_dir() / exe_name}"\r\n'
        f"del /q \"%~f0\"\r\n",
        encoding="utf-8",
    )
    os.startfile(str(bat))  # type: ignore[attr-defined]
    return bat


class UpdateChecker:
    """启动即在后台跑的更新检查。"""

    def __init__(self, on_found: Callable[[ReleaseInfo], None] | None = None,
                 on_error: Callable[[str], None] | None = None):
        self.on_found = on_found
        self.on_error = on_error
        self._thread: Optional[threading.Thread] = None
        self.latest: Optional[ReleaseInfo] = None

    def start(self, delay: float = 1.0) -> None:
        def run():
            import time

            time.sleep(delay)
            rel = fetch_latest()
            if rel is None:
                return
            self.latest = rel
            if rel.has_newer and self.on_found:
                try:
                    self.on_found(rel)
                except Exception:  # pragma: no cover
                    log.exception("on_found 回调失败")

        self._thread = threading.Thread(target=run, name="si-update", daemon=True)
        self._thread.start()
