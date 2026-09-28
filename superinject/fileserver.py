"""本地预览服务：把「进程资源导出目录」用 127.0.0.1 上的临时 HTTP 服务暴露出来。

为什么不用 ``file://``：pywebview（WebView2）里 ``<video>`` 直接读本地路径既受
本地文件同源策略限制，又需要 HTTP Range 支持才能播放与拖动进度。这里起一个
只监听回环地址、只服务导出目录的最小 HTTP 服务，支持 Range 请求。
"""

from __future__ import annotations

import http.server
import logging
import os
import threading
from pathlib import Path
from typing import Optional

log = logging.getLogger("supinject.fileserver")

_EXTRA_TYPES = {
    ".mp4": "video/mp4",
    ".m4v": "video/mp4",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
    ".mov": "video/quicktime",
    ".avi": "video/x-msvideo",
    ".wmv": "video/x-ms-wmv",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".ogg": "audio/ogg",
    ".oga": "audio/ogg",
    ".flac": "audio/flac",
    ".m4a": "audio/mp4",
    ".aac": "audio/aac",
    ".opus": "audio/opus",
    ".webp": "image/webp",
    ".avif": "image/avif",
    ".ico": "image/x-icon",
    ".cur": "image/x-icon",
    ".bmp": "image/bmp",
    ".tif": "image/tiff",
    ".tiff": "image/tiff",
    ".svg": "image/svg+xml",
    ".bin": "application/octet-stream",
    ".dib": "application/octet-stream",
}


class _RangeHandler(http.server.SimpleHTTPRequestHandler):
    """只读、支持 Range 的静态文件处理器（仅服务导出目录）。"""

    server_version = "SuperInjectPreview/1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # 静默，避免刷日志
        log.debug("%s - %s", self.address_string(), fmt % args)

    def guess_type(self, path):  # type: ignore[override]
        ext = os.path.splitext(str(path))[1].lower()
        if ext in _EXTRA_TYPES:
            return _EXTRA_TYPES[ext]
        return super().guess_type(path)

    def do_POST(self):  # pragma: no cover - 明确拒绝写操作
        self.send_error(405, "Method Not Allowed")

    def send_head(self):  # type: ignore[override]
        path = self.translate_path(self.path)
        if os.path.isdir(path):
            self.send_error(404, "Not a file")
            return None
        try:
            f = open(path, "rb")
        except OSError:
            self.send_error(404, "File not found")
            return None

        try:
            size = os.fstat(f.fileno()).st_size
            ctype = self.guess_type(path)
            start, end, partial = 0, max(size - 1, 0), False

            rng = self.headers.get("Range")
            if rng and rng.startswith("bytes=") and size > 0:
                spec = rng[len("bytes="):].split(",")[0].strip()
                left, _, right = spec.partition("-")
                try:
                    if left:
                        start = int(left)
                        end = int(right) if right else size - 1
                    else:
                        length = int(right)
                        start = max(0, size - length)
                        end = size - 1
                    partial = True
                except ValueError:
                    partial = False
                if partial and (start > end or start >= size):
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    f.close()
                    return None
                end = min(end, size - 1)

            length = end - start + 1 if size else 0
            self.send_response(206 if partial else 200)
            self.send_header("Content-Type", ctype)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            if partial:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            self.end_headers()
            if start:
                f.seek(start)
            self._remaining = length
            return f
        except Exception:  # pragma: no cover - 任何异常都不应拖死服务
            f.close()
            raise

    def copyfile(self, source, outputfile):  # type: ignore[override]
        remaining = getattr(self, "_remaining", None)
        if remaining is None:
            return super().copyfile(source, outputfile)
        while remaining > 0:
            chunk = source.read(min(64 * 1024, remaining))
            if not chunk:
                break
            outputfile.write(chunk)
            remaining -= len(chunk)


class _Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class PreviewServer:
    """回环地址上的只读预览服务。"""

    def __init__(self, root: Optional[Path] = None):
        self.root: Optional[Path] = Path(root).resolve() if root else None
        self._httpd: Optional[_Server] = None
        self._thread: Optional[threading.Thread] = None
        self._port = 0

    # -------------------------------------------------- 生命周期

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._port}" if self._httpd else ""

    @property
    def running(self) -> bool:
        return self._httpd is not None

    def start(self, root: Optional[Path] = None) -> str:
        """启动服务并返回 base url（重复调用只更新根目录）。"""
        if root is not None:
            self.root = Path(root).resolve()
        if self._httpd is not None:
            return self.base_url
        if self.root is None:
            return ""
        self.root.mkdir(parents=True, exist_ok=True)
        handler = lambda *a, **kw: _RangeHandler(  # noqa: E731
            *a, directory=str(self.root), **kw)
        self._httpd = _Server(("127.0.0.1", 0), handler)
        self._port = int(self._httpd.server_address[1])
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="si-preview",
            kwargs={"poll_interval": 0.2}, daemon=True)
        self._thread.start()
        log.info("预览服务已启动 %s -> %s", self.base_url, self.root)
        return self.base_url

    def stop(self) -> None:
        httpd, self._httpd = self._httpd, None
        if httpd is not None:
            try:
                httpd.shutdown()
                httpd.server_close()
            except Exception:  # pragma: no cover
                log.debug("关闭预览服务失败", exc_info=True)
        self._port = 0

    # -------------------------------------------------- 地址

    def url_for(self, path) -> str:
        """把导出根目录下的文件映射成可访问 URL；不在目录内则返回空串。

        DLL 会为每个进程建一个子目录（``<root>\\<pid>\\res_*.png``），
        所以只要路径位于根目录之内就放行，URL 带上相对路径。
        """
        if not self._httpd or self.root is None:
            return ""
        try:
            resolved = Path(path).resolve()
            rel = resolved.relative_to(self.root)
        except Exception:  # pragma: no cover - 越界或无法解析
            return ""
        return f"{self.base_url}/{rel.as_posix()}"
