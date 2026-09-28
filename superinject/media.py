"""媒体类型判定：被注入进程里取出的资源该用哪种方式预览。

只做纯字符串/字节判断，不依赖平台，便于单测。
"""

from __future__ import annotations

IMAGE_EXTS = {
    "png", "jpg", "jpeg", "jpe", "gif", "bmp", "webp", "ico", "cur",
    "tif", "tiff", "avif", "heic", "svg", "apng",
}
VIDEO_EXTS = {
    "mp4", "m4v", "avi", "mkv", "mov", "webm", "wmv", "flv", "mpg", "mpeg",
    "ts", "3gp", "ogv", "asf", "rmvb",
}
AUDIO_EXTS = {
    "wav", "mp3", "ogg", "oga", "flac", "m4a", "aac", "wma", "mid", "midi",
    "opus", "aiff", "ape", "amr",
}

KIND_IMAGE = "image"
KIND_VIDEO = "video"
KIND_AUDIO = "audio"
KIND_OTHER = "other"

# C 侧也用同一份「值得从内存里拷出来」的扩展名集合（见 native/agent.c）
FALLBACK_EXT = "bin"


def ext_of(path_or_name: str) -> str:
    """取小写扩展名（不含点）。无扩展名返回空串。"""
    name = str(path_or_name).replace("\\", "/").rstrip("/").split("/")[-1]
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1].lower()


def kind_for_ext(ext: str) -> str:
    e = str(ext).lower().lstrip(".")
    if e in IMAGE_EXTS:
        return KIND_IMAGE
    if e in VIDEO_EXTS:
        return KIND_VIDEO
    if e in AUDIO_EXTS:
        return KIND_AUDIO
    return KIND_OTHER


def kind_for_path(path_or_name: str) -> str:
    return kind_for_ext(ext_of(path_or_name))


def is_media(path_or_name: str) -> bool:
    return kind_for_path(path_or_name) != KIND_OTHER


def kind_for(item: dict) -> str:
    """根据 DLL 返回的资源条目推断预览类型。

    优先用内容嗅探出的扩展名，其次用来源文件的扩展名。
    """
    for key in ("ext", "origin", "path", "module"):
        value = item.get(key)
        if not value:
            continue
        k = kind_for_path(value)
        if k != KIND_OTHER:
            return k
    return KIND_OTHER


def preview_bytes_limit(kind: str) -> int:
    """多大的文件还值得直接预览（超出只给下载/导出）。"""
    return {
        KIND_IMAGE: 32 * 1024 * 1024,
        KIND_AUDIO: 64 * 1024 * 1024,
        KIND_VIDEO: 512 * 1024 * 1024,
    }.get(kind, 0)


def _module_path_from_item(item: dict) -> str:
    return str(item.get("module") or "")


def build_preview_item(item: dict, url: str = "") -> dict:
    """把 DLL 的资源条目整理成前端可直接用的结构（纯逻辑，可单测）。

    ``url`` 由调用方（controller + PreviewServer）算好后传入。
    """
    path = str(item.get("path") or "")
    origin = str(item.get("origin") or "")
    ext = str(item.get("ext") or ext_of(path) or FALLBACK_EXT).lower()
    kind = kind_for({**item, "ext": ext})
    size = int(item.get("size") or 0)
    source = str(item.get("source") or "resource")

    previewable = bool(url) and kind != KIND_OTHER and size <= preview_bytes_limit(kind)
    out = {
        "path": path,
        "origin": origin or path,
        "module": _module_path_from_item(item),
        "ext": ext,
        "kind": kind,
        "size": size,
        "source": source,
        "rtype": int(item.get("rtype") or 0),
        "truncated": bool(item.get("truncated")),
        "url": url if previewable else "",
        "previewable": previewable,
    }
    # 保留调用方补充的字段（例如 DIB 转换前的原始 dump 路径）
    for key, value in item.items():
        out.setdefault(key, value)
    return out
