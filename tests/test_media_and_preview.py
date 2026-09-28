"""媒体识别、PE 资源转换、本地预览服务的测试（全部跨平台可跑）。"""

from __future__ import annotations

import struct
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from superinject import media, resconv
from superinject.fileserver import PreviewServer

# ------------------------------------------------------------------ 媒体类型

@pytest.mark.parametrize("name,kind", [
    ("a.png", "image"), ("a.JPG", "image"), ("logo.webp", "image"),
    ("icon.ico", "image"), ("pic.svg", "image"), ("x.avif", "image"),
    ("movie.mp4", "video"), ("clip.MKV", "video"), ("v.webm", "video"),
    ("bgm.mp3", "audio"), ("s.wav", "audio"), ("x.FLAC", "audio"),
    ("C:\\Windows\\System32\\notepad.exe", "other"),
    ("res_100_1.bin", "other"),
    ("noext", "other"),
])
def test_kind_for_path(name, kind):
    assert media.kind_for_path(name) == kind


def test_kind_for_prefers_sniffed_ext():
    item = {"ext": "png", "origin": "C:\\stuff\\data.bin", "path": "x\\res.png"}
    assert media.kind_for(item) == "image"


def test_kind_for_falls_back_to_origin():
    item = {"ext": "", "origin": "C:\\app\\assets\\clip.mp4", "path": ""}
    assert media.kind_for(item) == "video"


def test_build_preview_item_marks_previewable():
    item = {"path": "C:\\Temp\\SuperInject\\100\\res_1.png", "ext": "png",
            "size": 1024, "source": "mapped", "origin": "C:\\app\\a.png"}
    out = media.build_preview_item(item, "http://127.0.0.1:1/100/res_1.png")
    assert out["kind"] == "image" and out["previewable"]
    assert out["url"].startswith("http://127.0.0.1:1/")
    assert out["origin"] == "C:\\app\\a.png"


def test_build_preview_item_without_url_is_export_only():
    item = {"path": "C:\\Temp\\x.png", "ext": "png", "size": 10}
    out = media.build_preview_item(item, "")
    assert out["previewable"] is False and out["url"] == ""


def test_build_preview_item_huge_file_not_previewed():
    item = {"path": "C:\\Temp\\x.mp4", "ext": "mp4", "size": 5 * 1024 ** 3}
    out = media.build_preview_item(item, "http://x/x.mp4")
    assert out["kind"] == "video" and out["previewable"] is False


# ------------------------------------------------------------------ DIB 转换

def make_dib(width=2, height=2, bit_count=24, extra=b""):
    header = struct.pack("<IiiHHIIiiII", 40, width, height, 1, bit_count,
                         0, 0, 0, 0, 0, 0)
    return header + extra + b"\x10" * (width * height * 3)


def test_dib_to_bmp_has_file_header():
    dib = make_dib()
    out = resconv.dib_to_bmp(dib)
    assert out and out[:2] == b"BM"
    size, _, _, offset = struct.unpack_from("<IHHI", out, 2)
    assert size == len(out)
    assert offset == 14 + 40                    # 像素数据紧跟文件头 + 信息头
    assert out[14:] == dib                      # 信息头与像素原样保留
    assert out[offset:] == dib[40:]


def test_dib_to_bmp_with_palette():
    """8 位色带 256 色调色板时，文件头里的像素偏移要跳过调色板。"""
    dib = make_dib(bit_count=8) + b"\x00" * (256 * 4)
    out = resconv.dib_to_bmp(dib)
    assert out is not None
    _, _, _, offset = struct.unpack_from("<IHHI", out, 2)
    assert offset == 14 + 40 + 256 * 4


def test_dib_to_bmp_rejects_garbage():
    assert resconv.dib_to_bmp(b"") is None
    assert resconv.dib_to_bmp(b"\x00" * 8) is None


def test_dib_to_ico_halves_height():
    """ICON 的 DIB 高度是「图像 + AND 掩码」，目录里必须写回一半。"""
    dib = make_dib(width=32, height=64, bit_count=32)
    out = resconv.dib_to_ico(dib)
    assert out is not None
    reserved, icon_type, count = struct.unpack_from("<HHH", out, 0)
    assert (reserved, icon_type, count) == (0, 1, 1)
    width, height = out[6], out[7]
    assert (width, height) == (32, 32)
    (_, _, _, _, planes, bit_count, bytes_in_res, offset) = \
        struct.unpack_from("<BBBBHHII", out, 6)
    assert planes == 1 and bit_count == 32
    assert bytes_in_res == len(dib) and offset == 22
    assert out[22:] == dib


def test_dib_to_ico_marks_256_as_zero():
    dib = make_dib(width=256, height=512, bit_count=32)
    out = resconv.dib_to_ico(dib)
    assert out is not None and out[6] == 0 and out[7] == 0


def test_dib_to_cur_uses_hotspot():
    dib = make_dib(width=16, height=32, bit_count=32)
    raw = struct.pack("<HH", 3, 5) + dib
    out = resconv.dib_to_ico(raw, is_cursor=True)
    assert out is not None
    assert struct.unpack_from("<HHH", out, 0)[1] == 2      # type=cursor
    (_, _, _, _, hot_x, hot_y, _, _) = struct.unpack_from("<BBBBHHII", out, 6)
    assert (hot_x, hot_y) == (3, 5)


def test_convert_dump_writes_next_to_dump(tmp_path):
    p = tmp_path / "res_100_1.dib"
    p.write_bytes(make_dib())
    out = resconv.convert_dump(p, resconv.RT_BITMAP)
    assert out is not None and out.name == "res_100_1.bmp"
    assert out.read_bytes()[:2] == b"BM"
    assert resconv.convert_dump(p, 999) is None


# ------------------------------------------------------------------ 预览服务

@pytest.fixture()
def preview(tmp_path):
    root = tmp_path / "SuperInject"
    (root / "100").mkdir(parents=True)
    (root / "100" / "a.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"A" * 100)
    (root / "100" / "big.bin").write_bytes(bytes(range(256)) * 8)
    outside = tmp_path / "secret.txt"
    outside.write_text("nope")
    srv = PreviewServer(root)
    base = srv.start()
    yield srv, base, root, outside
    srv.stop()


def test_preview_server_serves_file(preview):
    srv, base, root, _ = preview
    with urllib.request.urlopen(f"{base}/100/a.png", timeout=5) as r:
        assert r.status == 200
        assert r.read().startswith(b"\x89PNG")
        assert r.headers["Accept-Ranges"] == "bytes"


def test_preview_server_supports_range(preview):
    """<video> 拖动进度依赖 206 Partial Content。"""
    srv, base, root, _ = preview
    req = urllib.request.Request(f"{base}/100/big.bin",
                                 headers={"Range": "bytes=10-19"})
    with urllib.request.urlopen(req, timeout=5) as r:
        assert r.status == 206
        assert r.read() == bytes(range(10, 20))
        assert r.headers["Content-Range"].startswith("bytes 10-19/")


def test_preview_server_rejects_outside_path(preview):
    srv, base, root, _ = preview
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(f"{base}/../secret.txt", timeout=5)
    assert err.value.code in (403, 404)


def test_preview_url_for_inside_and_outside(preview):
    srv, base, root, outside = preview
    url = srv.url_for(root / "100" / "a.png")
    assert url == f"{base}/100/a.png"
    assert srv.url_for(outside) == ""
    assert srv.url_for(root / "nope.png") == f"{base}/nope.png"


def test_preview_server_url_empty_before_start(tmp_path):
    assert PreviewServer(tmp_path).url_for(tmp_path / "a").endswith("a") is False
    assert PreviewServer(tmp_path).base_url == ""
