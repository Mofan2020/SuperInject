"""仓库与 CI 配置的守卫测试。

单独一个文件是为了让「这类失败」一眼可辨：不是功能坏了，而是发布流程的
某个前提不成立了。改动发版流程时先看这里。
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_NOTES = ROOT / "docs" / "release-notes.md"


def test_release_notes_file_exists_and_is_not_empty():
    """发版正文的**唯一来源**是 docs/release-notes.md。

    以前正文写死在 workflow 里，结果是每次发版都靠人记得去改；v1.3.0 时就
    真的漏了，Release 上挂的还是上一版内容。现在由 CI 从文件读，这个测试
    守两件事：文件在、内容非空（CI 的 release job 里也有一道 `test -s`）。
    """
    assert RELEASE_NOTES.exists(), "docs/release-notes.md 缺失，发版会失败"
    assert RELEASE_NOTES.read_text(encoding="utf-8").strip(), "发版正文不能为空"


def test_release_notes_carries_the_usage_warning():
    """免责声明是发版正文的固定内容，不能在某次改写里被顺手删掉。"""
    text = RELEASE_NOTES.read_text(encoding="utf-8")
    assert "严禁滥用" in text
    assert "已获得明确授权" in text


def test_ci_release_job_reads_body_from_file_not_inline():
    """守「正文不在 workflow 里写死」这条约定。

    如果哪天有人把 body 改回 inline 大段文本，正文与文件就会再次分叉，
    这个测试应当拦下来。
    """
    text = CI_YML.read_text(encoding="utf-8")
    assert "body_path: docs/release-notes.md" in text
    # inline body 的形状是行首缩进的 ``body: |``；出现即视为回退
    assert not re.search(r"^\s+body:\s*\|", text, re.MULTILINE), \
        "Release 正文又写回 workflow 里了，请改用 body_path"


def test_ci_release_job_checks_out_before_reading_notes():
    """release job 必须能读到文件 —— 所以 checkout 要在读它之前。"""
    text = CI_YML.read_text(encoding="utf-8")
    idx_checkout = text.find("actions/checkout@v4", text.find("  release:"))
    idx_body = text.find("body_path: docs/release-notes.md")
    assert idx_checkout != -1, "release job 缺少 actions/checkout"
    assert idx_body != -1
    assert idx_checkout < idx_body, "checkout 必须在读取 release notes 之前"


def test_release_is_prerelease_by_default():
    """硬规矩：未经真机手测确认的版本只能先发 Pre-release。

    这道守卫防止有人「顺手」把 prerelease 改成 false —— 升正式版应当是在
    Release 建好之后用 `gh release edit --prerelease=false` 手动做。
    """
    text = CI_YML.read_text(encoding="utf-8")
    assert re.search(r"^\s+prerelease:\s*true\s*$", text, re.MULTILINE), \
        "CI 里 prerelease 不再是 true 了 —— 违反发版硬规矩"
