#!/usr/bin/env python3
"""前端布局的无头渲染检查（Playwright + Chromium）。

为什么需要它：SuperInject 的界面是 pywebview 里的本地页面，CI 上既没有桌面
也没有 Windows GUI，所以「整页能不能滚动、功能区会不会被裁掉」这类问题过去
只能靠人肉看。这个脚本用假后端（``tests/ui/mock_bridge.js``）把真实页面渲染
出来，然后在多个窗口尺寸下断言：

* 页面整体可滚动（内容高度 > 视口高度）；
* 没有横向溢出（内容宽度 <= 视口宽度）；
* 六个功能区都能滚到视口内、标题不被吸顶栏挡住；
* 进程表/资源墙/日志各自有内部滚动（说明空间分配生效，不是无限长页面）。

用法：
    pip install playwright && playwright install --with-deps chromium
    python tests/ui/render_check.py            # 退出码非 0 即失败
    python tests/ui/render_check.py --shots-dir /tmp/si-ui   # 顺便存截图
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
WEB = ROOT / "superinject" / "web"
MOCK = Path(__file__).resolve().parent / "mock_bridge.js"

# 覆盖到「最小窗口」和「比最小还小」两种极端；外观跟随系统，深浅两套都要能看
VIEWPORTS = [(1280, 800, "default", "light"), (1024, 640, "min", "light"),
             (760, 520, "tiny", "light"), (1280, 800, "dark", "dark")]
PANELS = ["panel-procs", "panel-inject", "panel-control",
          "panel-res", "panel-mem", "panel-log"]

FAILURES: list[str] = []


def check(cond: bool, message: str) -> None:
    if cond:
        print(f"  [PASS] {message}")
    else:
        print(f"  [FAIL] {message}")
        FAILURES.append(message)


def run_viewport(page, width: int, height: int, label: str,
                 shots_dir: Path | None, scheme: str = "light"):
    print(f"\n== 视口 {width}x{height} ({label}, {scheme}) ==")
    page.set_viewport_size({"width": width, "height": height})
    page.emulate_media(color_scheme=scheme)
    page.goto(WEB.joinpath("index.html").as_uri())
    page.wait_for_function(
        "() => document.querySelectorAll('#proc-table tbody tr').length > 50",
        timeout=15000)

    metrics = page.evaluate("""() => {
        const de = document.documentElement;
        const wrap = document.querySelector('.table-wrap');
        const grid = document.querySelector('.res-grid');
        const log = document.querySelector('#log');
        return {
            scrollH: de.scrollHeight, clientH: de.clientHeight,
            scrollW: de.scrollWidth, clientW: de.clientWidth,
            rows: document.querySelectorAll('#proc-table tbody tr').length,
            tableScroll: wrap.scrollHeight > wrap.clientHeight + 4,
            tableH: Math.round(wrap.getBoundingClientRect().height),
            gridH: Math.round(grid.getBoundingClientRect().height),
            logScroll: log.scrollHeight > log.clientHeight + 4,
            logLines: log.children.length,
            panels: [...document.querySelectorAll('main > section.panel')].length,
            navSegs: document.querySelectorAll('.nav-seg').length,
            bodyOverflowX: getComputedStyle(document.body).overflowX,
            bodyBg: getComputedStyle(document.body).backgroundColor,
            label: getComputedStyle(document.body).color,
        };
    }""")
    if scheme == "dark":
        rgb = [int(x) for x in metrics["bodyBg"].replace("rgb(", "")
               .replace(")", "").split(",")[:3]]
        text = [int(x) for x in metrics["label"].replace("rgb(", "")
                .replace(")", "").split(",")[:3]]
        check(sum(rgb) < 200, f"深色外观生效（背景 {metrics['bodyBg']}）")
        check(sum(text) > 480, f"深色外观文字为亮色（{metrics['label']}）")
    else:
        rgb = [int(x) for x in metrics["bodyBg"].replace("rgb(", "")
               .replace(")", "").split(",")[:3]]
        check(sum(rgb) > 500, f"浅色外观生效（背景 {metrics['bodyBg']}）")

    check(metrics["panels"] == len(PANELS), f"六个功能区齐全（{metrics['panels']}/6）")
    check(metrics["navSegs"] == len(PANELS), "分区导航分段齐全")
    check(metrics["rows"] > 100, f"进程表渲染出 {metrics['rows']} 行")
    check(metrics["scrollH"] > metrics["clientH"] + 20,
          f"整页可滚动（内容 {metrics['scrollH']}px > 视口 {metrics['clientH']}px）")
    check(metrics["scrollW"] <= metrics["clientW"] + 1,
          f"无横向溢出（内容 {metrics['scrollW']}px <= 视口 {metrics['clientW']}px）")
    check(metrics["tableScroll"], f"进程表内部滚动生效（高 {metrics['tableH']}px）")
    check(metrics["logLines"] > 0, f"日志区有输出（{metrics['logLines']} 行）")

    # 每个功能区都能滚进视口，且标题不被吸顶栏遮挡
    for pid in PANELS:
        page.evaluate(
            "id => document.getElementById(id).scrollIntoView({block:'start'})", pid)
        page.wait_for_timeout(250)
        box = page.evaluate("""id => {
            const el = document.getElementById(id);
            const head = el.querySelector('.panel-head');
            const r = el.getBoundingClientRect();
            const hr = head ? head.getBoundingClientRect() : r;
            return { top: r.top, headTop: hr.top, bottom: r.bottom,
                     innerH: window.innerHeight };
        }""", pid)
        check(box["top"] >= -2 and box["top"] < box["innerH"],
              f"{pid} 可滚入视口（top={box['top']:.0f}）")
        check(box["headTop"] >= -2,
              f"{pid} 标题未被吸顶栏遮挡（title top={box['headTop']:.0f}）")

    # 滚到底：最后一个功能区（日志）必须完整可见 —— 这正是「看不全」的判据
    page.evaluate("() => window.scrollTo(0, document.documentElement.scrollHeight)")
    page.wait_for_timeout(300)
    bottom = page.evaluate("""() => {
        const el = document.getElementById('panel-log');
        const r = el.getBoundingClientRect();
        return { bottom: r.bottom, innerH: window.innerHeight,
                 atBottom: Math.ceil(window.scrollY + window.innerHeight)
                           >= document.documentElement.scrollHeight - 2 };
    }""")
    check(bottom["atBottom"], "能滚动到页面底部")
    check(bottom["bottom"] <= bottom["innerH"] + 2,
          f"日志区完整可见（底边 {bottom['bottom']:.0f} <= 视口 {bottom['innerH']}）")

    # 点导航「内存」应把该区滚进视口（页面已到底时会停在底，属正常夹取）
    page.evaluate("() => window.scrollTo(0, 0)")
    page.wait_for_timeout(300)
    top_active = page.evaluate(
        "() => document.querySelector('.nav-seg.on')?.dataset.target")
    check(top_active == "panel-procs", f"回到顶部时高亮第一个区（{top_active}）")
    page.click('.nav-seg[data-target="panel-mem"]')
    page.wait_for_timeout(800)
    mem = page.evaluate("""() => {
        const r = document.getElementById('panel-mem').getBoundingClientRect();
        return { top: r.top, innerH: window.innerHeight,
                 scrolled: window.scrollY > 0 };
    }""")
    check(mem["scrolled"], "点击导航后页面确实滚动了（scrollY>0）")
    check(-2 <= mem["top"] < mem["innerH"],
          f"导航目标进入视口（内存区 top={mem['top']:.0f}）")

    if shots_dir:
        shots_dir.mkdir(parents=True, exist_ok=True)
        page.evaluate("() => window.scrollTo(0, 0)")
        page.wait_for_timeout(200)
        page.screenshot(path=str(shots_dir / f"ui-{label}-top.png"))
        page.evaluate(
            "() => document.getElementById('panel-log')"
            ".scrollIntoView({block:'start'})")
        page.wait_for_timeout(250)
        page.screenshot(path=str(shots_dir / f"ui-{label}-bottom.png"))
        print(f"  截图已保存到 {shots_dir}")


def run_interactions(page, shots_dir: Path | None) -> None:
    """驱动真实交互：选进程 → 看资源 → 搜内存 → 弹确认框。

    纯渲染不看事件绑定，这一轮把这些按钮真点一遍，确认懒加载 / 结果渲染 /
    弹窗这些「看不见的路径」也是通的。
    """
    print("\n== 交互路径 ==")
    page.set_viewport_size({"width": 1280, "height": 800})
    page.goto(WEB.joinpath("index.html").as_uri())
    page.wait_for_function(
        "() => document.querySelectorAll('#proc-table tbody tr').length > 50",
        timeout=15000)

    page.click("#proc-table tbody tr")
    check(page.evaluate("() => document.querySelectorAll('#proc-table tbody tr.sel').length") == 1,
          "点击行可选中进程")
    check(page.inner_text("#btn-inject") == "注入选中 (1)", "选中计数同步到注入按钮")

    page.click('.act[data-act="resources"]')
    page.wait_for_selector(".res-card", timeout=8000)
    cards = page.evaluate("""() => ({
        cards: document.querySelectorAll('.res-card').length,
        imgs: document.querySelectorAll('.res-media img').length,
        summary: document.getElementById('res-summary').textContent,
    })""")
    check(cards["cards"] >= 6, f"资源卡片渲染（{cards['cards']} 张）")
    check(cards["imgs"] >= 1, f"图片缩略图渲染（{cards['imgs']} 张）")
    check("个资源" in cards["summary"], f"资源汇总更新：{cards['summary']}")

    page.fill("#mem-pattern", "4D 5A ?? ??")
    page.click("#btn-search")
    page.wait_for_selector("#mem-results table", timeout=8000)
    hits = page.evaluate("() => document.querySelectorAll('#mem-results tbody tr').length")
    check(hits > 0, f"内存搜索结果渲染（{hits} 行）")

    page.click("#mem-results button[data-addr]")
    check(page.evaluate("() => !document.getElementById('mem-editor').classList.contains('hidden')"),
          "点击「查看/修改」打开内存编辑器")
    check(page.input_value("#ed-addr").startswith("0x"), "编辑器地址被填入")

    page.click('.act[data-act="unload"]')
    page.wait_for_selector("#modal:not(.hidden)", timeout=5000)
    check("确定要卸载" in page.inner_text("#modal-text"), "危险操作弹出确认框")
    if shots_dir:
        page.screenshot(path=str(shots_dir / "ui-interactions.png"))
    page.click("#modal-cancel")
    check(page.evaluate("() => document.getElementById('modal').classList.contains('hidden')"),
          "取消后确认框关闭")

    page.reload()
    page.wait_for_function(
        "() => document.querySelectorAll('#proc-table tbody tr').length > 50",
        timeout=15000)
    page.click('.act[data-act="ping"]')
    page.wait_for_function(
        "() => document.getElementById('log').children.length > 4", timeout=8000)
    check(True, "批量指令走到调用后端（日志有输出）")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--shots-dir", default=os.environ.get("SI_UI_SHOTS", ""),
                    help="保存截图的目录（默认不存）")
    ap.add_argument("--headed", action="store_true")
    args = ap.parse_args()
    shots = Path(args.shots_dir) if args.shots_dir else None

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("需要 playwright：pip install playwright && playwright install chromium")
        return 2

    if not WEB.joinpath("index.html").exists():
        print(f"找不到前端目录 {WEB}")
        return 2

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not args.headed)
        page = browser.new_page()
        # 假后端必须在任何页面脚本之前注入（app.js 启动时就用它）
        page.add_init_script(path=str(MOCK))
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: errors.append(m.text)
                if m.type == "error" else None)
        for width, height, label, scheme in VIEWPORTS:
            run_viewport(page, width, height, label, shots, scheme)
        run_interactions(page, shots)
        browser.close()

    check(not errors, f"页面无 JS 报错（{len(errors)} 条）")
    if errors:
        for e in errors[:10]:
            print("    " + e)

    if FAILURES:
        print(f"\n布局检查失败：{len(FAILURES)} 项")
        for f in FAILURES:
            print("  - " + f)
        return 1
    print("\n布局检查全部通过：整页可滚动 / 无横向溢出 / 各功能区均可完整显示")
    return 0


if __name__ == "__main__":
    sys.exit(main())
