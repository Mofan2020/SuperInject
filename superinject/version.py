"""版本与项目常量。

约定：唯一版本来源是本文件，构建脚本与打包流程都从这里读取。
"""

from __future__ import annotations

APP_NAME = "SuperInject"
REPO = "Mofan2020/SuperInject"
PROJECT_URL = f"https://github.com/{REPO}"
GITHUB_RELEASES_API = f"https://api.github.com/repos/{REPO}/releases"
GITHUB_API = f"https://api.github.com/repos/{REPO}/releases/latest"
GITHUB_RELEASES = f"https://github.com/{REPO}/releases"

__version__ = "1.0.1"

# 命名管道前缀：注入端 DLL 用 \\.\pipe\SuperInject-<控制器PID>-<目标PID>
PIPE_PREFIX = r"\\.\pipe\SuperInject-"


def pipe_name(controller_pid: int, target_pid: int) -> str:
    """构造控制器与注入端之间唯一的管道名。"""
    return f"{PIPE_PREFIX}{controller_pid}-{target_pid}"


def compare_version(a: str, b: str) -> int:
    """比较两个版本号：a>b 返回 1，a<b 返回 -1，相等返回 0。"""
    def parts(v: str) -> list[int]:
        out: list[int] = []
        for chunk in str(v).strip().lstrip("vV").split("."):
            num = ""
            for ch in chunk:
                if ch.isdigit():
                    num += ch
                else:
                    break
            out.append(int(num) if num else 0)
        return out or [0]

    pa, pb = parts(a), parts(b)
    for i in range(max(len(pa), len(pb))):
        x = pa[i] if i < len(pa) else 0
        y = pb[i] if i < len(pb) else 0
        if x != y:
            return 1 if x > y else -1
    return 0
