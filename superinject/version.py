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

# 控制通道：注入端（DLL）主动反向连接到控制器的回环 TCP 端口。
# 控制器把「端口 + 一次性令牌」写到这里，注入端按自己的 PID 取用：
#   %TEMP%\SuperInject\port-<目标PID>.txt   内容：<端口> <令牌>
CHANNEL_DIR_NAME = "SuperInject"
PORT_FILE_FMT = "port-{pid}.txt"


def port_file_name(target_pid: int) -> str:
    """注入端读取回环端口所用的文件名。"""
    return PORT_FILE_FMT.format(pid=int(target_pid))



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
