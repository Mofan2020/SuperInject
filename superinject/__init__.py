"""SuperInject —— 基于 DLL 注入的快捷调试工具（仅限 Windows）。

⚠️ 仅供开发人员调试自己的程序使用，严禁用于未授权的第三方进程。
"""

from .version import __version__, APP_NAME, PROJECT_URL

__all__ = ["__version__", "APP_NAME", "PROJECT_URL"]
