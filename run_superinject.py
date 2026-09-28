#!/usr/bin/env python3
"""SuperInject 启动入口（PyInstaller 打包目标）。"""

import multiprocessing
import sys

from superinject.__main__ import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
