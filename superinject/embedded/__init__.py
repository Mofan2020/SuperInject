"""内嵌 DLL 占位包。

真正的字节由 ``build/make_payload.py`` 生成到 ``dll_payload.py``，
运行时不读取任何手写的 SHA —— 哈希一律由程序实时计算。
"""
