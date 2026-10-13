
v1.3.1 hotfix
============

按 image 路径查进程
--------------------

* CLI / GUI / MCP 三层都加上了按进程映像路径过滤。CLI 用
  ``SuperInject list --path "C:\\Windows\\System32"``；GUI 进程表
  面板加了一个 "按映像路径搜索" 输入框（与原有的按名搜索并列）；
  MCP 工具 ``list_processes`` 也新增 ``path`` / ``arch`` 参数。
* 新增按父目录查找：``controller.find_in_dir(parent)``，匹配
  ``C:\\Windows\\System32`` 这种父目录时不会误中含同样子串的
  文件名。
* 进程列表也可以按位数过滤：x64 / x86。

x86 架构进程注入（GUI 入口补齐）
--------------------------------

v1.3.0 已经在 DLL 层编了 x86 版本，并且 ``test_x86_injection_on_syswow64_ping``
在 Windows runner 上跑通了。这次把 GUI 入口补齐：进程面板加了
"位数" 下拉，注入按钮按用户选的目标位数走；CLI / MCP 之前的
``--arch`` / ``arch`` 参数已经接好。

修复
----

* 控制器里 ``resolve_targets`` 在 macOS 上的单元测试一直 fail，
  最后定位是内层循环 ``for p_l, pids in path_lookup.items()`` 跟
  函数参数 ``pids`` 同名，导致外层 ``for p in pids`` 看到的是
  shadow 之后的值（最后一项的 pid 列表）。修法是重命名为
  ``hit_pids``。详细在 docs/notes.md 第二十二章。


## 本版新增

- 内存快照 / diff：给进程内存拍快照，之后对比两份找出哪些内存页变了，改动一两个字节也能定位。
- 硬件断点：在指定地址下断点，可设执行 / 读 / 写触发。命中时带回当时的 CPU 寄存器和栈内容。
- MCP 支持：把调试能力开放给 AI Agent（Claude Desktop、Cursor 等）。默认什么都不给，先在界面里授权，限定能操作哪些进程、允许哪几档能力、多久过期。没授权的工具 Agent 看不到，硬调也只会被拒。
- 授权面板：界面顶部显示 MCP 授权状态，可以授权、撤销、复制 Agent 端配置。
- 免 UAC 连接：界面里启用 MCP 服务后，Agent 通过 launcher 连接，不用每次点 UAC。
- 一键写配置：可以直接把配置写进 Claude Desktop 或 Cursor，写入前备份原文件，只改本工具自己那一项。

## 使用前必读

本工具仅供开发人员调试程序使用，严禁滥用，违规使用者后果自负。

- 只能用于你自己拥有、或已获得明确授权的目标进程；
- 严禁用于绕过软件的授权 / 保护机制；
- 未经授权对第三方进程注入 DLL 可能违反当地法律与服务条款，由此产生的一切后果由使用者自行承担。

## 验证情况

windows runner 上用 MSVC 构建注入端 DLL，并在真实 Windows 进程里跑集成测试：注入、内存读写、冻结、快照对比、断点、资源导出、卸载、重新注入。打包产物另外跑一遍全链路自检。

界面交互、免 UAC 效果和 Agent 实际连接需要你在真机上确认。
