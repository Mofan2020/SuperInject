# SuperInject

> **⚠️ 仅供开发人员调试程序使用，严禁滥用，违规使用者后果自负！**

**SuperInject** 是一个**仅运行在 Windows 上**的、基于 DLL 注入的**快捷调试工具**。
它把「找进程 → 注入 → 读内存 → 改内存 → 冻结 → 卸载 / 结束」这条调试链路压缩进一个
PyWebView 图形界面里，帮助开发者在几分钟内定位问题，而不是在各种命令行脚本之间来回切换。

> **使用边界（请务必阅读）**
> 本工具**只能**用于你自己拥有、或已获得**明确授权**的目标进程。
> 严禁用于任何未授权的第三方程序、用于绕过软件保护机制，或用于侵犯他人权益的行为。
> 在多数司法辖区，未经授权对第三方进程注入代码可能违反法律与软件许可协议；
> 由此产生的一切后果由使用者自行承担。本项目作者与贡献者不承担任何责任。

---

## 功能一览

| 能力 | 说明 |
| --- | --- |
| 启动自检 1 | 检测权限（非管理员则自动触发 UAC 提权，以管理员 / SYSTEM 身份运行） |
| 启动自检 2 | DLL 完整性校验：运行时计算 SHA256 与内嵌副本比对，不一致（或缺失）**自动替换** |
| 进程选择 | 全量进程列表，支持按名称 / PID 搜索，支持多选批量，也支持手工粘贴 PID |
| 注入 | `CreateRemoteThread + LoadLibraryW`，批量注入，支持 DLL 冷/热更新后重新注入 |
| 批量控制 | 注入端 DLL 通过命名管道**反向连接**控制器，控制器可同时控制任意多个已注入进程 |
| 卸载注入 | 让目标进程内的 DLL 自己 `FreeLibraryAndExitThread`，干净卸载 |
| 终止进程 | 由注入的 DLL 在目标进程内调用 `ExitProcess`——即"进程自己终结自己" |
| 冻结进程 | `NtSuspendProcess` 挂起全部线程，目标进程**完全无响应**，调试时非常管用；可随时解除 |
| 内存搜索 | 支持 `4D 5A ?? ??` 通配的十六进制模式扫描，批量在多进程内搜索 |
| 内存查看 / 修改 | 十六进制读写任意地址，可批量写入 |
| 进程资源查看 | 提取目标进程已加载模块中的图片（PNG/JPG/GIF/BMP）、音频（WAV/OGG/MP3）等资源到本地目录 |
| 自动更新 | 后台检查 GitHub Release，有新版时询问是否下载安装 |

---

## 工作原理

```
┌──────────────── SuperInject.exe（Python / PyWebView）────────────────┐
│                                                                        │
│  自检1 权限  →  自检2 DLL SHA 校验替换  →  GUI 启动  →  后台检查更新      │
│                                                                        │
│  Controller ──► CreateRemoteThread + LoadLibraryW 注入                 │
│      │                                                                 │
│      │  为每个目标预建命名管道 \\.\pipe\SuperInject-<ctl>-<target>      │
│      ▼                                                                 │
│  PipeServer  ◄════════ 命名管道（4 字节长度 + JSON）════════  PipeClient │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ 注入点
                 ┌─────────────────▼──────────────────┐
                 │ SuperInjectAgent.dll（目标进程内）    │
                 │  · ping / info / mem_regions         │
                 │  · mem_search / mem_read / mem_write  │
                 │  · resources（提取图片音视频）        │
                 │  · freeze / terminate / unload       │
                 └────────────────────────────────────┘
```

关键设计：**控制通道是反向的**。被注入的 DLL 主动连接控制器创建的命名管道，
因此一次注入即可支持**批量、随时、反复**地控制目标进程，而不需要每次操作都重新注入。

DLL 字节在打包时以 base64 **内嵌进 exe**，运行时的 SHA256 **全部实时计算**，
源码与配置中不存在任何手写哈希常量（有单元测试守护这条规则）。

---

## 安装与使用

### 方式一：下载 Release

从 [Releases](https://github.com/Mofan2020/SuperInject/releases) 下载 `SuperInject-win-x64` 压缩包，
解压后运行 `SuperInject.exe`，按提示同意 UAC 提权。

> 依赖：Windows 10/11 x64 + [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)（Win11 自带）。

### 方式二：从源码运行

```bash
git clone https://github.com/Mofan2020/SuperInject.git
cd SuperInject
python -m pip install -r requirements.txt

# 1) 编译注入端 DLL（需要 MinGW-w64 或 MSVC）
python build/build_native.py
# 2) 把 DLL 内嵌进程序
python build/make_payload.py
# 3) 运行（会自动触发 UAC 提权）
python run_superinject.py
```

### 使用步骤

1. **选择进程** —— 在列表里搜索名称或 PID，勾选（可多选），或直接粘贴 PID。
2. **注入** —— 点击「注入选中」，日志会显示每个 PID 的注入结果。
3. **控制** —— 在「控制（批量）」区执行冻结 / 解除冻结 / 查看资源 / 卸载 / 终止。
4. **内存调试** —— 输入十六进制模式（如 `4D 5A ?? ??`）搜索，选中结果后即可查看与修改。

---

## 项目结构

```
SuperInject/
├─ superinject/
│  ├─ __main__.py        启动流程（权限自检 → DLL 自检 → GUI → 更新检查）
│  ├─ gui.py             PyWebView 桥接层（暴露给前端 JS 的 API）
│  ├─ controller.py      注入控制器：进程 → 注入 → 批量控制
│  ├─ winapi.py          Win32/NT API 的 ctypes 封装
│  ├─ ipc.py             命名管道 IPC + 帧协议编解码
│  ├─ dll_manager.py     DLL 内嵌副本与 SHA256 自校验替换（自检2）
│  ├─ elevate.py         权限自检与 UAC 提权（自检1）
│  ├─ updater.py         GitHub Release 更新检查与安装
│  ├─ web/               前端界面（index.html / app.js / style.css）
│  └─ embedded/          打包时生成的 DLL 字节（base64）
├─ native/
│  ├─ agent.c            被注入的 DLL：管道客户端 + 各项能力
│  └─ superinject_json.c/.h  DLL 侧零依赖 JSON 实现
├─ build/                编译 / 内嵌 / 打包脚本
├─ tests/                单元测试（可在任意平台运行）
└─ .github/workflows/ci.yml  CI：编译 DLL + 测试 + 打包 + 自动发布
```

---

## 开发与测试

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -q          # 40+ 个用例，纯逻辑部分跨平台可跑
python build/build_native.py       # 交叉编译 DLL（Ubuntu 上装 mingw-w64 即可）
```

CI（[`.github/workflows/ci.yml`](.github/workflows/ci.yml)）会在每次 push / PR 上：

1. 用 **MinGW-w64** 编译 `SuperInjectAgent.dll`（`-Wall -Wextra -Werror`），并校验产物是 64 位 PE DLL；
2. 在 **Ubuntu + Windows** 上跑 Python 单元测试与语法检查；
3. 在 **windows-latest** 上用 PyInstaller 打包 `SuperInject.exe`；
4. 打 `v*` tag 时自动发布 GitHub Release。

---

## 常见问题

**Q：注入失败怎么办？**
- 确认已同意 UAC 提权（标题栏徽标应为绿色「权限 ✓」）；
- 目标进程与 SuperInject 必须**位数一致**（x64 只能注入 x64，x86 只能注入 x86）；
- 部分安全软件 / 反作弊会拦截 `CreateRemoteThread`，本工具不提供任何绕过能力。

**Q：搜索内存很慢？**
全进程空间扫描确实耗时；对已知地址建议直接用「查看/修改」读该地址区域。

**Q：冻结后怎么恢复？**
「解除冻结」按钮，或直接结束进程。冻结期间目标进程完全不响应，包括它的注入端 DLL。

---

## 安全声明（再次强调）

- SuperInject **仅供开发人员调试程序使用，严禁滥用，违规使用者后果自负**；
- 请仅在你自己开发的、或已获得书面授权的软件/进程上使用；
- 请遵守所在地区的法律法规与相关软件的许可协议；
- 作者与贡献者对任何滥用行为造成的损失不承担责任。

## 许可证

[MIT](LICENSE) © 2026 Skyc8266
