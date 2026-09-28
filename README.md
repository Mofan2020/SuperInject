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
| 启动自检 1 | 识别当前权限（SYSTEM / 管理员 / 普通用户）；普通用户则自动触发 UAC 提权 |
| 启动自检 2 | DLL 完整性校验：运行时计算 SHA256 与内嵌副本比对，不一致（或缺失）**自动替换** |
| 进程选择 | 全量进程列表，支持按名称 / PID 搜索，支持多选批量，也支持手工粘贴 PID |
| 注入检查 | 注入前逐个 PID 预检：进程是否还在、位数是否匹配、能否打开、是否系统关键进程、是否已注入 |
| 注入 | `CreateRemoteThread + LoadLibraryW`，批量注入，**并确认控制通道真的建立**才算成功 |
| 热更新重注入 | 对已注入的进程再次注入时，自动「先卸载旧 DLL → 等通道断开 → 注入新 DLL」 |
| 批量控制 | 注入端 DLL 通过**回环 TCP 反向连接**控制器（带一次性令牌），控制器可同时控制任意多个已注入进程 |
| 卸载注入 | 让目标进程内的 DLL 自己 `FreeLibraryAndExitThread`，干净卸载并断开通道 |
| 终止进程 | 由注入的 DLL 在目标进程内调用 `ExitProcess`——即"进程自己终结自己" |
| 冻结进程 | `NtSuspendProcess` 挂起全部线程，目标进程**完全无响应**；可随时解除，并核实线程真实挂起状态 |
| 内存搜索 | 支持 `4D 5A ?? ??` 通配的十六进制模式扫描，可批量在多进程内搜索 |
| 内存查看 / 修改 | 十六进制读写任意地址；遇到代码段/只读页会自动临时改页属性再写回（可改代码） |
| 进程资源查看 | 提取并**直接在界面里预览**目标进程内存中的图片 / 音频 / 视频：<br>① PE 资源（RT_BITMAP / RT_ICON / RT_CURSOR 会补文件头转成 BMP / ICO / CUR）<br>② 内存映射文件（自己进程里被 map 进来的图片音视频，按内存内容原样导出） |
| 自动更新 | 后台检查 GitHub Release（含预发布版本），有新版时询问是否下载安装 |

---

## 工作原理

```
┌──────────────── SuperInject.exe（Python / PyWebView）────────────────┐
│                                                                        │
│  自检1 权限  →  自检2 DLL SHA 校验替换  →  GUI 启动  →  后台检查更新      │
│                                                                        │
│  Controller ──► 注入检查 → CreateRemoteThread + LoadLibraryW 注入       │
│      │                                                                 │
│      │  为每个目标写会合文件 %TEMP%\SuperInject\port-<目标PID>.txt       │
│      ▼                                                                 │
│ AgentServer  ◄════ 回环 TCP 127.0.0.1（4 字节长度 + JSON）════  Agent   │
│      │                                                                 │
│      │  导出目录 %TEMP%\SuperInject\<pid>\ → 127.0.0.1 只读预览服务      │
│      ▼                                                                 │
│  <img>/<video>/<audio> 直接播放（支持 Range，能拖进度）                  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ 注入点
                 ┌─────────────────▼──────────────────┐
                 │ SuperInjectAgent.dll（目标进程内）    │
                 │  · ping / info / mem_regions         │
                 │  · mem_search / mem_read / mem_write  │
                 │  · resources（PE 资源 + 内存映射）     │
                 │  · terminate / unload                 │
                 └────────────────────────────────────┘
```

关键设计：

* **控制通道是反向的**。被注入的 DLL 读会合文件后主动连接控制器的回环端口，
  因此一次注入即可支持**批量、随时、反复**地控制目标进程，不需要每次操作都重新注入。
* **冻结在控制器侧完成**（`NtSuspendProcess`）。从进程内部挂起自己是没意义的 —— 只会让
  DLL 唯一的工作线程睡死，既冻结不了目标也永远回不来。冻结期间目标进程完全不响应，
  DLL 自然也不响应，这是预期行为。
* **注入成功 = 通道建立**。`LoadLibraryW` 返回非 0 只说明模块进了目标进程；
  本工具会继续等待注入端连上控制通道，连不上就如实报失败（并区分「模块残留」这类情况）。
* **通道用回环 TCP 而不是命名管道**。控制器只监听 `127.0.0.1`（不对外），并把
  「端口 + 一次性随机令牌」写进 `%TEMP%\SuperInject\port-<目标PID>.txt`，注入端连上后
  首帧必须回传该令牌，否则连接被丢弃。早期版本用命名管道，实测在「控制器写命令、
  注入端阻塞读」并存时会出现方向性死等（写端与读端一起卡死数分钟），故换成 socket。
* DLL 字节在打包时以 base64 **内嵌进 exe**，运行时的 SHA256 **全部实时计算**，
  源码与配置中不存在任何手写哈希常量（有单元测试守护这条规则）。

---

## 安装与使用

### 方式一：下载 Release

从 [Releases](https://github.com/Mofan2020/SuperInject/releases) 下载 `SuperInject-win-x64.zip`，
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
2. **注入** —— 点击「注入选中」，会先做注入检查（系统关键进程、位数不匹配等会被拦下），
   再执行注入并确认控制通道已建立。
3. **控制** —— 在「控制（批量）」区执行冻结 / 解除冻结 / 查看资源 / 卸载 / 终止。
4. **看资源** —— 「查看进程资源」会把目标进程内存里的图片/音频/视频导出到临时目录，
   并在下方**直接以缩略图 / 播放器呈现**（音频视频可播放拖动）。
5. **内存调试** —— 输入十六进制模式（如 `4D 5A ?? ??`）搜索，选中结果后即可查看与修改；
   写入只读页（例如 PE 头、代码段）时会自动临时改页属性并还原。

### 无界面自检（CI 与自测用）

```powershell
SuperInject.exe --self-test            # 全链路自检，报告写入程序目录
SuperInject.exe --self-test --report D:\report.json
SuperInject.exe --self-test --keep-target
```

它从**打包产物**本身出发，用内嵌的 DLL 去注入一个真实进程，逐项验证：
权限自检 → DLL 校验与 SHA 一致 → 拉起目标进程 → 注入检查 → 注入并建连 →
ping / info / mem_regions / 内存搜索 / 内存读写还原 → 资源提取 →
冻结与解除（核实线程挂起状态）→ 卸载 → 重新注入 → 热更新重注入 → 自我终止。
退出码 0 表示全部通过，报告为 JSON（`self-test-report.json`）。

---

## 项目结构

```
SuperInject/
├─ superinject/
│  ├─ __main__.py        启动流程（权限自检 → DLL 自检 → GUI → 更新检查）/ CLI 入口
│  ├─ gui.py             PyWebView 桥接层（暴露给前端 JS 的 API）
│  ├─ controller.py      注入检查 / 注入 / 批量控制 / 内存 / 资源编排
│  ├─ winapi.py          Win32/NT API 的 ctypes 封装（权限、注入、挂起检测等）
│  ├─ ipc.py             回环 TCP 控制通道 + 帧协议编解码
│  ├─ fileserver.py      127.0.0.1 只读预览服务（支持 Range，供音视频播放）
│  ├─ media.py           媒体类型判定与预览条目组装
│  ├─ resconv.py         裸 DIB → BMP / ICO / CUR（PE 资源补文件头）
│  ├─ dll_manager.py     DLL 内嵌副本与 SHA256 自校验替换（自检2）
│  ├─ elevate.py         权限自检与 UAC 提权（自检1）
│  ├─ updater.py         GitHub Release 更新检查与安装
│  ├─ selftest.py        无界面全链路自检（--self-test）
│  ├─ web/               前端界面（index.html / app.js / style.css）
│  └─ embedded/          打包时生成的 DLL 字节（base64）
├─ native/
│  ├─ agent.c            被注入的 DLL：管道客户端 + 各项能力
│  └─ superinject_json.c/.h  DLL 侧零依赖 JSON 实现
├─ build/                编译 / 内嵌 / 打包脚本
├─ tests/                单元测试（跨平台） + Windows 真实注入集成测试
└─ .github/workflows/ci.yml  CI：编译 DLL + 测试 + 打包 + 产物自检 + 自动发布
```

---

## 开发与测试

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -q --ignore=tests/test_integration_windows.py   # 跨平台单元测试
python -m ruff check superinject build tests run_superinject.py
python build/build_native.py       # 交叉编译 DLL（Ubuntu 上装 mingw-w64 即可）
```

Windows 上（管理员终端）跑真实注入集成测试：

```powershell
$env:SUPERINJECT_DLL_PATH = "native/build/SuperInjectAgent.dll"
python -m pytest tests/test_integration_windows.py -v
```

CI（[`.github/workflows/ci.yml`](.github/workflows/ci.yml)）在每次 push / PR 上：

1. 用 **MinGW-w64** 交叉编译 `SuperInjectAgent.dll`（`-Wall -Wextra -Werror`），并校验产物是 64 位 PE DLL；
2. 用 **MSVC**（`/W4 /WX`）在 windows runner 上再编译一次，保证两套工具链都能过；
3. 在 **Ubuntu + Windows** 上跑单元测试、`compileall` 与 `ruff`；
4. 在 **windows-latest** 上跑**真实注入集成测试**（注入 `ping.exe`，
   覆盖内存读写含只读页、冻结与解除、资源提取、卸载、重新注入、自我终止）；
5. 用 PyInstaller 打包，压成 `SuperInject-win-x64.zip`；
6. 对**打包产物**再跑一次 `SuperInject.exe --self-test`，把整条链路在发布件上重验一遍；
7. 打 `v*` tag 时自动发布正式版 Release（附加 zip 资产，自动更新只认它）。

> 改动前先读 [`docs/notes.md`](docs/notes.md)：那里记录了本版修掉的遗留缺陷及根因
> （控制通道方向性死锁、数组序列化无限互递归、重新注入竞态、`pid_alive` 假存活等）、
> 架构约定、已知边界，以及「哪些没做、为什么没做」。

---

## 常见问题

**Q：注入失败怎么办？**
- 先看「注入检查」的结论，它会明确告诉你是哪种情况：
  进程不存在 / 位数不匹配（x64 工具不能注入 x86 进程，反之亦然）/ 无法打开进程（未提权）/
  系统关键进程被拦（`lsass.exe`、`csrss.exe` 之类注入会直接蓝屏）。
- 部分安全软件 / 反作弊会拦截 `CreateRemoteThread`，本工具不提供任何绕过能力。

**Q：提示「已存在 SuperInjectAgent.dll 但控制通道未建立」？**
说明目标进程里残留了上一次的注入模块（例如控制器被强杀）。这种情况无法从外部安全卸载，
请重启目标进程后再注入。

**Q：想更新 DLL 后重新注入？**
直接对已注入的进程再点「注入选中」即可，会自动先卸载旧 DLL 再注入新的。

**Q：搜索内存很慢？**
全进程空间扫描确实耗时；对已知地址建议直接用「查看/修改」读该地址区域。

**Q：冻结后怎么恢复？**
「解除冻结」按钮，或直接结束进程。冻结期间目标进程完全不响应，包括它的注入端 DLL。

**Q：资源提取为什么有些图片打不开？**
内存映射文件是按「当时被映射进内存的那段内容」导出的，如果程序只映射了文件的一部分，
导出的就是这一部分（界面上会标注「已截断」）。

---

## 安全声明（再次强调）

- SuperInject **仅供开发人员调试程序使用，严禁滥用，违规使用者后果自负**；
- 请仅在你自己开发的、或已获得书面授权的软件/进程上使用；
- 请遵守所在地区的法律法规与相关软件的许可协议；
- 作者与贡献者对任何滥用行为造成的损失不承担责任。

## 许可证

[MIT](LICENSE) © 2026 Skyc8266
