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
| 启动自检 1 | 识别当前权限（SYSTEM / 管理员 / 普通用户）：普通用户先走 UAC 提到管理员，管理员再**自我提权到 SYSTEM**（复制 SYSTEM 进程令牌 + `CreateProcessAsUserW`），以便调试高权限进程；失败会明确降级为管理员并说明原因 |
| 启动自检 2 | DLL 完整性校验：运行时计算 SHA256 与内嵌副本比对，不一致（或缺失）**自动替换** |
| 进程选择 | 全量进程列表，支持按名称 / PID / **进程路径** 搜索，支持多选批量，也支持手工粘贴 PID |
| CLI 模式 | `-c -y <command>`：进程列表 / 注入 / 冻结 / 内存读写 / 卸载 / 终止 / DLL 自校验；默认 plain text，加 `--json` 切 JSON |
| x86 应用注入 | 同时内嵌 x64 + x86 两份 DLL；按目标进程位数自动选择，无需手动指定 |
| 注入检查 | 注入前逐个 PID 预检：进程是否还在、位数是否匹配（含「x86 DLL 可用时自动放行跨位数」）、能否打开、是否系统关键进程、是否已注入 |
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
| 界面 | 单页应用、**整页可滚动**、六个功能区按视口高度分配空间；外观跟随系统（浅色 / 深色）的 macOS 风格 |
| 单文件交付 | 打包产物**只有 `SuperInject.exe` 一个文件**（无 `_internal` 目录），内置 DLL 与前端资源都在 exe 内 |

---

## 工作原理

```
┌──────────────── SuperInject.exe（Python / PyWebView）────────────────┐
│                                                                        │
│  自检1 权限（UAC → SYSTEM 提权重启）→ 自检2 DLL SHA 校验替换 → GUI 启动     │
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
* **SYSTEM 提权不改会话**。做法是：打开 `SeDebugPrivilege` → 在**当前会话**里找一个
  以 SYSTEM 运行的进程（首选 `winlogon.exe`，它未被 PPL 保护）→ 复制其令牌为**主令牌**
  → 用该令牌把自己重新拉起。新进程是 SYSTEM，但仍在你当前的桌面/会话里，
  所以 GUI 照常显示（用计划任务以 SYSTEM 启动会掉进 session 0，界面根本看不见）。
  候选限定在同会话，因此完全不需要 `SeTcbPrivilege`。
* **会合文件跨 TEMP 也能找到**。注入端除了读自己的 `%TEMP%\SuperInject\`，
  在找不到时会再只读扫描各用户的 `%TEMP%\SuperInject\` —— 因为 SYSTEM 服务这类
  目标进程的 `GetTempPathW()` 往往是 `C:\Windows\Temp`，而控制器写在启动它的
  那个用户的 TEMP 里。只读扫描，不往公共目录写令牌。

---

## 安装与使用

### 方式一：下载 Release

从 [Releases](https://github.com/Mofan2020/SuperInject/releases) 下载 `SuperInject-win-x64.zip`，
解压得到**单个 `SuperInject.exe`**（没有 `_internal` 目录，也不需要安装），双击运行，
按提示同意 UAC。

> 依赖：Windows 10/11 x64 + [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/)（Win11 自带）。
>
> 发布包（`SuperInject-win-x64.zip`）里**只有 `SuperInject.exe` 一个文件**，
> 解压出来就是单文件，没有 `_internal` 目录、也不需要安装。
>
> 首次运行会在 exe 同目录释放内置的 `SuperInjectAgent.dll`（自检2 会实时校验它的
> SHA256）；若 exe 放在不可写的位置（如 `Program Files`），DLL 会自动改释放到
> `%LOCALAPPDATA%\SuperInject\`。

### 方式二：从源码运行

```bash
git clone https://github.com/Mofan2020/SuperInject.git
cd SuperInject
python -m pip install -r requirements.txt

# 1) 编译注入端 DLL（macOS/Linux 用 MinGW-w64 交叉编译，Windows 上优先用 MSVC）
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

### 命令行参数

```
SuperInject.exe                  启动自检 → 提权到 SYSTEM → 图形界面
SuperInject.exe --as-admin       只提到管理员（不提 SYSTEM），调试普通进程时用
SuperInject.exe --self-test      无界面全链路自检
SuperInject.exe --help           帮助

# CLI 模式（v1.1.0 新增）：不带 GUI，方便脚本与 Agent 调用
SuperInject.exe -c -y list                 # 列进程
SuperInject.exe -c -y list --path "C:\Program Files\..."   # 按路径过滤
SuperInject.exe -c -y list --name chrome   # 按名过滤
SuperInject.exe -c -y inject 1234          # 注入（自动按目标位数选 DLL）
SuperInject.exe -c -y inject --pid 100 --pid 200 --arch x86
SuperInject.exe -c -y freeze 1234
SuperInject.exe -c -y mem-read 1234 0x401000 64
SuperInject.exe -c -y mem-search 1234 '4D 5A ?? ??'
SuperInject.exe -c -y unload 1234
SuperInject.exe -c -y terminate 1234
SuperInject.exe -c -y status
SuperInject.exe -c -y dll                  # DLL 自校验
```

CLI 模式：

* 默认输出 plain text（Agent 友好）；加 `--json` 切 JSON。
* `-c` 启动 CLI（必需）；`-y` 一律同意免责（必需，否则拒绝执行）。
* 同时编两份 DLL：x64 + x86。注入 x86 进程时会自动选 x86 DLL，无需手动指定 `--arch`。
* 完整子命令与帮助：`-h` / `--help`。

### 关于 SYSTEM 权限

- **默认就会提权到 SYSTEM**：注入检查、内存读写、冻结这些能力对高权限进程
  （SYSTEM 服务、其他用户的进程）同样有效；界面右上角会显示当前真实权限
  （`权限 SYSTEM ✓` / `权限 管理员 ✓` / `权限 未提权 ✗`）。
- **拿不到 SYSTEM 也能用**：若系统策略不允许（例如没有可用的 SYSTEM 令牌来源、
  安全软件拦截令牌复制），程序会**降级为管理员继续运行**，并在日志里写明原因，
  不会硬性退出 —— 调试普通进程用管理员权限足够。
- **不想提 SYSTEM** 时加 `--as-admin`。
- **可以调试哪些高权限进程**：在 SYSTEM 模式下，目标进程只要不是内核/受保护进程
  （PPL）都可以尝试注入；`lsass.exe`、`csrss.exe`、`services.exe` 等系统关键进程
  被本工具主动拦下（注入它们会导致系统崩溃，这不是能力不足而是必须的护栏）。

### 无界面自检（CI 与自测用）

```powershell
SuperInject.exe --self-test            # 全链路自检，报告写入程序目录
SuperInject.exe --self-test --report D:\report.json
SuperInject.exe --self-test --keep-target
```

它从**打包产物**本身出发，用内嵌的 DLL 去注入一个真实进程，逐项验证：
权限自检 → DLL 校验与 SHA 一致 → SYSTEM 令牌复制 → **真实创建一个 SYSTEM 进程并核对身份** → 拉起目标进程 → 注入检查 → 注入并建连 →
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
│  ├─ elevate.py         权限自检、UAC 提权与 SYSTEM 提权策略（自检1）
│  ├─ system_token.py    SYSTEM 令牌复制与 CreateProcessAsUserW 重启（Windows 专用）
│  ├─ updater.py         GitHub Release 更新检查与安装
│  ├─ selftest.py        无界面全链路自检（--self-test）
│  ├─ web/               前端界面（index.html / app.js / style.css）
│  └─ embedded/          打包时生成的 DLL 字节（base64）
├─ native/
│  ├─ agent.c            被注入的 DLL：管道客户端 + 各项能力
│  └─ superinject_json.c/.h  DLL 侧零依赖 JSON 实现
├─ build/                编译 / 内嵌 / 打包脚本
├─ tests/                单元测试（跨平台） + Windows 真实注入集成测试
│  └─ ui/render_check.py 前端布局的无头渲染检查（Playwright + 假后端）
└─ .github/workflows/ci.yml  CI：编译 DLL + 测试 + 打包 + 产物自检 + 自动发布
```

---

## 开发与测试

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -q --ignore=tests/test_integration_windows.py   # 跨平台单元测试
python -m ruff check superinject build tests run_superinject.py
python build/build_native.py       # 本机编译 DLL 自测（macOS/Linux 走 MinGW-w64 交叉编译；
                                   # 发布件由 CI 用 MSVC 构建，见 ci.yml 的 native-msvc）

# 前端布局检查（无头 Chromium，装一次浏览器即可）
python -m pip install playwright && python -m playwright install chromium
python tests/ui/render_check.py --shots-dir /tmp/si-ui
```

Windows 上（管理员终端）跑真实注入集成测试：

```powershell
$env:SUPERINJECT_DLL_PATH = "native/build/SuperInjectAgent.dll"
python -m pytest tests/test_integration_windows.py -v
```

CI（[`.github/workflows/ci.yml`](.github/workflows/ci.yml)）在每次 push / PR 上：

1. 在 windows runner 上用 **MSVC**（`/W4 /WX`）编译 `SuperInjectAgent.dll` —— 这是**唯一的构建产线**，
   校验产物是 64 位 PE DLL，并守卫**导入表只允许系统 DLL**（不许依赖 VCRUNTIME140/msvcp 这类
   用户得额外安装的运行库，否则注入会失败）；
2. 在 **Ubuntu + Windows** 上跑单元测试、`compileall` 与 `ruff`
   （Windows 上还会跑 `tests/test_system_token_windows.py`：真复制 SYSTEM 令牌、
   以 SYSTEM 创建进程并核对子进程身份）；
3b. 用 **Playwright + Chromium** 把前端渲染三档窗口尺寸 + 深浅两套外观，
   断言「整页可滚动 / 无横向溢出 / 各功能区都能完整看到」，并真点一遍交互路径；
4. 在 **windows-latest** 上跑**真实注入集成测试**（注入 `ping.exe`，
   覆盖内存读写含只读页、冻结与解除、资源提取、卸载、重新注入、自我终止）；
5. 用 PyInstaller **单文件**打包（`--onefile`），断言产物只有 `SuperInject.exe`、
   zip 里也只有这一个文件，再压成 `SuperInject-win-x64.zip`；
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

**Q：界面显示「权限 管理员 ✓」而不是 SYSTEM？**
说明 SYSTEM 提权没成功，日志里会写明原因（常见：安全软件拦截令牌复制、
没有可用的 SYSTEM 进程令牌）。功能仍然可用，只是调试不了 SYSTEM 级别的目标。

**Q：能不能只以管理员运行、不要 SYSTEM？**
可以，加 `--as-admin` 参数启动（例如做快捷方式时带上它）。

**Q：为什么任务管理器里看到 SuperInject 的进程名/用户变了？**
提权到 SYSTEM 时程序会「用 SYSTEM 令牌重新启动自己」再退出原进程，属于预期行为。

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
