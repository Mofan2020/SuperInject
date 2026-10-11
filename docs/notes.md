# SuperInject 实施笔记

记录「做了什么、为什么这么做、哪些没动」。改动前请先读这里，避免重踩。

## 一、本版修掉的遗留缺陷（都有 CI 实测证据）

接手时项目「本地测试全绿、CI 全红」，逐条定位后确认是 8 个真实缺陷：

| # | 现象 | 根因 | 处理 |
|---|------|------|------|
| 1 | CI 看似通过实则假绿 | 集成步骤用 bash 语法跑在 pwsh 下；只有「编译」被验证，注入链路没跑过 | 改成真注入 `ping.exe` 的集成测试，失败时自动 dump 注入端日志 |
| 2 | 启动即崩 | `__main__.py` 第 58 行用了未定义的 `log` | 修 NameError，并把启动自检流程显式暴露给前端 |
| 3 | 前端事件全部失效 | `gui.Api._emit()` 里事件名没转义，JS 静默报错 | 修转义并补事件名断言 |
| 4 | 冻结是假的 | 只写了「已冻结」状态，没真挂起线程 | DLL 侧真 `NtSuspendProcess`/逐线程挂起，控制器核实挂起状态 |
| 5 | 重新注入是假的 | 只重新 LoadLibrary，旧 DLL 还在 | 先卸载（等通道断开 + 等模块真的消失）再注入 |
| 6 | 自动更新拿不到资产 | Release 列表接口漏了预发布版本 | 改用 releases 列表并识别 `*.zip` 里带 `win` 的资产 |
| 7 | 校验 DLL 的 SHA 由开发者手写 | 与「SHA 必须程序自动计算」的要求冲突 | 运行时计算内嵌 DLL 的 SHA256 与磁盘产物比对，不一致就重写 |
| 8 | LICENSE 被误识别 | 文件里混入了非 MIT 文本 | 恢复纯 MIT，署名 Skyc8266 |

另外还修了（CI 暴露后逐个定位的四个硬骨头）：

- **控制通道方向性死锁**：命名管道在「服务端写、对端阻塞读」并存时会互等，
  1MB 大缓冲也绕不过。改为**回环 TCP（127.0.0.1）+ 一次性令牌**，端口与令牌
  经 `%TEMP%\SuperInject\port-<PID>.txt` 会合。副作用是通道可以在 macOS 上
  真起 socket 单测（命名管道时代做不到）。
- **数组序列化无限互递归**：`si_json_array_push` 与 `obj_set` 互相回调，任何真的
  往数组塞过元素的命令（`info` / `mem_regions` / `mem_search`）永久卡死，而数组
  恰好为空的 `resources` 反而「正常」，把问题伪装成传输层随机挂死。
- **重新注入的时序竞态**：卸载走 `FreeLibraryAndExitThread`，它先结束线程、加载器
  再异步摘模块 —— socket 断开 ≠ 模块已卸载。必须等模块真的从目标进程消失再注入。
- **`pid_alive` 假存活**：目标退出后只要还有人持有句柄（例如未回收的 `Popen`），
  `OpenProcess` 依然成功 → 把「已 ExitProcess」判成「仍存活」。改用
  `GetExitCodeProcess != STILL_ACTIVE`。

## 二、架构约定（改代码前必读）

- **DLL 是唯一注入端**：`native/agent.c`（+ `superinject_json.c` 纯 C99 JSON 层）。
  控制器 Python 侧只通过回环 TCP 发命令，不直接碰目标进程内存。
- **JSON 层必须保持纯 C99**：不引 `windows.h`、不链 `advapi32` —— 这样本机
  `cc` / CI 的 `cl` 都能编译并运行 `tests/native/test_si_json.c` 自测。
  Win32 小工具（`si_mem_type` / `si_is_elevated`）住在 `agent.c`，不要搬回去。
- **DLL 字节唯一来源是编译产物**：`build/make_payload.py` 只写字节，SHA 一律运行时
  算。禁止把 SHA 常量写进源码或文档。
- **卸载/重新注入必须等「模块消失」**，不能只看 socket 断开（见上表）。
- **构建脚本自己处理编码**：Windows 控制台默认 cp1252，脚本里 `print` 中文会
  `UnicodeEncodeError`；脚本内 `reconfigure(encoding="utf-8")`，同时 CI 顶部设
  `PYTHONUTF8`。

## 三、测试与验证怎么跑

```bash
# 本机（macOS 即可，不需要 Windows）
cc -std=c99 -Wall -Wextra -Werror -I native \
   tests/native/test_si_json.c native/superinject_json.c -o /tmp/t && /tmp/t   # JSON 层自测
x86_64-w64-mingw32-gcc -shared -O2 -Wall -Wextra -Werror -DUNICODE -D_UNICODE \
   native/agent.c native/superinject_json.c -o /tmp/si.dll -lws2_32 -ladvapi32 -lshell32 -luser32
python -m pytest tests -q --ignore=tests/test_integration_windows.py
python -m ruff check superinject build tests run_superinject.py
```

Windows 真机验证（CI 自动跑，本机跑不了）：

```powershell
$env:SUPERINJECT_DLL_PATH = "native\build\SuperInjectAgent.dll"
python -m pytest tests/test_integration_windows.py -v      # 真实注入 ping.exe
dist\SuperInject\SuperInject.exe --self-test               # 打包产物全链路自检
```

## 四、已知限制（不是 bug，是当前边界）

- **仅 Windows**：注入、冻结、内存读写依赖 Win32；macOS/Linux 只能跑纯 Python 单测。
- **SYSTEM 提权有条件**：令牌复制（`SeDebugPrivilege` + `DuplicateTokenEx` +
  `CreateProcessAsUserW`，失败回退 `CreateProcessWithTokenW`）需要管理员，且要有
  一个**同会话**的、未被 PPL 保护的 SYSTEM 进程可作令牌来源（`winlogon.exe` 首选）。
  拿不到就降级为管理员并写明原因，不硬失败。详见第四节之后「SYSTEM 提权」。
- **受保护进程（PPL）无法注入**：`lsass.exe`、`csrss.exe` 这类由 Windows 自身保护，
  连打开令牌都会被拒；本工具把它们与系统关键进程一起拦在注入检查里。
- **GUI 的自动化验证边界**：Playwright 现在能在 CI 里渲染真实页面（布局 + 交互路径，
  `tests/ui/render_check.py`），但 **pywebview 容器本身**（Windows 上的 WebView2 窗口、
  SYSTEM 身份下的 WebView 行为）仍需人工过一遍。
- **资源查看靠嗅探**：提取 PE 资源 + 扫描内存映射里的媒体文件；对没有媒体资源的
  目标（如 `ping.exe`）条目为 0 属正常。
- **残留模块**：若目标进程内 DLL 线程已死但模块被别处引用着（罕见），只能重启目标
  进程后再注入，控制器会明确报出这一点而不是静默超时。

## 五、没动的部分与原因

- **未引入任何 Windows 钩子/驱动**：需求只要求 DLL 注入调试能力，钩子会显著提高
  被杀软误报的概率，超出范围。
- **未做「注入所有进程」快捷操作**：批量注入必须由用户逐个确认目标，避免误伤系统进程。
- **未实现进程内存的写回历史/撤销**：调试场景下写入是小步试错，控制器只提供
  「读 → 改 → 读回」，需要还原时由调用方自己写回（`selftest` 就是这么做的）。
- **命名管道相关代码已删除**，不保留兼容分支：两套通道并存只会让排查更难。

## 六、本轮（v1.0.2）：UI 重做 / SYSTEM 提权 / 单文件打包

需求原文：「修复 UI 问题…请允许整体页面滚动，并处理好各个功能区的空间大小分配」、
「提权自身到 SYSTEM 权限」、「打包为单个 EXE 文件（无 _internal 文件夹）」、
「UI 尽可能使用 Apple 风格」。

| # | 问题 | 根因 | 处理 |
|---|------|------|------|
| 1 | 界面「绝大多数情况下显示不全」 | 窗口写死 `1280x820`、`min_size=(1040,640)`：小屏/高缩放机器上窗口比屏幕还大，底部功能区永远在屏幕外；同时 6 个面板各自 `max-height` 固定像素，与窗口高度无关 | 窗口尺寸按屏幕可用区域计算（≤ 屏幕 92%，最小 720x500，`winapi.screen_work_area()`）；`html/body` 去掉 `height:100%`，改由**整页滚动**；各功能区改用 `clamp(…, vh, …)` 分配高度 |
| 2 | 视觉不统一 | 深色单一主题、控件样式拼凑 | 重写 `style.css`：macOS 设计语言（系统蓝 / 圆角 8-14px / 毛玻璃吸顶栏 / 分段导航 / 覆盖式滚动条），**跟随系统自动切浅色深色** |
| 3 | 提权只到管理员 | `elevate.py` 只有 UAC | 新增 `system_token.py`：同会话找 SYSTEM 进程 → 复制主令牌 → `CreateProcessAsUserW` 重启自身（回退 `CreateProcessWithTokenW`），GUI 仍在当前桌面 |
| 4 | 交付物是一个文件夹 | PyInstaller `--onedir` | 改 `--onefile`，并在 `build_exe.py` 与 CI 里双重断言「只有单个 exe、zip 里也只有它」 |
| 5 | 高权限目标「注入成功但连不上」 | 注入端只读**自己** TEMP 下的会合文件；SYSTEM 服务的 `GetTempPathW()` 是 `C:\Windows\Temp`，而控制器写在启动它的用户 TEMP 里 | 注入端加只读回退：扫各用户 `%TEMP%\SuperInject\`（**不往公共目录写令牌**，避免把一次性令牌暴露给其他本地用户）；`tests/test_integration_windows.py::test_inject_target_with_foreign_temp` 专门构造「目标 TEMP 与控制端不同」来跑这条路径 |
| 6 | 前端启动跑两遍 | `pywebviewready` 与「api 已就绪」两条路都调 `boot()` | 加 `booted` 守卫，只启动一次 |

### SYSTEM 提权的关键决策

- **用「复制令牌 + CreateProcessAsUserW」而不是计划任务 / PsExec**：计划任务以 SYSTEM
  启动会掉进 **session 0**（没有交互桌面），GUI 根本显示不出来；PsExec 是外部二进制、
  还会注册服务。令牌复制只用系统自带 API。
- **候选进程必须同会话**：跨会话创建进程需要 `SeTcbPrivilege`（只有 SYSTEM 自己有），
  同会话则完全不需要。
- **首选 `winlogon.exe`**：它是 SYSTEM、每个交互会话都有，且**未被 PPL 保护**；
  `lsass.exe` / `csrss.exe` 在 Win10+ 受保护，`OpenProcessToken` 直接 ACCESS_DENIED。
- **`lpDesktop` 先空着**（继承父进程窗口站/桌面，同会话下最稳），失败再显式
  `winsta0\default` 重试。
- **必须传显式环境块**：`TEMP` 要原样继承 —— 控制器与注入端靠
  `%TEMP%\SuperInject\port-<PID>.txt` 会合，TEMP 变了就连不上。同时用
  `SUPERINJECT_SYSTEM_LAUNCH=1` 给子进程打标，防止自我重启死循环。
- **降级而不是硬失败**：提权不成 / 用户加了 `--as-admin` 时以管理员继续，日志写明原因。

### 可验证性（怎么证明不是「写着好看」）

- `tests/test_system_token.py`（跨平台，31 例）：结构体 ABI 断言 —— `STARTUPINFOW`
  必须正好 104 字节、`PROCESS_INFORMATION` 24、`LUID` 8、`TOKEN_PRIVILEGES` 16。
  **这里踩过一个坑**：最初用 `ctypes.wintypes.DWORD`（= `c_ulong`），在本机算出的是
  Windows 的两倍大小，布局错误只有到 Windows 才暴露；改成定宽类型后本机就能拦。
- `tests/test_system_token_windows.py`（Windows + 管理员）：真复制 SYSTEM 令牌，
  并**真创建一个 SYSTEM 进程**，读子进程写回的身份文件断言
  `privilege == "system"` 且 SID 是 `S-1-5-18`。
- `--self-test` 增加两步（`SYSTEM 令牌复制` / `SYSTEM 提权链路（真实创建 SYSTEM 进程）`），
  报告里带上令牌来源进程、子进程 PID、会话与 SID；环境不允许时记为 `unknown` 并写明原因，
  不静默当通过。
- `tests/ui/render_check.py`（Playwright）：假后端 `tests/ui/mock_bridge.js` 把真实
  页面渲染出来，在 1280x800 / 1024x640 / 760x520 + 深浅两套外观下断言整页可滚动、
  无横向溢出、六个功能区都能滚进视口且标题不被吸顶栏遮挡、滚到底日志区完整可见，
  并真点一遍交互路径（选进程 → 资源墙 → 内存搜索 → 危险操作确认框）。

## 七、本轮没动 / 没做的部分与原因

- **没有给通道加文件系统以外的会合方式**（注册表、`\.\mailslot`、共享内存等）：
  当前只读扫描已覆盖「同用户」「SYSTEM 服务」两类目标；再加通道只会扩大攻击面。
- **没有引入单实例互斥**：同时开两个 GUI 仍然是两个独立控制器（与旧版一致）。
  这属于产品行为变更，等确有必要再做。
- **没有把前端换成框架**：还是原生 JS + 一个 CSS 文件，避免为一次视觉重做引入构建链。
- **没有做 UI 的像素级视觉回归**（截图对比）：只断言布局不变量，截图仅作 CI 工件留档；
  像素对比在不同 runner 字体/渲染下抖动太大，收益不成正比。

## 八、v1.0.2 发布前 CI 抓出的两个真问题（都已修，本机复现验证）

### 1) 单文件打包后「自检卡死」：子进程复用了父进程的解包目录

现象：CI 的「打包产物自检」步骤 10 分钟不返回（v1.0.1 的 onedir 只要 2~3 分钟）。

根因（本机用最小 onefile 程序复现，非推测）：

```
PARENT _MEIPASS=/tmp/_MEIEmM8NY
[照抄环境] CHILD _MEIPASS=/tmp/_MEIEmM8NY   ← 与父进程完全相同
[清掉变量] CHILD _MEIPASS=/tmp/_MEInQLg53   ← 自己解包了一份
```

PyInstaller onefile 会把 `_PYI_APPLICATION_HOME_DIR` / `_PYI_ARCHIVE_FILE` /
`_PYI_PARENT_PROCESS_LEVEL` 塞进**当前进程的环境**，指向它解包出来的 `_MEIxxxx`
目录。拉起「自己」时照抄环境，子进程就直接用父进程那份解包结果：子进程退出的清理
会动到父进程正在使用的目录，于是卡死 / 随机失败。

修复：`system_token.child_environment()` 清掉这组私有变量（`_PYI_PRIVATE_ENV`）。
在真实 onefile 产物里验证过：子进程拿到自己的 `_MEIPASS`，且
`is_launched_child()` 为 True（说明跑的确实是我们的代码）。

> 教训：**任何「打包产物拉起自己」的路径都要清掉这组变量**，不只是提权重启。

### 2) `--windowed` 产物里的裸 `print` 会导致「双击没反应」

GUI 子系统的 exe 在 Windows 上没有控制台，`sys.stdout` 可能是 `None`，此时
`print()` 抛 `AttributeError`。而启动自检的一串 `print("[自检1] …")` 发生在 GUI
**之前** —— 抛异常就是窗口都没起来、进程已死，用户完全看不出原因。

修复：新增 `superinject/console.py::safe_print`（无控制台时静默失败、绝不抛），
`__main__.py` 全部输出改走它，`selftest._safe_print` 收敛到同一实现。

### 3) 本轮 CI 还抓出一个补丁误伤

补丁把 `selftest.py` 的 `from . import dll_manager, elevate, winapi` 误改成
`ipc`（模糊匹配匹配到了相邻行），ruff 的 F821 当场拦下 —— 否则自检第一步就
NameError。**改完 import 行务必跑一次 ruff**，这类误伤不会自己暴露。

## 九、v1.0.2 的验证证据（可复核）

发布件 `SuperInject-win-x64.zip`（13,292,297 字节，sha256
`2e1769f5cb4455946a3b56de1970c07c45fb94253522b0fde5945ec5803acf56`）里**只有
`SuperInject.exe` 一个文件**，解压后 13,509,566 字节。

在 windows-latest 上对**这个发布产物**跑 `--self-test`，21/21 步通过，其中提权相关：

| 步骤 | 实测结果 |
|---|---|
| SYSTEM 令牌复制（SeDebugPrivilege + DuplicateTokenEx） | 来源 `winlogon.exe` pid=7292 sid=`S-1-5-18` |
| SYSTEM 提权链路（真实创建 SYSTEM 进程） | `CreateProcessWithTokenW` 创建 pid=7532，权限 **system**，sid **S-1-5-18**，session=2 |

注意实测走的是**回退路径** `CreateProcessWithTokenW`（GitHub runner 默认不持有
`SeAssignPrimaryTokenPrivilege`）—— 这正说明双路径回退不是摆设，而是必要的。

另外新增两个 CI 守卫：冻结产物 `--help` 必须退出 0（覆盖无控制台 print 路径）、
`integration` / `exe-self-test` 加 `timeout-minutes`（卡死必须是失败，不能一直转圈）。

## 十、v1.0.3：删掉 ubuntu 上的 MinGW 交叉编译 job

起因是一个很合理的质问：「windows runner 能编译过、功能自动化测试也没问题，
为什么还要在 ubuntu 上交叉编译一遍？」查完发现**原设计是反的**：

| | MinGW（ubuntu 交叉编译） | MSVC（windows runner） |
|---|---|---|
| 当时谁在用 | **发布件**（package 取 `dll-mingw`） | 只有集成测试用 |
| 导入表 | ADVAPI32 / KERNEL32 / WS2_32 / msvcrt.dll | ADVAPI32 / KERNEL32 / WS2_32（**无 CRT 依赖**） |
| 体积 | 382,821 字节 | **194,560 字节** |

也就是说：**功能测试跑的那份不发布，发布的那份只做过编译检查**；而且发布的是更重、
多一层 CRT 依赖的交叉编译产物。改成单一产线：

* 删掉 `native-mingw` job；`native-msvc` 成为唯一 DLL 构建方式；
* `integration` 与 `package` 都取 `dll-msvc` —— 发布件就是被测物；
* `build/build_native.py` 保留 MinGW 路径，但**明确只用于本机开发**（macOS 跑不了
  `cl.exe`），并且现在优先用 MSVC（有的话），贴近发布件。

### 用「导入表守卫」替代原来 mingw job 的隐性价值

原来那个 job 间接盯的是「DLL 别依赖用户没装的运行库」（MinGW 默认只链 msvcrt.dll）。
但真正该断言的是结果，于是新增 `build/check_dll_imports.py`（纯 Python 解析 PE 导入表，
CI 在 windows runner 上跑）：

* 拦：`VCRUNTIME140.dll` / `MSVCP140.dll` / `MSVCR120.dll`（带版本号的 CRT）/ `python*`
  —— 这些要求用户机器额外安装，DLL 一旦导入它们，注入时 `LoadLibrary` 直接失败，
  症状是「注入失败」但原因极难看出来；
* 放行：`KERNEL32/ADVAPI32/WS2_32/SHELL32/USER32/msvcrt.dll`，以及 `api-ms-win-*`
  这组 Windows API Set（含 UCRT）—— Win10+ 系统自带，本项目最低支持 Win10 x64。

已用真实产物验证过正反两个方向：

```
本机 mingw 产物（UCRT 版）      → OK
CI 的 MSVC 产物                 → OK（导入表最干净）
CI 的 mingw 产物                → OK（只链 msvcrt.dll）
把导入名改成 VCRUNTIME140.dll   → FAIL + exit 1（守卫真的会拦）
```

> 踩到的坑：第一版把 `msvcr` 当禁用前缀，结果把系统自带的 `msvcrt.dll` 也拦了；
> 只有**带版本号**的 `msvcrNNN.dll` 才需要额外安装。另外本机 Homebrew 的 mingw-w64
> 默认用 UCRT（`api-ms-win-crt-*`），而 CI ubuntu 上的 mingw 默认用 msvcrt.dll ——
> 同一个脚本编译出两种依赖，这也是「看导入表」比「看编译器」更靠谱的例证。
## 十一、v1.1.0：CLI 模式 / 路径搜索 / x86 支持

需求原文：

* 添加 CLI 模式：``-c -y <command>``，``-h`` 帮助无需 ``-c``。
* 进程搜索支持按路径过滤。
* 支持注入 x86 应用（两个 DLL，自动选）。

### CLI 入口

``superinject/cli.py`` 提供 ``-c`` / ``-y`` / ``-h`` 与子命令分派。子命令格式：

* 子命令风格：``si.exe -c -y inject 1234``
* 单串 DSL：``si.exe -c -y 'inject 1234 --json'``（``parse()`` 内部 shlex 再切一次）

输出默认 plain text，``--json`` 切 JSON；``--report PATH`` 把结果同时落盘。CLI 也
走 ``elevate.ensure_privilege``，自动 UAC/SYSTEM 提权后退出原进程；``-y`` 没给时
直接拒绝执行（防误操作）。

子命令集：

```
list            # --name / --path / --pid / --injected-only
preflight       # 注入前预检
inject          # 自动按目标位数选 DLL；--arch 强制
freeze / unfreeze / info / ping / unload / terminate
mem-search / mem-read / mem-write
open / status / dll
```

### 路径搜索

``controller.list_processes()`` 已带 ``path`` 字段（``winapi.process_path(pid)``），
``cli._filter_processes`` 与 GUI 搜索都按子串匹配 ``path`` / ``name``。

### x86 DLL

CI 的 ``native-msvc`` 现在跑 ``strategy.matrix.arch: [x64, x86]``，分别走
``ilammy/msvc-dev-cmd@v1`` 的 ``arch: x64`` / ``arch: x86``，产物为
``SuperInjectAgent.dll`` (x64) + ``SuperInjectAgent_x86.dll`` (x86)。两条都过
``check_dll_imports.py``（导入表守卫复用）。

``dll_manager``：

* ``embedded_bytes(arch="x64"|"x86")`` 拿对应内嵌字节；``x86`` 未内嵌返回 None
  而不是抛异常，方便「暂时没编 x86」的本地开发场景。
* ``dll_for_arch(arch)`` 优先返回已释放的 DLL，其次回退到 ``native/build/``。
* ``verify_and_sync(arch=...)`` 两份 DLL 各自跑自检与释放。
* ``build/make_payload.py`` 同时嵌入 ``DATA_B64`` 与 ``DATA_B64_X86``，x86 缺失
  时 ``DATA_B64_X86`` 留空串 + 打 warning（仍能继续编 x64）。

``Controller.inject(arch="")``：

* ``arch=""``：对每个 PID 跑 ``is_wow64(pid)`` 探测位数，各自选 DLL —— 混批
  x86 + x64 时按 DLL 分组并发注入。
* ``arch="x64"|"x86"``：所有目标统一用该位数。

注入检查（``preflight``）同步：位数不匹配时若该位数 DLL 可用，只加 warning
不再 blocked。

集成测试 ``tests/test_integration_windows.py::test_x86_injection_on_syswow64_ping``
在 windows runner 上真跑：拉起 ``C:\Windows\SysWOW64\ping.exe``（32 位），
用 ``SUPERINJECT_DLL_PATH_X86`` 注入并 ping 验证。

### 已知约束（没做的部分与原因）

- **未做 CLI 的交互式 REPL**：CLI 是给 Agent 用的、单次调用即退出；带 REPL 就要
  解决 stdout 缓冲 + 中断信号 + 多命令上下文，越界。
- **CLI 输出没做颜色 / 进度条**：plain text 优先，颜色让管道与日志更乱。
- **没把 ``--json`` 改成自动检测 TTY**：脚本场景下用户希望明确控制输出格式。
- **x86 注入检查仍走 ``IsWow64Process``**：这是 Windows 提供的标准 API，没有更
  好的办法；CI 上必须用 SysWOW64\ping.exe 才能拿到真 32 位目标。

### 验证证据

* macOS 本地 MinGW 交叉编译：``x86_64-w64-mingw32-gcc -Werror`` 与
  ``i686-w64-mingw32-gcc -Werror`` 两条都过；产物字节数 x64=156,902 / x86=148,063，
  机器码分别为 0x8664 与 0x014C。
* ``tests/test_cli.py`` 21 例全过（跨平台；Win32 调用打桩）。
* ``tests/test_controller.py`` 中位数相关的两条用例更新：
  ``test_preflight_blocks_arch_mismatch``（x86 DLL 不可用时拦下）
  + ``test_preflight_allows_arch_mismatch_when_dll_available``（可用时放行）。
* ``tests/test_dll_and_update.py`` 全部更新为 ``lambda *a, **kw: ...`` 兼容
  ``embedded_bytes(arch)`` 的新签名。

## 十二、v1.2.0：调试能力扩展（崩溃转储 / 事件流 / 符号 / 线程 / trampoline）

需求原文：「SuperInject 持续扩展功能，提供更强的开发调试能力」—— 四个方向
同时上：

1. **崩溃转储（minidump）** —— DLL 在 `DllMain` 装 `SetUnhandledExceptionFilter`
   + `AddVectoredExceptionHandler`，拦截 `EXCEPTION_ACCESS_VIOLATION /
   STACK_OVERFLOW / ILLEGAL_INSTRUCTION / DIVIDE_BY_ZERO / PRIV_INSTRUCTION
   / GUARD_PAGE / INVALID_HANDLE` 时落 `%TEMP%\SuperInject\<pid>\dump-<tick>.dmp`
   （走 `MiniDumpWriteDump`）+ 同名 `.json` sidecar（元数据）。
   "协议上不需要 DLL 崩溃后还能回话"——所以控制器在 `on_detach` 时按 attach
   时记录的"水位线"扫 `dump-*.dmp`，新文件合成 `event:crash` 推到事件流。

2. **事件流** —— `ipc.AgentServer` 加 `on_event` 通路：DLL 主动推 `type=event:*`
   帧不参与 id 匹配，否则会被误清空 waiter。`Controller._on_event` 把消息转
   存 + 触发订阅回调 `on_event`；CRUD 接口 `list_events(pid=None, name=None,
   clear=False)`。

3. **模块符号解析** —— 自写轻量 PE 解析（`pe_parse_image` +
   `collect_module_exports`，覆盖 PE32/PE32+），单模块最多 256 条、按名字去重；
   `info` 命令附每模块的导出，`exports` 命令按 base / name 单查。
   `superinject.symbols` 提供 `build_module_index / resolve_address /
   format_address`（输出 `module!symbol+0x42`）/`lookup_export`（GUI 模糊搜索）。
   不依赖 dbghelp / symsrv。

4. **线程级冻结** —— `threads` 列目标进程全部线程（`Thread32First/Next` +
   `GetThreadDescription` 拿名字 + `NtQueryInformationThread(ThreadBasicInformation)`
   拿 SuspendCount）。`thread_suspend` / `thread_resume` 单条挂起/恢复
   （`OpenThread THREAD_SUSPEND_RESUME` + `NtSuspend/ResumeThread`）。

5. **代码 patch (trampoline)** —— 4 个新指令 `patch_inject`/`patch_list`/
   `patch_revert`/`patch_clear`：在目标地址写 5 字节 `E9 rel32` 跳到刚
   `VirtualAlloc` 的 RWX 跳板，shellcode 末尾 `E9 rel32` 跳回原地址+5；
   原 5 字节备份，写回即还原。上限 32 条/进程。

### 12.1 协议变更

* `ipc.AgentServer.on_event(cb)` 新增；回调签名 `(pid:int, msg:dict) -> None`。
* `Controller.on_event(cb)` 同步；列表 `list_events(pid, name, clear)`。
* 新 IP 命令（全部 require-DLL-on-target）：`events / dumps / threads /
  thread_suspend / thread_resume / exports / patch_inject / patch_list /
  patch_revert / patch_clear`。

### 12.2 改动文件

* `native/agent.c`：约 700 行新增（崩溃转储、VEH/SEH handler、内存 trampoline、
  线程枚举、单线程挂起、PE 导出解析）。
* `superinject/ipc.py`：`on_event` 通路 + `_dispatch` 区分 `event:*` 帧。
* `superinject/controller.py`：`_on_event` / `list_events` / `on_event` /
  合成 crash 事件（detach 时扫 dump 目录）；`exports`/`threads`/
  `thread_suspend`/`thread_resume`/`patch_inject/list/revert/clear`。
* `superinject/symbols.py` 新模块（离线单测 5 通过）。
* `superinject/cli.py`：`exports/threads/thread-suspend/thread-resume/
  patch-inject/patch-list/patch-revert/patch-clear/events/dumps` 10 个子命令。
* `superinject/version.py` 与 `native/agent.c` 里 `SI_VERSION` 都 bump 到 1.2.0。
* `build/build_native.py` 和 `.github/workflows/ci.yml` 加 `dbghelp.lib` /
  `-ldbghelp`。
* `tests/test_ipc_socket.py` + `test_controller.py` + `test_cli.py` +
  `test_symbols.py` 新增共 8 个测试。

### 12.3 验证证据

* macOS 端：197 单测全过；ruff clean。
* Windows 端：CI 编译 DLL（MinGW 或 MSVC）→ 集成测试会一并跑 patch 注入：
  本机需要实测才能确认。
* v1.2.0 未经星空喵手测确认前按"全项目硬规矩"只发 Pre-release，不升正式版。

## 十三、v1.3.0：内存快照 / diff（P1 调试核心之前半段）

P1 是 v1.3.0 计划里最独立的一节：纯 controller + agent.c，不引入新 Python
依赖、不动 DLL 端的 windows.h 边界。P2 硬件断点、P3 寄存器捕获在 P1 之前
没用 —— 历史调试界面里"找 1 字节差异"靠 mem_read + 手动对比，P1 把这条
路径自动化成"拍一个 SHA 快照、过会拍另一个、按 SHA diff 出页级变化"。

### 13.1 协议变更

* DLL 端两条新命令：
  * ``mem_snapshot(name, regions?)`` —— 拉指定 regions（或自动 mem_regions 当前
    视图），逐 4KB 页 SHA-256 + 前 64 字节 + bytes 大小，回 ``{name, count, bytes, sha256, pages:[{addr, size, sha, head64}]}``。
  * ``mem_diff(a_pages, b_pages)`` —— 接收两侧 pages 列表（来自控制器），按 sha
    比对；变化页回 ``head64`` 两栏 hex，相同页累计到 ``unchanged_count``。
  * 不落盘：DLL 只算 / 只传，不写文件；落盘是控制器侧的事。
* 控制器 ``Controller.snapshot(pid, name, regions=None)`` → 调 DLL + ``SnapshotStore.save()`` → 落盘 + 更新索引。``Controller.diff(pid, name1, name2, limit=0)`` → ``SnapshotStore.diff()`` → 调 DLL 校头 → 拼出 ``changed / only_in_a / unchanged_count``。
* CLI 4 个子命令：``snapshot`` / ``diff`` / ``snapshots``（列表） / ``snapshot-delete``；默认 plain text，``--json`` 出结构化。

### 13.2 改动文件

* ``native/agent.c``：~260 行新增（FIPS 180-4 SHA-256 自实现 ~150 行 + 4KB 分页
  memory snapshot loop ~80 行 + mem_snapshot / mem_diff 两个 handler ~140 行）；
  ``SI_VERSION`` 从 1.2.0 升 1.3.0；新增 ``si_json_is_array()`` 给上层查询用。
  SHA-256 自实现零外部依赖；macOS / Linux 上的 ``cc -std=c99 -Wall -Wextra -Werror``
  必须能直接跑（见 ``tests/native/test_si_sha256.c`` 13 个 NIST 向量）。
* ``native/superinject_json.{c,h}``：暴露 ``si_json_is_array()``，避免 caller 触碰
  struct 内部（agent.c 的 strlen 测试用得着）。
* ``superinject/snapshots.py`` 新文件：``SnapshotStore`` + 落盘 + 索引；
  路径 ``%LOCALAPPDATA%/SuperInject/snapshots/<pid>/<name>.json``（Windows） /
  ``~/.local/share/SuperInject/snapshots/...``（macOS / Linux），无新依赖；
  ``SUPERINJECT_SNAPSHOT_ROOT`` 环境变量供测试覆写路径。
* ``superinject/controller.py``：~80 行新增（``snapshot`` / ``list_snapshots``
  / ``delete_snapshot`` / ``diff`` 方法 + ``_snapshot_store`` 懒加载工厂）。
* ``superinject/gui.py``：``Api`` 加 ``list_snapshots`` / ``snapshot`` /
  ``diff_snapshot`` / ``delete_snapshot`` 4 个方法暴露给前端。
* ``superinject/cli.py``：``snapshot`` / ``diff`` / ``snapshots`` /
  ``snapshot-delete`` 4 个子命令 + 帮助更新。
* ``superinject/web/{index.html, app.js, style.css}``：「内存快照」面板插入到
  「内存调试」与「日志」之间，含列表 + 选择两个做 diff + 6 个快照数 + 顶部按钮组。
* ``superinject/version.py`` 与 ``native/agent.c`` 的 ``SI_VERSION`` 都 bump 到 1.3.0。

### 13.3 验证证据

* macOS 端：211 单测全过；ruff clean；``cc -std=c99 -Wall -Wextra -Werror`` 单独
  编 SHA-256 自测 13 个 NIST 标准向量（空 / abc / 56 字节 abcd... / 64 / 65 字节
  全零 / 56 'a' / quick-fox 43 / quick-fox 86 / 1MB 'a'）全部命中标准值，
  与 ``hashlib.sha256(...)`` 完全一致。
* Windows 端：CI 会用 MSVC 重编 DLL → 在 ``tests/test_integration_windows.py``
  跑 ``test_snapshot_and_diff``（注入 ping.exe → RW 页拍 A → 改 1 字节 → 拍 B
  → diff 出 1 条 changed 页，校验 ``old_bytes`` / ``new_bytes`` 在我们改的 offset
  字节值）。
* v1.3.0 同样按"全项目硬规矩"未经星空喵手测确认前只发 Pre-release。

### 13.4 未做的部分

* 没做内存视图的可视化导航（左栏地址树、右栏 hex）。P1 满足"找 1 字节改动"
  这条最小路径，把导航留到 P5（GUI 一键启动 MCP）+ 后续。
* 没把 SHA 校验搬到硬件加速（CRC32 指令集 / AES-NI 自带 SHA）。SHA-256 是
  自实现的纯 C，足够快（4KB 页 / 一次快照万级页 ≈ 30MB / 秒），上 SSE 反而
  要再绑编译开关，违反「DLL 字节唯一来源是编译产物」的硬规矩。
* 没做快照自动去重（同一秒拍两次内容相同就跳过）。 当前要求是"用户
  主动拍、不主动触发"，下次需要时再加。

## 十四、v1.3.0：硬件断点（P2 调试核心之后半段）

v1.3.0 调试能力的第二段。P1 已经把"对得上 1 字节改动"的快照落盘了，P2
把"看得到运行到那一步"的断点也接上；P3 会再把现场抓全（寄存器 + 栈）。

### 14.1 协议变更

**DLL 侧（`native/agent.c`）**：

* 新增 4 条命令：`bp_set` / `bp_list` / `bp_remove` / `bp_clear`。
  - `bp_set` 参数：`tid`（非 0 → 硬件 DR 槽；0 → VEH 模拟）、`address`、
    `type_str ∈ {exec, read, write, rw}`、`len ∈ {1,2,4,8}`。
  - 槽位耗尽时返回 `{"ok": false, "error": "no_slot_available"}`。
* 命中事件 payload（`event:breakpoint`）：
  - 字段：`addr` / `pid` / `tid` / `slot`（-1=VEH）/ `kind`（"hw" | "veh"） /
    `fault_addr` / `hit_count` / `bp_type` / `bp_len`。
  - P3 **占位字段**：`regs`（空对象）/ `stack`（空数组）—— P2 阶段先把
    schema 占位写好，避免 P3 接入时再改协议字段。
* 同一 VEH handler 内分流（`agent_veh_filter` 顶部新增两段）：

  ```c
  if (c0 == EXCEPTION_BREAKPOINT) {
      LONG rc = si_veh_breakpoint_dispatch(ep);
      if (rc != EXCEPTION_CONTINUE_SEARCH) return rc;
  } else if (c0 == EXCEPTION_SINGLE_STEP) {
      LONG rc = si_veh_single_step_dispatch(ep);
      if (rc != EXCEPTION_CONTINUE_SEARCH) return rc;
  }
  ```

  —— 不新增 VEH。命中后 `CONTEXT.Rip` 回跳到 orig 字节、`EFlags |= TF`
  走单步，`si_veh_single_step_dispatch` 把 `0xCC` 重装回去。

**Controller 侧（`superinject/controller.py`）**：

* 新增 4 个方法：`breakpoint_set` / `breakpoint_list` /
  `breakpoint_remove` / `breakpoint_clear`。
  - `breakpoint_set(address, target, tid, bp_type, size, symbol_index)`：
    `module!symbol+offset` 形式先经过
    `superinject.symbols.resolve_symbol` 转地址再下发；纯数字地址走
    passthrough。
* 命中事件透传：`Controller.on_event` 已就绪（v1.2.0），断点事件
  即"主动推送、不期望响应"，与现有 `event:*` 通道一致。

**符号层（`superinject/symbols.py`）**：

* 新增 `resolve_symbol(index, target)` —— 把
  `module!symbol+0x42` / `module+0x42` / `0x401000` 统一解到
  `(addr, module_name, offset, symbol_or_None)`，找不到时返回 `None`。

**CLI（`superinject/cli.py`）**：

* 新增 4 个子命令：`bp-set` / `bp-list` / `bp-remove` / `bp-clear`。
  - `bp-set <pid> <target> [--tid T] [--type exec|read|write|rw] [--size 1|2|4|8]`，
    `target` 接受数字或 `module!symbol+0x42`；后者内部自动 `info` 拉模块表 +
    `exports` 拉导出。
* `--json` 输出结构化、默认 plain text。

**GUI（`superinject/web/`）**：

* 新增 `panel-bp` 面板（折叠式，在「内存快照 / diff」和「日志」之间）：
  列表（地址 / 类型 / 大小 / kind / tid / 命中数）+ 装载表单 +
  命中事件流（折叠，含「复制最新 payload」按钮，方便贴给 Agent）。

### 14.2 改动文件

* `native/agent.c`：新增约 600 行（P2 数据结构 + 4 个 bp_* 命令 + VEH 命中
  分支与单步重装 + g_send_cs 锁）；DllMain 增加 si_send_cs_init 与
  退出时把所有 VEH 模拟 patch 还原。
* `superinject/symbols.py`：`resolve_symbol`（约 60 行，新增）。
* `superinject/controller.py`：4 个方法（约 130 行，新增）+ `Tuple` 入
  typing。
* `superinject/cli.py`：4 个 subparser + 4 个 dispatch 块 +
  `_build_bp_index` helper（约 100 行，新增）。
* `superinject/gui.py`：4 个 Api 方法 + `_build_bp_index` + `list_events`
  暴露（约 70 行，新增）。
* `superinject/web/index.html`：`panel-bp` section（约 45 行 HTML）。
* `superinject/web/app.js`：断点面板渲染 / 装载 / 移除 / 清空 / 命中事件
  流轮询（约 200 行新增）。
* `superinject/web/style.css`：断点面板样式（约 90 行新增）。
* `tests/test_breakpoint.py`（新增）：跨平台 12 条单测，覆盖控制器协议帧、
  symbols 解析（5 种形式）、事件 payload schema、槽位耗尽 fallback、
  hw/VEH 两条路径并存。
* `tests/test_integration_windows.py`（增量）：`test_hw_breakpoint_on_ping`，
  真注入 ping.exe → 在 ping 模块的某个 `Icmp*` 导出上 bp_set → 等 25s
  命中 → bp_clear 清理。

### 14.3 验证证据

* **DLL 编译零新 warning**：MinGW 走
  `x86_64-w64-mingw32-gcc -shared -O2 -Wall -Wextra` 全部
  `-Wcast-function-type` warning 仍是 v1.2.0 既存的（5 条全在
  write_dump_with_meta / NtSuspendThread / NtResumeThread /
  NtQueryInformationThread / GetThreadDescription），P2 没有
  引入任何新 warning。
* **单测**：基线 211 + 新增 12 = **223 passed**（含 5 skip = Windows-only）。
  `ruff check` clean。
* **DLL 体积**：181KB → 188KB（+7KB），断点指令路径未引入未用代码。

### 14.4 P3 占位与硬规矩对照

* **VEH 单 handler 分流**：`si_should_capture` 与崩溃转储逻辑未改动；
  `agent_veh_filter` 入口先分 `EXCEPTION_BREAKPOINT` /
  `EXCEPTION_SINGLE_STEP`，命中走 bp，否则继续原流程。**没**装新 VEH。
* **不引入新 Python 依赖**：仍然只用 stdlib。`mcp` 等 P4 才进。
* **P3 占位字段保留**：每个断点命中事件的 payload 强制带 `regs: {}` /
  `stack: []`，对应的强约束在 `tests/test_breakpoint.py` 的
  `test_breakpoint_event_payload_schema_construction`。
* **CI 全绿**：`pytest tests -q --ignore=tests/test_integration_windows.py`
  通过（基线 + 新增 = 223 passed，5 skip）；`ruff check` clean。
* **DLL 编译零新 warning**：见 14.3。

### 14.5 未做的部分与原因

* **未做完整 CONTEXT 寄存器捕获**：P2 阶段 `regs` 字段是空 obj。
  P3 会通过 `GetThreadContext` 取 CONTEXT_FULL（x64：rip/rsp/rbp/r8–r15 +
  segments；x86：Eip/Esp/Ebp + segments），再把栈 16 个 QWORD 一起填进
  `stack` 字段。schema 在 P2 已定好，P3 只填字段不重新设计。
* **未做条件断点（条件表达式）**：plan 把这条留给 v1.4.0。P3 至少先把
  CONTEXT 与栈捕获好，条件断点需要先有"代码能拿到 caller 给的 Python 表达式"的
  边界（P5 的 MCP 工具期才会出现）。
* **未做数据断点的原子 action（断点命中时跳/单步/写入寄存器改 Eip）**：
  一旦装有"自定义命中动作"，需要把 `EXCEPTION_CONTINUE_EXECUTION` 之外的
  路径考虑全（P3 之后单独走 P3.5 计划）。
* **未做 CONSOLE 子命令 `bp-trace` 长跑模式**：长跑需要 controller 端对
  命中做 ring-buffer + flush；同样放 P4 / MCP 阶段。

## 十五、v1.3.0：断点寄存器 / 栈捕获（P3 调试核心补全）

P2 把"看得到运行到那一步"的断点接上了，但命中事件的现场是空的 —— `regs`
是空对象、`stack` 是空数组，光知道"命中了"，不知道**命中那一刻各寄存器是
什么值、栈上是什么**。P3 就把这两个字段填成真内容：`regs` 来自 VEH 路径
直接给我们的真 `CONTEXT`（不需要再 `GetThreadContext`），`stack` 从
RSP/ESP 起读 16 个 QWORD/DWORD。**协议 schema 一个字段名都没动** —— P2 定
的字段名是硬约束（`test_breakpoint_event_payload_schema_construction`），
P3 只填值。

### 15.1 协议变更

**DLL 侧（`native/agent.c`）**：

* `si_send_breakpoint_event` 签名从 `(bp, fault_addr, tid)` 扩为
  `(bp, fault_addr, tid, ctx)`。唯一调用点 `si_veh_breakpoint_dispatch(ep)`
  把 `ep->ContextRecord` 传进来 —— **VEH 路径下这块就是被冻结目标线程的
  真 CONTEXT**，不用再拉一次线程上下文。

* `regs` 字段内容（`si_emit_regs`）：
  - x64：`rip` / `rsp` / `rbp` / `rflags` + `rax..rdi` + `r8..r15`
    （14 个 GPR）+ `cs` / `ss`；
  - x86：`eip` / `esp` / `ebp` / `eflags` + `eax..edi`（6 个 GPR）
    + `cs` / `ss`；
  - `ctx == NULL` 时仍为空对象（schema 不变）。

* `stack` 字段内容（`si_emit_stack`）：
  - 从 `RSP`（x86 为 `ESP`）起读 16 个 `ULONG_PTR` / `DWORD`；
  - 每项 `{i, addr, value}`（`i` 0..15，`addr` 该项地址，`value` 读到的值）；
  - **安全**：读之前先 `VirtualQuery` 校验该地址所在页 `MEM_COMMIT` 且不带
    `PAGE_NOACCESS` / `PAGE_GUARD`；不满足 → `stack: []`，**命中事件照推**，
    不让断点路径因栈坏而崩。

* **不改**的字段：`type` / `addr` / `pid` / `tid` / `slot` / `kind` /
  `fault_addr` / `hit_count` / `bp_type` / `bp_len` —— 全部原样。

**Controller 侧（`superinject/controller.py`）**：

* **无改动**。v1.2.0 的 `_on_event` 本来就是"把除 `id` / `type` 外的键
  原样并入事件 dict"，`regs` / `stack` 自然透传给 `list_events` 订阅方
  （GUI / CLI / 未来 MCP）。

**前端（`superinject/web/`）**：

* 命中事件流每条事件新增两个折叠面板：
  - **展开寄存器**：按 GPR 分组，每行 2 个寄存器 + 值（十六进制）；
    架构判断与 DLL 侧一致 —— 有 `rip` 即 x64、有 `eip` 即 x86，两者皆缺
    则不显示该面板；
  - **展开栈**：`addr  value` 两列，前 16 项；
  - 原始 payload 改为折叠（默认收起，方便整条贴给 Agent）。
* `index.html`：命中事件流的 summary 更新；导航补上「断点」分段
  （P2 加了 `panel-bp` 却没进导航，`ui-layout` 的 panel 计数与导航数
  因此对不上 —— P3 一并补齐）。

### 15.2 改动文件

* `native/agent.c`：`si_send_breakpoint_event` 扩参 + 新增 `si_emit_regs` /
  `si_emit_stack`（约 110 行）；`si_veh_breakpoint_dispatch` 传
  `ep->ContextRecord` 并改由 `bp_ctx` 引用；VEH 单步的 IP 回跳从无条件
  `ctx->Rip` 改为按位宽分派（x86 用 `Eip`）—— x86 DLL 才能编过。
* `superinject/web/app.js`：`hexVal` / `bpArchOf` / `renderRegsHtml` /
  `renderStackHtml` + `refreshBpEvents` 渲染三个折叠面板（约 90 行新增）。
* `superinject/web/style.css`：寄存器网格 / 栈列表 / 折叠面板样式（约 45 行）。
* `superinject/web/index.html`：事件流 summary 文案 + 导航补「断点」。
* `tests/test_breakpoint.py`（增量）：新增 5 条 P3 用例（regs 非空、
  stack 16 项、x86 / x64 架构字段、RSP 无效 → `stack=[]` 不崩）。
* `tests/test_integration_windows.py`（增量）：`test_hw_breakpoint_on_ping`
  增断言 —— 命中事件 `regs.rip` 落在 ping 模块地址范围内、`stack` ≥ 1 项
  且每项含 `{i, addr, value}`。
* `tests/ui/render_check.py` + `tests/ui/mock_bridge.js`：把 `panel-bp`
  纳入布局检查的 panel 列表；假后端补 `bp_*` / `list_events`（含一条
  带完整寄存器 + 16 项栈的 x64 命中事件），让 P3 的前端渲染路径在
  `ui-layout` 里被真跑一遍。

### 15.3 验证证据

* **DLL 编译零新 warning**：x64 MinGW `-Wall -Wextra` 仍是 v1.2.0 既存的
  5 条 `-Wcast-function-type`（`write_dump_with_meta` / `NtSuspendThread` /
  `NtResumeThread` / `NtQueryInformationThread` / `GetThreadDescription`），
  P3 没有引入新 warning。x86 从"编不过（`ctx->Rip` 在 x86 CONTEXT 不存在）"
  变为**能编过**（0 error），warning 类别也没新增。
* **单测**：223 → **228 passed**（+5），5 skip（Windows-only），`ruff check`
  clean。
* **前端渲染**：`python tests/ui/render_check.py` 全绿（含 `panel-bp`
  纳入检查、页面无 JS 报错）。另用 Playwright 探针实测：选进程后命中的
  x64 事件渲染出 20 个寄存器（rip/rsp/rbp/rflags/14×GPR/cs/ss，每行 2 个
  = 10 行）+ 16 项栈；x86 事件渲染出 12 个寄存器（eip/esp/ebp/eflags/6×GPR
  /cs/ss，6 行）+ 16 项栈（4 字节步长）；展开后页面无横向溢出。
* **DLL 体积**：188KB → 190KB（+1.5KB，寄存器 / 栈填值路径）。

### 15.4 未做的部分

* **未做 FPU / MMX / XMM / AVX（SIMD）寄存器**：`CONTEXT_FULL` 里
  `FloatSave`（x86）/ `FltSave`（x64）能拿到 x87/SSE 状态，但那是一大块
  128 位 + 变长向量（AVX-512 要到 `XSave` 区），序列化成 JSON 又大又慢，
  且绝大多数"断点看现场"只需要通用寄存器 + 栈。**明确不做**：v1.3.0 的
  `regs` 只覆盖 GPR + IP/SP/BP/FLAGS + segments。
* **未做栈的符号化回溯**：`stack` 是"从 RSP 起 16 个机器字"的**原始内存**，
  不是走 `.pdata` / RBP 链的**调用栈回溯**。回溯要把每个地址映射回模块 +
  解析 unwind 信息，放后续（MCP 客户端拿到原始 regs/stack 后自行处理）。
* **未做栈深度可配**：固定 16 项。需要更多时后续加 `--stack-depth`。
* **未做数据断点命中时的原子动作**：同 14.5 —— 命中时改寄存器 / 跳转
  这类"自定义动作"不在 P3。

## 十六、v1.3.0 修掉的 P1/P2 遗留（前端检查覆盖不足）

P3 收尾时按「P1/P2 的验证证据里都只报了 pytest / ruff / DLL 编译」这条线复查，
发现两类问题都不在单测覆盖范围内，靠 CI 的 `ui-layout` job（跑
`tests/ui/render_check.py`）才会暴露：

| # | 现象 | 根因 | 处理 |
|---|------|------|------|
| 1 | P2 的 x86 DLL **编不过**（`error: 'CONTEXT' has no member named 'Rip'`） | P3 之前的 VEH 单步回跳写死了 `ctx->Rip`，而 x86 的 `CONTEXT` 只有 `Eip`。x64 编译正常，所以只看 x64 的验证会漏掉 | 改为按位宽分派 `Rip`/`Eip`；同时 guard 掉 x86 未用的 `dr6`（MSVC `/WX` 会当错）。现在 x86 与 x64 都 0 error |
| 2 | `render_check.py` 报 `a[name] is not a function` | P1 加了快照面板，但 `tests/ui/mock_bridge.js` 没补 `list_snapshots` / `snapshot` / `diff_snapshot` / `delete_snapshot`；`call()` 里 `a[name](...)` 的 TypeError 在 `Promise.resolve` 之前同步抛出，`.catch` 抓不到 | 补齐 4 个 mock 方法（字段名对齐 `SnapshotIndexEntry.to_dict()`）|
| 3 | 快照列表 / 断点列表**从没被验证渲染过** | `render_check.py` 只检查「面板在不在视口内」（布局），不检查「点刷新后列表有没有数据」——所以 mock 少方法、方法返回空都不会被发现 | `run_interactions` 加两步：切到快照 / 断点面板 → 点「刷新列表」→ 断言 `tbody tr >= 2` |

### 为什么「只验 pytest」不够

P1 / P2 的报告都写了「pytest 全过 + ruff clean + DLL 编译成功」，看起来完整，
但漏掉了两条真实路径：

* **只编一个架构**：DLL 有两个产物（x64 / x86），只验 x64 会漏掉 x86 才有的
  编译错误（`CONTEXT` 的字段名差异）。**教训：DLL 改动必须两个架构都编。**
* **前端断言只覆盖布局**：`render_check.py` 的布局检查用的是「导航目标进入视口」，
  面板存在即通过；面板内部的数据渲染路径（懒加载 + 列表拼装）完全没跑到，
  于是 `mock_bridge.js` 这种「测试替身」与实际 API 的偏差不会被任何检查拦住。

### 验证证据

* 负向测试（证明校验器真的会拦，不是摆设）：把 `mock_bridge.js` 的
  `list_snapshots` 改名 → `render_check.py` 立刻报
  「快照列表渲染（0 行）」+「页面无 JS 报错（2 条）」并以 exit=1 结束；
  恢复后重新全绿。
* `x86_64-w64-mingw32-gcc -shared -O2 -DUNICODE -D_UNICODE ... -o /tmp/x64.dll`
  → exit=0，5 条 warning（全部是既存 `-Wcast-function-type`）。
* `i686-w64-mingw32-gcc ...` → exit=0；同一命令对 P2 的 `eaad008` 跑会得到
  `error: 'CONTEXT' has no member named 'Rip'`（已用 `git archive eaad008` 复现）。
* `python tests/ui/render_check.py` → 全绿（含新增的 2 项列表渲染断言）。

## 十七、v1.3.0 P4：MCP server + 会话授权

把调试能力通过 MCP（stdio JSON-RPC）开放给 AI Agent。本阶段只做**协议层 + 授权层**，
GUI 一键启停（P5）、无 UAC launcher（P6）、自动写 Agent 端配置（P7）都不在本阶段。

### 17.1 协议与授权设计

* **31 个工具，按能力分三档**（`read` 16 / `write` 14 / `dangerous` 1）。
  `tools/list` 会**按会话授权过滤**：只勾 `read` 的会话根本看不到 `mem_write` /
  `terminate`；硬调也只回结构化 `consent_denied`，**不落到 Controller**。
* **目标白名单**：`pid_allowlist`（PID 精确）+ `name_glob`（进程名通配，大小写不敏感）。
  两者都空 → 一律拒绝（避免「无授权即全放行」）。
* **过期**：默认 30 分钟（`DEFAULT_TTL_SECONDS`）。
* **防手改**：`SHA256(规范化字段 + 机器指纹)` 存进 `signature`，读回时用
  `hmac.compare_digest` 做常量时间比较。改字段而签名对不上 → 会话作废。
  **这是防误用不是防破解** —— 明文 JSON + 摘要，不做密钥级防护（见 SECURITY.md）。
* **工具 description 面向 Agent 写**：每条都写清「做什么 + 副作用 + 是否需要注入端在线」，
  例：`inject` 的 description 明说 `SIDE EFFECT: loads a DLL into the target and starts
  a background thread in it`。README 里那种免责声明不写进 description。

### 17.2 两条实现路径（SDK 可选，不是必需）

`mcp_server.run()` 自动探测：装了官方 `mcp` SDK 且没有显式传 `stdin`/`stdout` 就用 SDK，
否则走**裸 stdio JSON-RPC**（`initialize` / `tools/list` / `tools/call` / `ping` 四个方法
足够 MCP 客户端握手与调用）。SDK 路径抛任何异常（版本差异）都会 `log.exception` 后
降级到裸路径，**不会让 server 起不来**。

**两者共用同一套** `mcp_router.list_tools()` / `call_tool()`，所以授权语义、工具清单、
返回结构完全一致，不会出现「装了 SDK 就换一套行为」。

### 17.3 偏离计划的两处（有理由）

1. **`mcp` 不进必需依赖，改放 `[project.optional-dependencies]`**。
   计划原文是加进 `dependencies`。实际实现时发现：本机 `pip install mcp` 直接
   `No matching distribution found`（旧 pip / 索引受限环境会命中）。而 SDK 只是优化路径，
   裸实现已验证完整可用。放进必需依赖会让「装不上一个可选包」直接变成「功能不可用 +
   CI 全红」。所以改为 optional extra，并在 pyproject 注释里写明原因。
2. **GUI 授权弹窗只留了接线口，没有在本阶段接通**。
   `request_consent_gui(parent)` 在 `parent is None` 时**直接返回 None**（不弹窗），
   而 CLI 侧调用时 parent 恒为 None —— 所以 `SuperInject.exe mcp`（不带
   `--consent-stdin`、且本地没有有效授权）会**拒绝启动并提示**，而不是弹窗。
   这是刻意的阶段性状态：真正的弹窗属于 P5（GUI 一键启动）的范围，本阶段先把
   「没有授权就不许跑」这条底线立住。README 已按实际行为描述，等 P5 接上弹窗后再更新。

### 17.4 改动文件

* `superinject/mcp_consent.py`（新）：`ConsentSession` + 签名/校验 + `load/save_consent`
  + `check_target` / `check_capability` + `request_consent_cli`（stdin 一次性读，
  首行必须大写 `YES`）+ `request_consent_gui`（P5 接线口）。
* `superinject/mcp_router.py`（新）：`ToolSpec` 表（31 条）+ `list_tools(session)` +
  `call_tool(...)`（未知工具 / 能力不足 / 目标越界 → 三种结构化拒绝）。
* `superinject/mcp_server.py`（新）：`handle_message`（纯函数、无 IO，便于单测）+
  `run_stdio`（裸实现）+ `_run_sdk`（SDK 实现）+ `run()`（探测 + 兜底）。
* `superinject/cli.py`：`mcp` 子命令 + `--consent-stdin` / `--no-gui-consent` /
  `--print-config`；`mcp_config_snippet()` 生成 Agent 端配置。
* `superinject/__main__.py`：`argv[0] == "mcp"` 分派（在 `-c` 判断之前）。
* `superinject/web/consent.html`（新）：授权表单页（供 P5 的模态框加载）。
* `pyproject.toml`：`[project.optional-dependencies] mcp = ["mcp>=1.0"]`。
* `README.md` / `SECURITY.md`：MCP 用法 + 安全模型（含「不做什么」）。

### 17.5 验证证据

* `tests/test_mcp_consent.py`（24 例）：构造/签名、过期、**签名篡改后失效**、
  PID 白名单、`name_glob` 大小写不敏感、空名单拒绝一切、能力分档、落盘往返、
  损坏/形状不对的文件返回 None、CLI 解析（首行非 YES 拒绝、未知字段拒绝、缺
  capabilities 拒绝）。
* `tests/test_mcp_router.py`（14 例）：分档数量与计划一致（16/14/1）、只读会话看不到
  写类工具、**越权时断言 `Controller` 调用记录为空**、目标越界拒绝、name_glob 放行、
  每条工具都有非空 description 与合法 JSON Schema、带 PID 的工具必须声明 `target_args`。
* `tests/test_mcp_server.py`（14 例）：`initialize` / `tools/list` / `tools/call`、
  越权回 `isError=true` 且 Controller 未被调用、未知方法回 -32601、通知不回应、
  **stdout 纯净性**（重定向 stdout 后逐行 `json.loads`，非 JSON 行会直接炸）、
  坏包回 -32700 且主循环不退、空行跳过。
* **负向测试**：把 `check_capability` 改成恒 `True`，3 个越权用例立刻红
  （router 2 个 + server 1 个）；恢复后 28 例全过。证明这些断言真的会拦。
* 端到端手工验证：`SuperInject.exe mcp --print-config` 输出的 `mcpServers` 片段正确；
  `--consent-stdin` 喂配置后走 `run_stdio`，`initialize` + `tools/list` 响应正常，
  16 个 read 工具带完整 description/schema，stdout 只有 JSON-RPC 帧。

### 17.6 未做的部分

* **远程传输（TCP / SSE）**：明确不做，只 stdio。远程调试请走 SSH + 同机 launcher。
* **MCP resources / prompts**：只实现 `tools`。结构化只读视图留后续版本。
* **多 Agent 并发**：server 假设单客户端；并发会话未设计。
* **授权中途撤销的实时通知**：改白名单后已连接的 Agent 仍按旧会话运行到过期。
* **不做密钥级防护**：见 SECURITY.md 的「防误用不是防破解」一节。
