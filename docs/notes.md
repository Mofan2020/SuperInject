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
