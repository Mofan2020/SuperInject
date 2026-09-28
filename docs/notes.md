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
- **提权到不了 SYSTEM**：UAC 只能拿到管理员。真需要 SYSTEM 请自行用计划任务或
  PsExec 拉起（`elevate.py` 里有说明）。
- **GUI 无法在 CI 里自动验证**：Pywebview 需要桌面会话，CI 只验证到「打包成功 +
  `--self-test` 全链路」。GUI 的交互仍需人工过一遍。
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
