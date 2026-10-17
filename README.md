# SuperInject

> **⚠️ For developer debugging only. Do not misuse. You are solely liable for any consequences.**

**SuperInject** is a **Windows-only**, DLL-injection-based fast debugger. It collapses the chain "find process → inject → read memory → write memory → freeze → unload / terminate" into a single PyWebView GUI, so you can locate a bug in minutes instead of bouncing between command-line scripts.

![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)
![Python](https://img.shields.io/badge/Python-3.9%2B-yellow.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

[中文文档](./README.zh-CN.md) · [Releases](https://github.com/Mofan2020/SuperInject/releases)

> **Use boundaries (please read)**
> Use this tool **only** on processes you own or have **explicit written authorization** to debug.
> Do not use it on unauthorized third-party software, to bypass software protection mechanisms, or to infringe on others' rights.
> In most jurisdictions, injecting code into a third-party process without authorization may violate law and software license agreements; any consequences are the user's responsibility. The author and contributors disclaim all liability.

## Capabilities

| Capability | Description |
| --- | --- |
| Startup self-check 1: Privileges | Identifies the current privilege (SYSTEM / Admin / User); User → UAC to Admin → Admin self-elevates to **SYSTEM** (clone SYSTEM token + `CreateProcessAsUserW`); on failure, falls back to Admin and logs the reason. |
| Startup self-check 2: DLL integrity | Computes the runtime SHA-256 of `SuperInjectAgent.dll` and compares it to the in-binary copy; mismatch (or missing) → **auto-replace**. |
| Process picker | Full process list, searchable by name / PID / **process path**, multi-select, paste PIDs manually. |
| CLI mode | `-c -y <command>`: process list / inject / freeze / memory R-W / unload / terminate / DLL self-check; plain text by default, add `--json` for JSON. |
| x86 process injection | Both x64 + x86 DLLs are embedded; auto-picks by target architecture. |
| Pre-injection check | For each PID: still alive? architecture match? (with cross-arch auto-fallback when x86 DLL is available) not a protected system process? not already injected? |
| Injection | `CreateRemoteThread + LoadLibraryW`, batch injection, **confirmed by an actually-established control channel**, not just a non-zero return. |
| Hot reload | Re-injecting an already-injected process: automatically "unload old DLL → wait for channel teardown → inject new DLL". |
| Batch control | The injected DLL opens a **loopback TCP reverse connection** to the controller (with a one-shot token); the controller can talk to any number of injected processes in parallel. |
| Unload | The injected DLL calls `FreeLibraryAndExitThread` on itself; clean unload with channel teardown. |
| Terminate | The injected DLL calls `ExitProcess` inside the target — "process terminates itself". |
| Freeze | `NtSuspendProcess` suspends every thread; the target becomes **completely unresponsive**; resume verifies real thread state. |
| Memory search | Hex pattern scan with `4D 5A ?? ??` wildcards; cross-process batch search supported. |
| Memory view / write | Hex R/W at any address; code/read-only pages are temporarily flipped writable and restored (code patching supported). |
| Memory snapshot / diff | 4 KB page SHA-256 + first 64-byte snapshot, written to `%LOCALAPPDATA%/SuperInject/snapshots/<pid>/<name>.json`. Diff any two snapshots: page-level SHA locates changed pages, then `head64` shows a two-column hex diff — finds a 1-byte change without flooding you with MB of false positives. |
| Hardware breakpoints (P2/P3 v1.3.0) | Per-thread hardware breakpoints on DR0-DR3 (4 slots), DR7 controls R/W / LEN / L enable; when slots run out, falls back to VEH emulation (`INT3 0xCC` patch + single-step rewrite). Hit pushes `event:breakpoint` with `addr / pid / tid / slot / kind / fault_addr / hit_count / regs / stack`. **Full register state on hit** (x64: RIP/RSP/RBP/RFLAGS/RAX-RDI/R8-R15/CS/SS; x86: EIP/ESP/EBP/EFLAGS/EAX-EDI/CS/SS) **+ first 16 stack entries** (each `{i, addr, value}`; when RSP/ESP pages are unreadable the stack is empty, the event still fires). |
| MCP server (P4/P5/P6/P7 v1.3.0) | `SuperInject.exe mcp` starts a stdio JSON-RPC server exposing 31 debug capabilities (`read` 16 / `write` 14 / `dangerous` 1) under session-based consent: at startup a dialog (or `--consent-stdin` for one-shot config) confirms PID whitelist / process-name wildcards / capability tiers; unauthorized tools are absent from `tools/list`, and a hard call only returns `consent_denied` without ever reaching the controller. Default zero-dep raw stdio; if the official `mcp` SDK is installed, the SDK is preferred and falls back gracefully on failure. `--print-config` emits the Claude Desktop / Cursor `mcpServers` snippet (UAC-free launcher; `--direct` for the non-launcher version). **Built-in GUI consent panel** (P5): MCP status badge in the top bar (Unauthorized / Authorized / Expired) + "Authorize…" modal (PID whitelist / name wildcards / 3 capability tiers / validity) + "Revoke" + "Copy Agent config"; consent is persisted on disk for external agents to reuse. **UAC-free launcher** (P6): clicking "Enable MCP server" in the GUI causes the (already-elevated) main process to listen on named pipe `\\.\pipe\SuperInjectMCP`; the agent side uses `SuperInject.exe mcp-launcher` (which does **not require admin/SYSTEM**) to forward stdio JSON-RPC through the pipe to the main process — **no UAC prompt at all**. **One-click Agent config write** (P7): the MCP panel lists Claude Desktop and Cursor targets (name + config path + whether it already exists); clicking "Write" first shows a confirmation dialog, then performs a **merge** write (only the `mcpServers.superinject` key, all other top-level keys and other agents' `mcpServers` entries preserved verbatim), backs up via `copy2` to `<name>.bak-<timestamp>` first, writes atomically (temp file + `os.replace`); missing file is created, identical content returns `unchanged` (no write, no backup), malformed JSON is rejected **without touching the original**; **only happens after the user explicitly confirms**. |
| Process resource viewer | Extracts and **in-line previews** images / audio / video in target-process memory: ① PE resources (RT_BITMAP / RT_ICON / RT_CURSOR have file headers reconstructed into BMP / ICO / CUR) ② memory-mapped files (anything the process has mmap'd — images, audio, video — exported as-is). |
| Crash dump | DLL installs `SetUnhandledExceptionFilter` + `AddVectoredExceptionHandler` in `DllMain`; on ACCESS_VIOLATION / STACK_OVERFLOW / ILLEGAL_INSTRUCTION / DIVIDE_BY_ZERO / PRIV_INSTRUCTION / GUARD_PAGE / INVALID_HANDLE in the target, writes `%TEMP%\SuperInject\<pid>\dump-<tick>.dmp` and a same-name `.json` metadata sidecar; controller scans the directory at `on_detach` and pushes `event:crash` for new files into the event queue, consumable by both CLI and frontend. |
| Event stream | DLL / controller both push `type=event:*` frames (crash dumps, patch landed, etc.) — these don't participate in id matching and are designed for "notify but don't expect a reply". CLI `events` subcommand supports `--follow` for continuous polling. |
| Module exports + symbol resolution | `info` shows the first N exports per module; self-written PE parser, no dbghelp dependency; `exports` queries one module by base / name; `superinject.symbols` does `module+0x123` / `module!symbol+0x42` reverse lookups on the controller side. |
| Thread-level freeze | `threads` lists all threads of the target (tid / state / WaitReason / current SuspendCount / thread name via GetThreadDescription); `thread_suspend` / `thread_resume` per thread; `NtSuspendThread` + `NtQueryInformationThread(ThreadBasicInformation)` reads SuspendCount. |
| Code patch (trampoline) | `patch_inject` writes a 5-byte `E9 rel32` at the target address to jump to a freshly-allocated RWX trampoline; the shellcode ends with `E9 rel32` back to original+5; `patch_list` enumerates every patch (original bytes hex / trampoline base / version); `patch_revert` restores one, `patch_clear` restores all; cap 32 per process. |
| Auto-update | Background check of GitHub Releases (pre-releases included); prompts to download and install on a new version. |
| UI | Single-page, **fully scrollable**, six functional zones sized to the viewport; follows system appearance (light / dark) with a macOS-style aesthetic. |
| Single-file distribution | The packaged output is **one file — `SuperInject.exe`** (no `_internal` folder); the DLL and frontend assets are embedded. |

---

## How It Works

```
┌──────────────── SuperInject.exe (Python / PyWebView) ────────────────┐
│                                                                      │
│  Self-check 1 (priv → UAC → SYSTEM elevate) → Self-check 2 (DLL SHA,  │
│  auto-replace) → GUI launches                                        │
│                                                                      │
│  Controller ──► pre-check → CreateRemoteThread + LoadLibraryW         │
│      │                                                               │
│      │  Writes rendezvous file %TEMP%\SuperInject\port-<PID>.txt     │
│      ▼                                                               │
│ AgentServer  ◄════ loopback TCP 127.0.0.1 (4-byte length + JSON)     │
│      │                                       ══════  Agent          │
│      │  Export dir %TEMP%\SuperInject\<pid>\ → 127.0.0.1 read-only   │
│      ▼                                                               │
│  <img>/<video>/<audio> preview (supports Range, scrubbable)          │
└──────────────────────────────────┬───────────────────────────────────┘
                                   │ inject point
                 ┌─────────────────▼──────────────────┐
                 │ SuperInjectAgent.dll (in target)    │
                 │  · ping / info / mem_regions         │
                 │  · mem_search / mem_read / mem_write  │
                 │  · resources (PE + memory-mapped)     │
                 │  · terminate / unload                 │
                 └─────────────────────────────────────┘
```

Key design decisions:

- **Reverse control channel.** The injected DLL reads the rendezvous file and *initiates* the loopback connection, so a single injection supports **batch, ad-hoc, repeated** control of the target without re-injecting every time.
- **Freeze is on the controller side** (`NtSuspendProcess`). Self-suspending from inside the process is pointless — it would just sleep the DLL's only worker thread, freezing neither the target nor ever waking back up. While frozen, the target is fully unresponsive and so is its DLL; that is expected.
- **Injection success = channel established.** A non-zero return from `LoadLibraryW` only proves the module landed in the target. SuperInject keeps waiting for the injected DLL to connect to the control channel; if it doesn't, the tool reports failure (and distinguishes "module residue" cases).
- **Loopback TCP, not named pipe.** The controller listens on `127.0.0.1` only (not exposed), and writes "port + one-shot random token" to `%TEMP%\SuperInject\port-<target-PID>.txt`; the injected DLL must echo the token in its first frame, or the connection is dropped. An earlier named-pipe version deadlock-tested at "controller writes + DLL blocks reading" and wedged both ends for minutes — the switch to sockets eliminated it.
- **DLL bytes are base64-embedded in the exe; SHA-256 is computed at runtime.** There are no hand-written hash constants anywhere in the source or config (a unit test guards this rule).
- **SYSTEM elevation stays in the current session.** Open `SeDebugPrivilege` → find a SYSTEM process in the **current session** (preferring `winlogon.exe`, which is not PPL-protected) → duplicate its token as a **primary token** → relaunch self with that token. The new process is SYSTEM but stays in your current desktop/session, so the GUI shows normally (scheduled-task-as-SYSTEM would land in session 0 with no visible UI). Candidates are limited to the same session, so `SeTcbPrivilege` is never needed.
- **Rendezvous file works across TEMP directories.** The injected DLL tries its own `%TEMP%\SuperInject\` first, and if that fails, scans every user's `%TEMP%\SuperInject\` read-only — because `GetTempPathW()` for SYSTEM services is typically `C:\Windows\Temp`, while the controller wrote to the launching user's TEMP. Read-only scan, no token writes to public paths.

---

## Install & Use

### Option 1: Download a Release

Download `SuperInject-win-x64.zip` from [Releases](https://github.com/Mofan2020/SuperInject/releases). Unzip to get a **single `SuperInject.exe`** (no `_internal` folder, no installer), double-click, accept the UAC prompt.

> Requirements: Windows 10/11 x64 + [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/) (preinstalled on Win11).
>
> The release zip contains **only `SuperInject.exe`**.
>
> On first run, `SuperInjectAgent.dll` is extracted next to the exe (Self-check 2 verifies its SHA-256 in real time); if the exe sits in a non-writable location (e.g. `Program Files`), the DLL falls back to `%LOCALAPPDATA%\SuperInject\`.

### Option 2: Run from Source

```bash
git clone https://github.com/Mofan2020/SuperInject.git
cd SuperInject
python -m pip install -r requirements.txt

# 1) Compile the DLL (MinGW-w64 cross-compile on macOS/Linux; MSVC preferred on Windows)
python build/build_native.py
# 2) Embed the DLL into the program
python build/make_payload.py
# 3) Run (auto-triggers UAC)
python run_superinject.py
```

### Usage

1. **Pick processes** — search by name or PID in the list, tick (multi-select supported), or paste PIDs.
2. **Inject** — click "Inject selected". Pre-checks run first (protected system processes, architecture mismatch, etc. are blocked), then inject and confirm the control channel is up.
3. **Control** — in the "Control (batch)" zone: freeze / unfreeze / view resources / unload / terminate.
4. **View resources** — "View process resources" exports images/audio/video from target memory to a temp directory and renders them inline (thumbnails / player; audio & video support scrubbing).
5. **Memory debugging** — search with a hex pattern like `4D 5A ?? ??`; select a result to view / write. Writing into a read-only page (PE header, code section) auto-flips page protection and restores it.

### CLI Arguments

```
SuperInject.exe                  Self-check → elevate to SYSTEM → GUI
SuperInject.exe --as-admin       Only elevate to Admin (not SYSTEM), for ordinary targets
SuperInject.exe --self-test      Headless end-to-end self-check
SuperInject.exe --help           Help

# CLI mode (added in v1.1.0): no window, scriptable
SuperInject.exe -c -y list                 # list processes
SuperInject.exe -c -y list --path "C:\Program Files\..."   # filter by path
SuperInject.exe -c -y list --name chrome   # filter by name
SuperInject.exe -c -y inject 1234          # inject (auto-pick DLL by target arch)
SuperInject.exe -c -y inject --pid 100 --pid 200 --arch x86
SuperInject.exe -c -y freeze 1234
SuperInject.exe -c -y mem-read 1234 0x401000 64
SuperInject.exe -c -y mem-search 1234 '4D 5A ?? ??'
SuperInject.exe -c -y snapshot 1234 --name before --region 0x401000 0x1000
SuperInject.exe -c -y diff 1234 --a before --b after --limit 32
SuperInject.exe -c -y bp-set 1234 iphlpapi!IcmpSendEcho2+0x10        # module!symbol+offset
SuperInject.exe -c -y bp-set 1234 0x401000 --tid 12345 --type exec    # per-thread HW DR slot
SuperInject.exe -c -y bp-list 1234
SuperInject.exe -c -y bp-remove 1234 0x401000
SuperInject.exe -c -y bp-clear 1234
SuperInject.exe -c -y unload 1234
SuperInject.exe -c -y terminate 1234
SuperInject.exe -c -y status
SuperInject.exe -c -y dll                  # DLL self-check
```

MCP server (for AI agents, stdio JSON-RPC):

```powershell
SuperInject.exe mcp                               # start server (reuses valid consent; otherwise requires consent)
SuperInject.exe mcp --print-config                # print the agent-side config snippet and exit
SuperInject.exe mcp --consent-stdin --no-gui-consent < consent.txt
```

- With no flag: if a **non-expired** consent session exists locally, reuse it; otherwise refuse to start and prompt — either authorize in the GUI, or supply one-shot consent via `--consent-stdin`. Consent can only be granted by a human, never by an agent.
- `consent.txt` format (first line must be uppercase `YES` — that line *is* the consent):

```
YES
pids=1234,5678
names=notepad*,mytool.exe
capabilities=read,write
```

- Three capability tiers: `read` (list / read memory / query breakpoints, etc.), `write` (write memory / patch / freeze / install breakpoints, etc.), `dangerous` (terminate process).
- Unlisted target processes are always rejected; both `pids` and `names` empty = reject everything.
- Default 30-minute expiry; re-authorize afterwards.
- `--print-config` outputs the snippet to paste into Claude Desktop's `claude_desktop_config.json` (or Cursor's `mcp.json`) so the agent can discover the server.

**GUI consent flow** (v1.3.0 P5/P6, recommended):

1. Open the GUI; the MCP badge in the top bar shows current consent state. Click "Authorize…" in the MCP section.
2. In the modal: tick capability tiers (`read` auto-ticked; `write` changes target state; `dangerous` = terminate), fill PID whitelist / process-name wildcards, choose validity, click "Authorize". The session is **persisted to disk** (only on success).
3. Click "Enable MCP server": the main process (already elevated) begins listening on named pipe `\\.\pipe\SuperInjectMCP`; the panel and badge show "Running".
4. Click "Copy Agent config" to copy the `mcpServers` snippet; paste it into the agent's config (default is the UAC-free `mcp-launcher` variant).
5. Or click "Write" next to a target under "One-click Agent config" to write the config file directly (Claude Desktop's `claude_desktop_config.json` / Cursor's `~/.cursor/mcp.json`): **a confirmation dialog appears first** stating "will back up the original file and only modify the `mcpServers.superinject` key"; after confirmation, a **merge** write happens and the backup path is echoed. **The write only happens after the user explicitly confirms** — there is no silent-on-startup write path.
6. The agent launches `SuperInject.exe mcp-launcher` itself: it does **not require admin/SYSTEM**, forwards stdio JSON-RPC through the named pipe to the elevated main process, **no UAC prompt at all**.

**P7 write safety boundaries**: only `mcpServers.superinject` is touched — other top-level keys and other agents' `mcpServers` entries are preserved; the original file is backed up via `copy2` to `<name>.bak-<timestamp>` (path echoed in log) before atomic write via temp file + `os.replace`; missing file is created (only when the user clicks that target's "Write" — never auto-creating dirs for uninstalled agents); identical content returns `unchanged` (no write, no backup); existing file with malformed JSON / non-object top level / non-object `mcpServers` is **rejected without touching the original**.

**Why `mcp-launcher` instead of `SuperInject.exe mcp` directly?** Running `mcp` directly needs to inject into target processes, which requires admin/SYSTEM and triggers UAC every time. `mcp-launcher` only forwards requests to the **already-elevated** GUI main process — it needs no privileges itself, so no UAC. The trade-off: you must first open the GUI and enable the MCP server; if the main process isn't running, the launcher prints "SuperInject main process is not running (please open the GUI and enable the MCP server first)" to stderr and exits non-zero.

> **The launcher and the main process must be the same Windows user.** Named pipes default to an ACL that allows only the creating user; cross-user access (e.g. main as admin, launcher as standard user) won't connect — fall back to direct `SuperInject.exe mcp` (which goes through UAC).
>
> The GUI's MCP section handles **consent** + **starting/stopping the named pipe service** + **copying config**. The service itself is a **named pipe** (not inline stdio — the GUI process has no stdin/stdout for stdio transport). Click "Stop" to stop, "Revoke" to delete the consent file.

To skip the launcher and let the agent elevate itself via `SuperInject.exe mcp`, generate the direct config snippet with `--print-config --direct`.

CLI mode:

- Plain text by default (agent-friendly); add `--json` for JSON.
- `-c` enters CLI (required); `-y` means "I accept the disclaimer" (required, otherwise it refuses to run).
- Both x64 + x86 DLLs are built. Injecting x86 targets auto-picks the x86 DLL — no manual `--arch` needed.
- Full subcommands and help: `-h` / `--help`.

### About SYSTEM Privilege

- **Defaults to SYSTEM.** Inject checks, memory R/W, and freeze all work on high-privilege processes (SYSTEM services, other users' processes); the UI top-right shows the real privilege (`Privilege SYSTEM ✓` / `Privilege Admin ✓` / `Privilege Not elevated ✗`).
- **Still works without SYSTEM.** If policy disallows it (no available SYSTEM token source, security software blocks token duplication), the program **falls back to Admin** and logs the reason — it does not hard-exit. Admin is enough for ordinary processes.
- **Don't want SYSTEM** — pass `--as-admin`.
- **Which high-privilege processes are injectable**: in SYSTEM mode, anything not kernel / not PPL can be attempted; `lsass.exe`, `csrss.exe`, `services.exe`, and other critical processes are **actively blocked** (injecting them crashes the system — not a capability gap, an intentional guardrail).

### Headless Self-Test (CI & Manual)

```powershell
SuperInject.exe --self-test            # full end-to-end self-check, report written next to exe
SuperInject.exe --self-test --report D:\report.json
SuperInject.exe --self-test --keep-target
```

Starts from the **packaged artifact itself**, uses the embedded DLL to inject into a real process, and verifies each step:
privilege self-check → DLL verify and SHA match → SYSTEM token duplication → **actually create a SYSTEM process and verify identity** → launch target → pre-check → inject and establish channel →
ping / info / mem_regions / memory search / memory R-W and restore → resource extraction → freeze and resume (with thread-state verification) → unload → re-inject → hot reload → self-terminate.

Exit 0 means all passed; the report is JSON (`self-test-report.json`).

---

## Project Layout

```
SuperInject/
├─ superinject/
│  ├─ __main__.py        Startup (privilege check → DLL check → GUI → update check) / CLI entry
│  ├─ gui.py             PyWebView bridge layer (APIs exposed to frontend JS)
│  ├─ controller.py      Injection check / inject / batch control / memory / resource orchestration
│  ├─ winapi.py          Win32/NT API ctypes wrappers (privileges, injection, suspend state, etc.)
│  ├─ ipc.py             Loopback TCP control channel + frame codec
│  ├─ fileserver.py      127.0.0.1 read-only preview server (Range support, for A/V playback)
│  ├─ media.py           Media type detection and preview entry assembly
│  ├─ resconv.py         Raw DIB → BMP / ICO / CUR (reconstruct file headers for PE resources)
│  ├─ dll_manager.py     Embedded DLL copy and SHA-256 self-check (Self-check 2)
│  ├─ elevate.py         Privilege self-check, UAC elevation and SYSTEM elevation strategy (Self-check 1)
│  ├─ system_token.py    SYSTEM token duplication and CreateProcessAsUserW relaunch (Windows only)
│  ├─ updater.py         GitHub Release update check and install
│  ├─ selftest.py        Headless end-to-end self-check (--self-test)
│  ├─ web/               Frontend (index.html / app.js / style.css)
│  └─ embedded/          DLL bytes generated at packaging time (base64)
├─ native/
│  ├─ agent.c            Injected DLL: pipe client + every capability
│  └─ superinject_json.c/.h  Zero-dep JSON implementation on the DLL side
├─ build/                Compile / embed / package scripts
├─ tests/                Unit tests (cross-platform) + Windows real-injection integration tests
│  └─ ui/render_check.py Headless render check for the frontend (Playwright + fake backend)
└─ .github/workflows/ci.yml  CI: compile DLL + test + package + artifact self-check + auto-release
```

---

## Development & Testing

```bash
python -m pip install -r requirements-dev.txt
python -m pytest tests -q --ignore=tests/test_integration_windows.py   # cross-platform unit tests
python -m ruff check superinject build tests run_superinject.py
python build/build_native.py       # local DLL build self-test (MinGW-w64 cross-compile on macOS/Linux;
                                   # releases are built by CI with MSVC, see ci.yml's native-msvc job)

# Frontend layout check (headless Chromium; install the browser once)
python -m pip install playwright && python -m playwright install chromium
python tests/ui/render_check.py --shots-dir /tmp/si-ui
```

Real-injection integration test on Windows (admin terminal):

```powershell
$env:SUPERINJECT_DLL_PATH = "native/build/SuperInjectAgent.dll"
python -m pytest tests/test_integration_windows.py -v
```

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs on every push / PR:

1. On windows runner, compile `SuperInjectAgent.dll` with **MSVC** (`/W4 /WX`) — this is the **only build line**, with a check that the product is a 64-bit PE DLL and that the **import table only references system DLLs** (no VCRUNTIME140/msvcp-style runtimes that users would need to install separately; otherwise injection fails).
2. Run unit tests + `compileall` + `ruff` on **Ubuntu + Windows** (Windows also runs `tests/test_system_token_windows.py`: actually duplicates a SYSTEM token, creates a SYSTEM process, and verifies the child identity).
3. Use **Playwright + Chromium** to render the frontend at three window sizes × light/dark themes, asserting "fully scrollable / no horizontal overflow / every functional zone fully visible", and click through the interactive paths.
4. On **windows-latest**, run **real-injection integration tests** (inject `ping.exe`, covering memory R/W including read-only pages, freeze and resume, resource extraction, unload, re-inject, self-terminate).
5. PyInstaller **single-file** packaging (`--onefile`), assert the product is only `SuperInject.exe`, the zip contains only that file, then compress to `SuperInject-win-x64.zip`.
6. Run `SuperInject.exe --self-test` **on the packaged artifact** to re-verify the whole chain against the release build.
7. Pushing a `v*` tag triggers an auto-release (attaches the zip asset; auto-update keys off it).

> Before making changes, read [`docs/notes.md`](docs/notes.md): it records the defects fixed in this version with root cause (control-channel directional deadlock, array-serialization infinite mutual recursion, re-injection race, `pid_alive` false-positive), architectural conventions, known boundaries, and "what was deliberately not done and why".

---

## FAQ

**Q: Injection failed. What now?**

- Read what "Pre-injection check" actually said. It tells you which case this is:
  process gone / architecture mismatch (x64 tool can't inject x86, and vice versa) / cannot open process (not elevated) / protected system process blocked (`lsass.exe`, `csrss.exe` — injecting them bluescreens).
- Some security software / anti-cheat hooks `CreateRemoteThread`; this tool provides no bypass for that.

**Q: "SuperInjectAgent.dll already exists but control channel not established"?**

Means the previous injection left a residual module in the target (e.g. controller was force-killed). External safe-unload is impossible here — restart the target and inject again.

**Q: Want to update the DLL and re-inject?**

Click "Inject selected" again on an already-injected process — it automatically unloads the old DLL and injects the new one.

**Q: Memory search is slow?
**

Full process-space scan is indeed slow; for known addresses, use "View / Edit" on that address range directly.

**Q: How do I resume a frozen process?**

The "Unfreeze" button, or just terminate it. While frozen, the target is completely unresponsive, including its injected DLL.

**Q: The UI says "Privilege Admin ✓" instead of SYSTEM?**

SYSTEM elevation failed; check the log for the reason (common: security software blocks token duplication, no usable SYSTEM process token). Functionality is still available, just can't debug SYSTEM-level targets.

**Q: Can I run as Admin only, not SYSTEM?**

Yes — pass `--as-admin` (e.g. add it to your shortcut).

**Q: Why does Task Manager show SuperInject's process name / user changed?**

Elevation to SYSTEM relaunches itself with the SYSTEM token and exits the original process; this is expected.

**Q: Why can't some extracted resource images be opened?**

Memory-mapped files are exported as the contents mapped into memory at that moment — if the program only mapped part of the file, that's what you get (the UI marks it as "truncated").

---

## Safety Notice (Restated)

- SuperInject is **for developer debugging only. Do not misuse. You are solely liable for any consequences**.
- Use it only on software/processes you developed or have written authorization to debug.
- Comply with local laws and the relevant software's license agreements.
- The author and contributors disclaim all liability for any misuse.

## License

[MIT](LICENSE) © 2026 Skyc8266