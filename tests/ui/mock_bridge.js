/* 前端渲染检查用的假后端（模拟 pywebview 的 js_api）。
 *
 * 用途：不启动 Windows、不启动 pywebview，也能在 Chromium 里把真实界面渲染出来，
 * 用来验证「整页能滚动、各功能区不溢出、内容都渲染出来」。CI 的 ui-layout job
 * 与本地排查都用它。
 *
 * 用法：在页面脚本执行之前注入（Playwright 用 add_init_script，
 * CDP 用 Page.addScriptToEvaluateOnNewDocument），app.js 启动时会直接用它。
 */
(function () {
  "use strict";

  const BS = String.fromCharCode(92);   // 反斜杠：避免模板串里被当转义
  const WIN = "C:" + BS + "Windows" + BS + "System32";

  const THUMB =
    "data:image/svg+xml;base64," +
    btoa(
      `<svg xmlns="http://www.w3.org/2000/svg" width="180" height="120">
         <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
           <stop offset="0" stop-color="#4aa8ff"/><stop offset="1" stop-color="#5e5ce6"/>
         </linearGradient></defs>
         <rect width="180" height="120" fill="url(#g)"/>
         <circle cx="60" cy="45" r="16" fill="#ffffff" opacity=".85"/>
         <path d="M0 120 L55 62 L92 96 L130 60 L180 104 L180 120 Z" fill="#ffffff" opacity=".35"/>
       </svg>`
    );

  // 200 个进程：足够长，用来验证「进程表内部滚动 + 整页仍然能往下滚」
  const PROCS = [];
  const NAMES = ["chrome.exe", "explorer.exe", "Code.exe", "notepad.exe",
                 "ping.exe", "cmd.exe", "python.exe", "WeChat.exe"];
  for (let i = 0; i < 200; i++) {
    PROCS.push({
      pid: 1000 + i * 7,
      name: NAMES[i % NAMES.length],
      path: `C:${BS}Program Files${BS}App${i % 7}${BS}bin${BS}${NAMES[i % NAMES.length]}`,
      mem_mb: (12 + (i % 40) * 3).toFixed(1),
      injected: i % 23 === 0,
      frozen: i % 37 === 0,
    });
  }

  function resources(pid) {
    const items = [];
    for (let i = 0; i < 6; i++) {
      const kind = i % 3 === 0 ? "image" : i % 3 === 1 ? "video" : "audio";
      items.push({
        kind, ext: kind === "image" ? "png" : kind === "video" ? "mp4" : "ogg",
        size: 20480 * (i + 1), source: i < 4 ? "resource" : "mapped",
        rtype: i < 4 ? "RT_BITMAP" : "", previewable: i !== 5,
        url: kind === "image" ? THUMB : "", truncated: false,
        origin: `${WIN}${BS}${pid}-${i}.${kind}`,
        path: `C:${BS}Temp${BS}SuperInject${BS}${pid}-${i}.${kind}`,
      });
    }
    // 形状必须与 controller.resources() 一致：条目里再套一层 resp
    // （前端读的是 r.resp.items / r.resp.dir）
    return { ok: true, pid, resp: { ok: true, dir: `C:${BS}Temp${BS}SuperInject`,
             items, resource_count: 4, mapped_count: 2 } };
  }

  // 一条 x64 断点命中事件：带完整寄存器 + 16 项栈快照，
  // 供 P3 的「展开寄存器 / 展开栈」面板真实渲染（render_check 会走到这段）。
  function bpEvents(pid) {
    const ip = 140698000 + 0x1234;     // mock ping.exe 基址 + 偏移
    const sp = 0x7FF0001000;
    const regs = {
      rip: ip, rsp: sp, rbp: sp + 0x80, rflags: 0x202,
      rax: 0x1, rbx: 0x2, rcx: 0x3, rdx: 0x4, rsi: 0x5, rdi: 0x6,
      r8: 0x8, r9: 0x9, r10: 0x10, r11: 0x11, r12: 0x12, r13: 0x13,
      r14: 0x14, r15: 0x15, cs: 0x33, ss: 0x2B,
    };
    const stack = Array.from({ length: 16 }, (_, i) => ({
      i, addr: sp + i * 8, value: 0xDEAD0000 + i,
    }));
    return [{
      pid, seq: 1, ts_ms: Date.now(), type: "event:breakpoint",
      addr: ip, tid: 4242, slot: -1, kind: "veh",
      fault_addr: ip + 1, hit_count: 3, bp_type: 0, bp_len: 1,
      regs, stack,
    }];
  }

  const api = {
    bootstrap: () => ({
      app: "SuperInject", version: "1.0.2",
      url: "https://github.com/Mofan2020/SuperInject",
      privilege: "system", is_admin: true, identity: "SYSTEM / SYSTEM",
      elevation: {
        ok: true, privilege: "system", system: true, degraded: false,
        message: "已以 SYSTEM 重新启动（CreateProcessAsUserW，令牌来源 winlogon.exe pid=780）",
      },
      arch: "x64", status: {},
      dll: { ok: true, action: "ok", path: `C:${BS}Tools${BS}SuperInjectAgent.dll`,
             embedded_sha: "9f2c".repeat(16), message: "DLL 校验通过" },
    }),
    list_processes: () => PROCS,
    preflight: (pids) => pids.map((pid) => ({ ok: true, pid, blocked: false,
                                              reason: "", warnings: [] })),
    inject: (pids) => pids.map((pid) => ({ ok: true, pid, attached: true,
                                           module: "SuperInjectAgent.dll" })),
    ping: (pids) => pids.map((pid) => ({ ok: true, pid, resp: { ok: true } })),
    info: (pids) => pids.map((pid) => ({ ok: true, pid, resp: { ok: true,
      modules: [{ name: "ping.exe", base: 140698000, size: 24576 },
                { name: "ntdll.dll", base: 140700000, size: 2048000 }] } })),
    freeze: (pids) => pids.map((pid) => ({ ok: true, pid, verified: true })),
    unfreeze: (pids) => pids.map((pid) => ({ ok: true, pid, verified: false })),
    unload: (pids) => pids.map((pid) => ({ ok: true, pid, detached: true })),
    terminate: (pids) => pids.map((pid) => ({ ok: true, pid })),
    resources: (pids) => pids.map((pid) => resources(pid)),
    mem_search: (pids) => pids.map((pid) => ({ ok: true, pid, resp: { ok: true,
      results: Array.from({ length: 12 }, (_, i) => ({
        address: 140698000 + i * 64, region: 140690000, size: "4 KB",
        type: "MEM_PRIVATE / PAGE_READWRITE" })) } })),
    mem_read: () => ({ ok: true, hex: "4d5a90000300000004000000ffff0000" }),
    mem_write: () => ({ ok: true, written: 4 }),
    mem_regions: () => ({ ok: true, regions: [] }),

    // ---- 内存快照（v1.3.0 P1）：让快照面板的渲染路径被走到 ----
    // 字段名对齐 snapshots.SnapshotIndexEntry.to_dict()：
    //   name / created_at(ISO8601) / bytes / sha256 / pages
    list_snapshots: (pid) => ([
      { name: "before", created_at: "2026-10-11T22:00:00", bytes: 4096,
        sha256: "ab".repeat(32), pages: 1 },
      { name: "after", created_at: "2026-10-11T22:10:00", bytes: 8192,
        sha256: "cd".repeat(32), pages: 2 },
    ]),
    snapshot: (pid, name, regions) => ({
      ok: true, pid, name: name || "snap", count: 1, bytes: 4096,
      sha256: "ab".repeat(32),
      pages: [{ addr: 140698000, size: 4096, sha: "ab".repeat(32),
                head64: "4d5a90" + "00".repeat(29) + "0a" }],
    }),
    diff_snapshot: (pid, name1, name2, limit) => ({
      ok: true, pid, a: name1, b: name2, unchanged_count: 0,
      changed: [{ addr: 140698000, old_sha: "ab".repeat(32),
                  new_sha: "cd".repeat(32),
                  old_bytes: "4d5a9000", new_bytes: "4d5a9001" }],
      only_in_a: [], only_in_b: [],
    }),
    delete_snapshot: (pid, name) => true,

    reveal: () => true,
    verify_dll: () => ({ ok: true, message: "DLL 校验通过",
                         path: `C:${BS}Tools${BS}SuperInjectAgent.dll` }),
    check_update: () => ({ ok: true, has_newer: false, latest: "1.0.2" }),
    apply_update: () => ({ ok: true }),

    // ---- 硬件断点（v1.3.0 P2/P3）：让断点面板 + 命中事件流的渲染路径被走到 ----
    bp_set: (pid, target, tid, bp_type, size) => ({
      ok: true, pid, address: 140698000, slot: -1, kind: "veh",
      type: bp_type || "exec", len: size || 1, resolved_symbol: null,
    }),
    bp_list: (pid) => ({
      ok: true, pid,
      bps: [
        { addr: 140698000, slot: -1, kind: "veh", tid: 0,
          type: "exec", len: 1, hit_count: 3 },
        { addr: 140699120, slot: 0, kind: "hw", tid: 4242,
          type: "write", len: 4, hit_count: 1 },
      ],
      hw_slots_used: 1, hw_slots_total: 4,
      veh_slots_used: 1, veh_slots_total: 32,
    }),
    bp_remove: (pid) => ({ ok: true, pid, address: 140698000,
                           removed_hw: 0, removed_veh: 1 }),
    bp_clear: (pid) => ({ ok: true, pid, cleared_hw: 1, cleared_veh: 1 }),
    list_events: (pid, name, clear) => (name === "breakpoint" ? bpEvents(pid) : []),

    // ---- MCP 授权（v1.3.0 P5）：让 MCP 面板状态渲染 + 模态框提交路径被走到 ----
    // 字段与 gui.Api.mcp_status() 对齐：consent.state ∈ none/valid/expired。
    mcp_status: () => ({
      consent: {
        state: "valid", valid: true,
        summary: "pids=1234,5678 names=notepad* capabilities=read,write",
        expires_at: Date.now() / 1000 + 1800, created_at: Date.now() / 1000,
        capabilities: ["read", "write"],
        pid_allowlist: [1234, 5678], name_glob: ["notepad*"],
      },
      server: { running: false, transport: "stdio" },
    }),
    submit_consent: (payload) => ({
      ok: true,
      summary: "pids=" + ((payload && payload.pids) || "-") +
               " capabilities=" + ((payload && payload.capabilities) || []).join(","),
      expires_at: Date.now() / 1000 + 1800,
      path: "C:" + BS + "Users" + BS + "test" + BS + "mcp_consent.json",
    }),
    revoke_consent: () => ({ ok: true, removed: true }),
    mcp_config_snippet: () => JSON.stringify({
      mcpServers: { superinject: { command: "SuperInject.exe", args: ["mcp"], env: {} } },
    }, null, 2),
  };

  window.pywebview = { api };
  // 让 app.js 的 pywebviewready 分支也能走通（有些版本会等这个事件）
  window.__SI_MOCK__ = true;
  setTimeout(() => window.dispatchEvent(new Event("pywebviewready")), 0);
})();
