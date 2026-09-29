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
    reveal: () => true,
    verify_dll: () => ({ ok: true, message: "DLL 校验通过",
                         path: `C:${BS}Tools${BS}SuperInjectAgent.dll` }),
    check_update: () => ({ ok: true, has_newer: false, latest: "1.0.2" }),
    apply_update: () => ({ ok: true }),
  };

  window.pywebview = { api };
  // 让 app.js 的 pywebviewready 分支也能走通（有些版本会等这个事件）
  window.__SI_MOCK__ = true;
  setTimeout(() => window.dispatchEvent(new Event("pywebviewready")), 0);
})();
