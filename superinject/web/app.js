/* SuperInject 前端逻辑（纯原生 JS，pywebview 桥接 window.pywebview.api） */
(function () {
  "use strict";

  const $ = (s) => document.querySelector(s);
  const state = { procs: [], sel: new Set(), filter: "", onlyInjected: false };

  function api() {
    return window.pywebview && window.pywebview.api;
  }
  function call(name, ...args) {
    const a = api();
    if (!a) return Promise.reject(new Error("后端未就绪"));
    return Promise.resolve(a[name](...args)).catch((e) => {
      log("调用 " + name + " 失败: " + e, "err");
      return [];
    });
  }

  function log(msg, cls) {
    const box = $("#log");
    const t = new Date().toLocaleTimeString();
    const div = document.createElement("div");
    if (cls) div.className = cls;
    div.textContent = `[${t}] ${msg}`;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  }

  function humanSize(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(2) + " MB";
  }

  // ---------------------------------------------------------- 进程表
  function render() {
    const tb = $("#proc-table tbody");
    tb.innerHTML = "";
    const q = state.filter.toLowerCase();
    const rows = state.procs.filter((p) => {
      if (state.onlyInjected && !p.injected) return false;
      if (!q) return true;
      return String(p.name).toLowerCase().includes(q) || String(p.pid) === q;
    });
    rows.forEach((p) => {
      const tr = document.createElement("tr");
      if (state.sel.has(p.pid)) tr.className = "sel";
      const flags = [];
      if (p.injected) flags.push('<span class="pill on">已注入</span>');
      if (p.frozen) flags.push('<span class="pill frozen">❄ 冻结</span>');
      tr.innerHTML = `
        <td class="c-sel"><input type="checkbox" ${state.sel.has(p.pid) ? "checked" : ""} /></td>
        <td>${p.pid}</td>
        <td>${escapeHtml(p.name)}</td>
        <td>${p.mem_mb}</td>
        <td>${flags.join(" ") || '<span class="pill">—</span>'}</td>
        <td class="path">${escapeHtml(p.path || "")}</td>`;
      tr.querySelector("input").addEventListener("change", (e) => {
        if (e.target.checked) state.sel.add(p.pid);
        else state.sel.delete(p.pid);
        render();
      });
      tr.addEventListener("click", (e) => {
        if (e.target.tagName === "INPUT") return;
        if (state.sel.has(p.pid)) state.sel.delete(p.pid);
        else state.sel.add(p.pid);
        render();
      });
      tb.appendChild(tr);
    });
    updateCounts();
  }

  function selected() {
    return Array.from(state.sel);
  }
  function updateCounts() {
    const n = selected().length;
    $("#btn-inject").textContent = `注入选中 (${n})`;
    $("#sel-count").textContent = `已选 ${n} 个进程`;
  }

  async function refresh() {
    log("正在获取进程列表…");
    const list = await call("list_processes");
    if (!Array.isArray(list)) return;
    state.procs = list.filter((p) => p.pid);
    const alive = new Set(state.procs.map((p) => p.pid));
    state.sel = new Set(Array.from(state.sel).filter((p) => alive.has(p)));
    render();
    log(`共 ${state.procs.length} 个进程`, "ok");
  }

  // ---------------------------------------------------------- 控制指令
  const ACTIONS = {
    ping: { method: "ping", title: "连通性检查" },
    info: { method: "info", title: "查看模块" },
    freeze: { method: "freeze", title: "冻结进程", confirm: "冻结后目标进程将完全无响应，确定？" },
    unfreeze: { method: "unfreeze", title: "解除冻结" },
    unload: { method: "unload", title: "卸载注入 DLL", confirm: "确定要卸载这些进程中的 SuperInject DLL 吗？" },
    terminate: { method: "terminate", title: "终止进程", confirm: "这会让目标进程自行 ExitProcess 结束，数据可能丢失！确定？" },
    resources: { method: "resources", title: "查看进程资源" },
  };

  document.querySelectorAll(".act").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const key = btn.dataset.act;
      const cfg = ACTIONS[key];
      const pids = selected();
      if (!pids.length) return log("请先选择至少一个进程", "warn");
      if (cfg.confirm) {
        const ok = await confirmBox(cfg.title, `${cfg.confirm}\n\n目标进程：${pids.join(", ")}`);
        if (!ok) return;
      }
      btn.disabled = true;
      log(`${cfg.title} → ${pids.length} 个进程…`);
      try {
        const res = await call(cfg.method, pids);
        summarize(cfg.title, res);
        if (key === "resources") renderResources(res);
        if (key === "freeze" || key === "unfreeze") reportSuspend(cfg.title, res);
        if (key === "unload" || key === "terminate") setTimeout(refresh, 600);
      } finally {
        btn.disabled = false;
      }
    });
  });

  function summarize(title, res) {
    if (!Array.isArray(res) || !res.length) return;
    const ok = res.filter((r) => r.ok).length;
    log(`${title}: 成功 ${ok}/${res.length}`, ok === res.length ? "ok" : "warn");
    res.forEach((r) => {
      const err = r.error || (r.resp && r.resp.error) || "";
      if (!r.ok) log(`  PID ${r.pid} 失败: ${err}`, "err");
    });
    if (title === "查看模块") res.forEach((r) => {
      const mods = (r.resp && r.resp.modules) || [];
      log(`  PID ${r.pid} 模块数 ${mods.length}`);
      mods.slice(0, 12).forEach((m) =>
        log(`    ${m.name}  base=0x${Number(m.base).toString(16)}  ${m.size}`));
    });
  }

  function reportSuspend(title, res) {
    (res || []).forEach((r) => {
      if (!r.ok) return;
      if (r.verified === true) log(`  PID ${r.pid} 已确认全部线程被挂起（无响应）`, "ok");
      else if (r.verified === false) log(`  PID ${r.pid} 已确认线程全部恢复运行`, "ok");
      else log(`  PID ${r.pid} 挂起状态无法核实（权限限制）`, "warn");
    });
  }

  // ---------------------------------------------------------- 资源预览
  function renderResources(res) {
    const grid = $("#res-grid");
    grid.innerHTML = "";
    let total = 0;
    let dir = "";
    (res || []).forEach((r) => {
      const items = (r.resp && r.resp.items) || [];
      dir = (r.resp && r.resp.dir) || dir;
      total += items.length;
      log(`PID ${r.pid} 提取 ${items.length} 个资源` +
        `（PE 资源 ${(r.resp && r.resp.resource_count) || 0} / ` +
        `内存映射 ${(r.resp && r.resp.mapped_count) || 0}）→ ${r.resp && r.resp.dir}`,
        items.length ? "ok" : "warn");
      if (!items.length) return;
      const head = document.createElement("div");
      head.className = "res-group";
      head.textContent = `PID ${r.pid}`;
      grid.appendChild(head);
      items.forEach((it) => grid.appendChild(resCard(r.pid, it)));
    });
    $("#res-summary").textContent = total ? `共 ${total} 个资源` : "没有找到可预览的图片/音频/视频";
  }

  function resCard(pid, it) {
    const card = document.createElement("div");
    card.className = "res-card";
    const media = document.createElement("div");
    media.className = "res-media";
    const url = it.previewable ? it.url : "";
    if (url && it.kind === "image") {
      const img = document.createElement("img");
      img.loading = "lazy";
      img.src = url;
      img.alt = it.ext;
      media.appendChild(img);
    } else if (url && it.kind === "video") {
      const v = document.createElement("video");
      v.src = url;
      v.controls = true;
      v.preload = "metadata";
      media.appendChild(v);
    } else if (url && it.kind === "audio") {
      const a = document.createElement("audio");
      a.src = url;
      a.controls = true;
      media.appendChild(a);
    } else {
      const none = document.createElement("div");
      none.className = "no-preview";
      none.textContent = it.kind === "other" ? "非媒体文件" : "无法预览（体积过大或格式不支持）";
      media.appendChild(none);
    }
    card.appendChild(media);

    const meta = document.createElement("div");
    meta.className = "res-meta";
    const source = it.source === "mapped" ? "内存映射" : "PE 资源";
    meta.innerHTML = `
      <div class="res-title">${it.ext.toUpperCase()} · ${humanSize(it.size)}${it.truncated ? " · 已截断" : ""}</div>
      <div class="res-sub">${source}${it.rtype ? " · 类型 " + it.rtype : ""}</div>
      <div class="res-path" title="${escapeHtml(it.origin || "")}">${escapeHtml(it.origin || it.path)}</div>`;
    const row = document.createElement("div");
    row.className = "row";
    const open = document.createElement("button");
    open.className = "ghost";
    open.textContent = "定位文件";
    open.addEventListener("click", () => call("reveal", it.path));
    row.appendChild(open);
    if (it.origin && it.origin !== it.path) {
      const src = document.createElement("button");
      src.className = "ghost";
      src.textContent = "定位来源";
      src.addEventListener("click", () => call("reveal", it.origin));
      row.appendChild(src);
    }
    meta.appendChild(row);
    card.appendChild(meta);
    return card;
  }

  $("#btn-reveal-all").addEventListener("click", () => {
    const first = $("#res-grid").querySelector(".res-path");
    if (first) call("reveal", first.getAttribute("title") || "");
    else log("还没有提取过资源", "warn");
  });

  // ---------------------------------------------------------- 内存
  $("#btn-search").addEventListener("click", async () => {
    const pids = selected();
    const pattern = $("#mem-pattern").value.trim();
    if (!pids.length) return log("请先选择要搜索内存的进程", "warn");
    if (!pattern) return log("请输入十六进制模式", "warn");
    const max = parseInt($("#mem-max").value, 10) || 128;
    log(`内存搜索 ${pattern} × ${pids.length} 个进程…`);
    const res = await call("mem_search", pids, pattern, max);
    const box = $("#mem-results");
    box.innerHTML = "";
    (res || []).forEach((r) => {
      const results = (r.resp && r.resp.results) || [];
      log(`PID ${r.pid} 命中 ${results.length} 处`, results.length ? "ok" : "warn");
      if (!results.length) return;
      const t = document.createElement("table");
      t.innerHTML = `<thead><tr><th>PID</th><th>地址</th><th>区域</th><th>保护</th><th></th></tr></thead><tbody>` +
        results.map((m) => `<tr>
            <td>${r.pid}</td>
            <td>0x${Number(m.address).toString(16)}</td>
            <td>0x${Number(m.region).toString(16)} (${m.size})</td>
            <td>${m.type}</td>
            <td><button class="ghost" data-pid="${r.pid}" data-addr="${m.address}">查看/修改</button></td>
          </tr>`).join("") + "</tbody>";
      box.appendChild(t);
    });
    box.querySelectorAll("button[data-addr]").forEach((b) =>
      b.addEventListener("click", () => {
        $("#ed-addr").value = "0x" + Number(b.dataset.addr).toString(16);
        $("#mem-editor").classList.remove("hidden");
      }));
  });

  $("#btn-read").addEventListener("click", async () => {
    const pid = selected()[0];
    if (!pid) return log("请先在进程表里选中一个目标进程", "warn");
    const resp = await call("mem_read", pid, $("#ed-addr").value,
      parseInt($("#ed-size").value, 10) || 64);
    $("#ed-msg").textContent = resp.ok ? "" : `读取失败: ${resp.error || ""}`;
    if (resp.hex) $("#ed-data").value = resp.hex.replace(/(..)/g, "$1 ").trim();
  });

  $("#btn-write").addEventListener("click", async () => {
    const pids = selected();
    if (!pids.length) return log("请先选择目标进程", "warn");
    const ok = await confirmBox("写入内存",
      `将把编辑框中的数据写入 ${pids.join(", ")} 的 ${$("#ed-addr").value}，确定？`);
    if (!ok) return;
    const addr = $("#ed-addr").value;
    const data = $("#ed-data").value;
    for (const pid of pids) {
      const resp = await call("mem_write", pid, addr, data);
      log(`PID ${pid} 写入 ${resp.ok ? "成功" + (resp.written ? ` (${resp.written} 字节)` : "") : "失败: " + (resp.error || "")}`,
        resp.ok ? "ok" : "err");
    }
  });

  // ---------------------------------------------------------- 注入
  $("#btn-inject").addEventListener("click", async () => {
    const pids = selected();
    if (!pids.length) return log("请先选择目标进程", "warn");

    log(`注入检查：${pids.length} 个进程…`);
    const checks = await call("preflight", pids);
    const list = Array.isArray(checks) ? checks : [];
    list.forEach((c) => {
      (c.warnings || []).forEach((w) => log(`  PID ${c.pid} 提醒: ${w}`, "warn"));
      if (c.blocked) log(`  PID ${c.pid} 无法注入: ${c.reason}`, "err");
    });
    const okPids = list.filter((c) => !c.blocked).map((c) => c.pid);
    if (!okPids.length) return log("没有可注入的进程", "err");
    log(`注入检查通过 ${okPids.length}/${pids.length}`, "ok");

    const ok = await confirmBox("注入确认",
      `即将向 ${okPids.length} 个进程注入 SuperInjectAgent.dll。\n\n` +
      `请确认这些是你自己拥有或已获授权调试的进程。`);
    if (!ok) return;

    log(`开始注入 ${okPids.join(", ")}…`);
    const res = await call("inject", okPids);
    let okCount = 0;
    (res || []).forEach((r) => {
      if (r.ok) {
        okCount++;
        log(`  PID ${r.pid} 注入成功并已建立控制通道 ${r.image || ""}`, "ok");
      } else {
        log(`  PID ${r.pid} 注入失败: ${r.error}`, "err");
      }
    });
    log(`注入完成 ${okCount}/${(res || []).length}`, okCount ? "ok" : "warn");
    setTimeout(refresh, 800);
  });

  $("#btn-verify").addEventListener("click", async () => {
    const rep = await call("verify_dll", true);
    log("DLL 校验: " + rep.message, rep.ok ? "ok" : "err");
    $("#badge-dll").textContent = rep.ok ? "DLL 已同步" : "DLL 校验失败";
    $("#badge-dll").className = "badge " + (rep.ok ? "ok" : "bad");
    $("#dll-path").textContent = rep.path || "";
  });

  // ---------------------------------------------------------- 其它交互
  $("#btn-refresh").addEventListener("click", refresh);
  $("#search").addEventListener("input", (e) => {
    state.filter = e.target.value.trim();
    render();
  });
  $("#only-injected").addEventListener("change", (e) => {
    state.onlyInjected = e.target.checked;
    render();
  });
  $("#sel-all").addEventListener("change", (e) => {
    if (e.target.checked) state.procs.forEach((p) => state.sel.add(p.pid));
    else state.sel.clear();
    render();
  });
  $("#btn-add-pids").addEventListener("click", () => {
    const raw = $("#manual-pids").value.split(/[,，\s]+/).filter(Boolean);
    let added = 0;
    raw.forEach((x) => {
      const pid = parseInt(x, 10);
      if (pid && !state.sel.has(pid)) {
        if (!state.procs.some((p) => p.pid === pid))
          state.procs.push({ pid, name: "(手工输入)", path: "", mem_mb: 0, injected: false });
        state.sel.add(pid);
        added++;
      }
    });
    $("#manual-pids").value = "";
    log(`已加入 ${added} 个 PID`);
    render();
  });
  $("#btn-clear").addEventListener("click", () => { $("#log").innerHTML = ""; });

  // ---------------------------------------------------------- 分区导航
  // 整页滚动后用一个分段控件在功能区之间跳转；滚动时自动高亮当前区。
  (function initNav() {
    const segs = Array.from(document.querySelectorAll(".nav-seg"));
    const panels = segs
      .map((s) => document.getElementById(s.dataset.target))
      .filter(Boolean);
    if (!panels.length) return;

    const mark = (id) =>
      segs.forEach((s) => s.classList.toggle("on", s.dataset.target === id));

    segs.forEach((s) =>
      s.addEventListener("click", () => {
        const target = document.getElementById(s.dataset.target);
        if (!target) return;
        mark(s.dataset.target);
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      })
    );

    let ticking = false;
    const sync = () => {
      ticking = false;
      const line = window.scrollY + 140;
      let current = panels[0];
      panels.forEach((p) => {
        if (p.offsetTop <= line) current = p;
      });
      mark(current.id);
    };
    window.addEventListener(
      "scroll",
      () => {
        if (!ticking) {
          ticking = true;
          window.requestAnimationFrame(sync);
        }
      },
      { passive: true }
    );
    mark(panels[0].id);
  })();

  // ---------------------------------------------------------- 弹窗
  function confirmBox(title, text) {
    return new Promise((resolve) => {
      $("#modal-title").textContent = title;
      $("#modal-text").textContent = text;
      $("#modal").classList.remove("hidden");
      const done = (v) => {
        $("#modal").classList.add("hidden");
        $("#modal-ok").removeEventListener("click", ok);
        $("#modal-cancel").removeEventListener("click", cancel);
        resolve(v);
      };
      const ok = () => done(true), cancel = () => done(false);
      $("#modal-ok").addEventListener("click", ok);
      $("#modal-cancel").addEventListener("click", cancel);
    });
  }

  function showUpdate(info) {
    $("#up-ver").textContent = info.version;
    $("#up-notes").textContent = (info.notes || "").slice(0, 800) || "无更新说明";
    $("#update-modal").classList.remove("hidden");
    $("#up-install").onclick = async () => {
      $("#up-install").disabled = true;
      await call("apply_update", info.asset);
    };
    $("#up-later").onclick = () => $("#update-modal").classList.add("hidden");
  }

  const PRIV_LABELS = { system: "SYSTEM ✓", admin: "管理员 ✓", user: "未提权 ✗" };

  // ---------------------------------------------------------- 后端事件
  window.SI = {
    onEvent(name, payload) {
      if (name === "state") {
        const inj = Object.keys(payload.injected || {}).map(String);
        const frozen = (payload.frozen || []).map((f) => String(f.pid));
        state.procs.forEach((p) => {
          p.injected = inj.includes(String(p.pid));
          p.frozen = frozen.includes(String(p.pid));
        });
        render();
      } else if (name === "dll") {
        log("DLL: " + payload.message, payload.ok ? "ok" : "err");
      } else if (name === "update-available") {
        log(`发现新版本 ${payload.version}`);
        showUpdate(payload);
      } else if (name === "update-progress") {
        $("#up-progress").classList.remove("hidden");
        const pct = payload.total ? Math.round((payload.done / payload.total) * 100) : 0;
        $("#up-progress").textContent = `${payload.stage} ${pct}%`;
      } else if (name === "update-error") {
        $("#up-progress").classList.remove("hidden");
        $("#up-progress").textContent = "更新失败: " + payload.message;
      }
    },
  };

  async function boot() {
    try {
      const info = await call("bootstrap");
      $("#badge-ver").textContent = "v" + info.version;
      $("#badge-arch").textContent = (info.arch || "?") + " / " + (info.app || "");
      const admin = $("#badge-admin");
      admin.textContent = "权限 " + (PRIV_LABELS[info.privilege] || "未知");
      admin.className = "badge " +
        (info.privilege === "user" ? "bad" : info.privilege === "system" ? "ok" : "warn");
      admin.title = (info.elevation && info.elevation.message) || "";
      const dll = $("#badge-dll");
      dll.textContent = info.dll.ok ? "DLL " + info.dll.action : "DLL 异常";
      dll.className = "badge " + (info.dll.ok ? "ok" : "bad");
      $("#dll-path").textContent = info.dll.path || "";
      log("启动自检: " + info.identity);
      const elev = info.elevation || {};
      if (elev.message) log(elev.message, elev.degraded ? "warn" : "ok");
      if (elev.degraded && elev.reason) log("SYSTEM 提权说明: " + elev.reason, "warn");
      log(info.dll.message || "");
      if (info.dll.embedded_sha) {
        log(`DLL SHA256（运行时计算）: ${String(info.dll.embedded_sha).slice(0, 32)}…`);
      }
    } catch (e) {
      log("初始化失败: " + e, "err");
    }
    refresh();
  }

  // 只启动一次：pywebview 有时既已注入 api，又会再派发 pywebviewready，
  // 早期版本会因此把自检与进程列表跑两遍（日志里出现两份）。
  let booted = false;
  function bootOnce() {
    if (booted) return;
    booted = true;
    boot();
  }
  window.addEventListener("pywebviewready", bootOnce);
  if (window.pywebview && window.pywebview.api) bootOnce();
})();
