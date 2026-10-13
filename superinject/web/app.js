/* SuperInject 前端逻辑（纯原生 JS，pywebview 桥接 window.pywebview.api） */
(function () {
  "use strict";

  const $ = (s) => document.querySelector(s);
  // filter 现在是 {name, path} 两段独立过滤；不互相覆盖（与 controller API 对齐）
  const state = { procs: [], sel: new Set(), filter: { name: "", path: "" },
                  arch: "", onlyInjected: false };

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
    const q_name = (state.filter.name || "").toLowerCase();
    const q_path = (state.filter.path || "").toLowerCase();
    const rows = state.procs.filter((p) => {
      if (state.onlyInjected && !p.injected) return false;
      if (q_name && !String(p.name).toLowerCase().includes(q_name)
          && String(p.pid) !== q_name) return false;
      if (q_path && !String(p.path || "").toLowerCase().includes(q_path)) return false;
      return true;
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
    // 把 name / path / arch / only_injected 透传给 controller，源头过滤。
    // 留一份客户端 state.procs 缓存（用于搜索框微调 / 选中状态保留），
    // 但默认应当让 server 决定可见集合，否则 PID 跨进程枚举会失真。
    const list = await call("list_processes",
      state.filter.name, state.filter.path, state.arch, state.onlyInjected);
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
    // arch 取 GUI 上用户选的那一档：""=按目标自动；"x64" / "x86"=强制
    const arch = (state.arch || $("#arch-select") && $("#arch-select").value) || "";
    const res = await call("inject", okPids, arch);
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
    state.filter.name = e.target.value.trim();
    render();
  });
  $("#path-search").addEventListener("input", (e) => {
    state.filter.path = e.target.value.trim();
    render();
  });
  $("#arch-select").addEventListener("change", (e) => {
    state.arch = e.target.value;
    refresh();           // arch 走 controller 源头过滤，需重新拉
  });
  $("#only-injected").addEventListener("change", (e) => {
    state.onlyInjected = e.target.checked;
    refresh();
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

  // ---------------------------------------------------------- 内存快照 / diff

  // 模块作用域内：当前 PID + 缓存的快照列表
  state.snapshots = [];            // [{name, created_at, bytes, sha256, pages}, ...]
  state.snapSel = new Set();       // 选中的快照名（最多 2 个用于 diff）
  state.snapPid = null;             // 当前选中的 PID（用于刷新 / 删除）

  function fmtBytesShort(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(2) + " MB";
  }

  function shortSha(s) {
    s = String(s || "");
    if (s.length <= 12) return s;
    return s.slice(0, 6) + "…" + s.slice(-6);
  }

  function renderSnapshots() {
    const tb = $("#snap-table tbody");
    tb.innerHTML = "";
    if (!state.snapshots.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td colspan="6" class="empty">先在进程表选中目标 → 命名 → 新建</td>';
      tb.appendChild(tr);
    } else {
      state.snapshots.forEach((s) => {
        const tr = document.createElement("tr");
        if (state.snapSel.has(s.name)) tr.classList.add("sel");
        tr.innerHTML =
          `<td class="c-sel"><input type="checkbox" ${state.snapSel.has(s.name) ? "checked" : ""}/></td>` +
          `<td>${escapeHtml(s.name)}</td>` +
          `<td>${escapeHtml(s.created_at || "—")}</td>` +
          `<td>${s.pages || 0}</td>` +
          `<td>${fmtBytesShort(s.bytes)}</td>` +
          `<td><span class="sha" title="${escapeHtml(s.sha256 || "")}">${escapeHtml(shortSha(s.sha256))}</span></td>`;
        tr.querySelector("input").addEventListener("change", (e) => {
          if (e.target.checked) {
            if (state.snapSel.size >= 2) {
              // 切换：取消最早选的那个
              const first = state.snapSel.values().next().value;
              state.snapSel.delete(first);
            }
            state.snapSel.add(s.name);
          } else {
            state.snapSel.delete(s.name);
          }
          renderSnapshots();
          updateSnapActions();
        });
        tb.appendChild(tr);
      });
    }
    // A/B 下拉框同步
    const opts = state.snapshots
      .map((s) => `<option value="${escapeHtml(s.name)}">${escapeHtml(s.name)} · ${fmtBytesShort(s.bytes)}</option>`)
      .join("");
    const prev = { a: $("#snap-a").value, b: $("#snap-b").value };
    $("#snap-a").innerHTML = opts;
    $("#snap-b").innerHTML = opts;
    if (state.snapshots.find((s) => s.name === prev.a)) $("#snap-a").value = prev.a;
    if (state.snapshots.find((s) => s.name === prev.b)) $("#snap-b").value = prev.b;
    updateSnapActions();
  }

  function updateSnapActions() {
    const n = state.snapSel.size;
    $("#btn-snap-diff").disabled = n !== 2;
    $("#btn-snap-del").disabled = n === 0;
  }

  async function refreshSnapshots() {
    if (!state.snapPid) {
      log("请先在进程表里选中一个进程后再刷新快照列表", "warn");
      return;
    }
    const items = await call("list_snapshots", state.snapPid);
    state.snapshots = Array.isArray(items) ? items : [];
    state.snapSel = new Set();
    renderSnapshots();
  }

  async function takeSnapshot() {
    if (!state.snapPid) {
      log("请先在进程表里选中一个目标进程", "warn");
      return;
    }
    const name = ($("#snap-name").value || "").trim();
    if (!name) {
      log("请先填写快照名", "warn");
      return;
    }
    log(`拍快照 pid=${state.snapPid} name=${name}…`);
    const r = await call("snapshot", state.snapPid, name, []);
    if (r && r.ok) {
      log(`快照已落盘 ${r.path} (${r.count} 页 / ${fmtBytesShort(r.bytes)})`, "ok");
      $("#snap-name").value = "";
      await refreshSnapshots();
    } else {
      log("拍快照失败: " + (r && r.error || "未知错误"), "err");
    }
  }

  async function diffSnapshots() {
    if (state.snapSel.size !== 2) return;
    const [a, b] = Array.from(state.snapSel);
    if (!state.snapPid) return;
    log(`diff ${a} vs ${b}…`);
    const r = await call("diff_snapshot", state.snapPid, a, b, 0);
    if (!r || !r.ok) {
      log("diff 失败: " + (r && r.error || "未知错误"), "err");
      return;
    }
    const summary = document.createElement("div");
    summary.className = "summary";
    const chg = (r.changed || []).length;
    const only = (r.only_in_a || []).length;
    summary.innerHTML =
      `<b>${escapeHtml(a)}</b> vs <b>${escapeHtml(b)}</b>：` +
      `changed <b>${chg}</b>，仅 A 有 <b>${only}</b>，` +
      `未变 <b>${r.unchanged_count || 0}</b>`;
    const result = $("#snap-diff-result");
    result.innerHTML = "";
    result.appendChild(summary);
    (r.changed || []).forEach((c) => {
      const row = document.createElement("div");
      row.className = "snap-page";
      row.innerHTML =
        `<div class="addr">0x${Number(c.addr).toString(16).padStart(8, "0")}<br/>${c.size}B</div>` +
        `<div class="col diff"><div class="head">old  sha <b>${shortSha(c.old_sha)}</b></div>${formatHex(c.old_bytes)}</div>` +
        `<div class="col diff"><div class="head">new  sha <b>${shortSha(c.new_sha)}</b></div>${formatHex(c.new_bytes)}</div>`;
      result.appendChild(row);
    });
    log(`diff 完成：${chg} changed, ${only} only_in_a, ${r.unchanged_count} unchanged`, "ok");
  }

  async function deleteSnapshots() {
    if (state.snapSel.size === 0 || !state.snapPid) return;
    const names = Array.from(state.snapSel);
    if (!await confirmBox("删除快照", `即将从 pid=${state.snapPid} 删除 ${names.length} 个快照：${names.join(", ")}`)) return;
    for (const n of names) {
      await call("delete_snapshot", state.snapPid, n);
    }
    log(`已删除 ${names.length} 个快照`);
    await refreshSnapshots();
  }

  // 把 head64 这 128 字符 hex 拆成 16 字节一行做小规模 hexdump。
  function formatHex(hex) {
    hex = String(hex || "");
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
      const b = hex.slice(i, i + 2);
      if (b.length === 2) bytes.push(b);
    }
    if (!bytes.length) return '<span class="muted">—</span>';
    let row = "";
    for (let i = 0; i < bytes.length; i += 16) {
      row += bytes.slice(i, i + 16).join(" ") + "\n";
    }
    return `<pre style="margin:0;font-family:inherit;white-space:pre-wrap">${escapeHtml(row.trimEnd())}</pre>`;
  }

  $("#btn-snap-refresh").addEventListener("click", refreshSnapshots);
  $("#btn-snap-new").addEventListener("click", takeSnapshot);
  $("#btn-snap-diff").addEventListener("click", diffSnapshots);
  $("#btn-snap-del").addEventListener("click", deleteSnapshots);

  // 选定进程（注入/已注入）时自动同步 PID
  let lastRefreshPid = null;
  setInterval(() => {
    if (state.snapPid !== lastRefreshPid) {
      lastRefreshPid = state.snapPid;
      if (state.snapPid) refreshSnapshots();
    }
  }, 500);
  // 简单桥接：选中第一个进程时把 PID 同步到快照面板
  const origUpdateCounts = updateCounts;
  updateCounts = function () {
    origUpdateCounts();
    state.snapPid = selected()[0] || null;
  };

  // ---------------------------------------------------------- 硬件断点（v1.3.0 P2）
  //
  // 视图：
  //   - 顶部：装载表单（target / type / size / tid）
  //   - 列表：当前 PID 的所有 bp，命中数随事件实时刷新
  //   - 折叠：命中事件流（点开查看，"复制最新 payload" 给 Agent 看）
  //
  // GUI ↔ Controller 一致："module!symbol+0x42" 自动经 symbols 层解析，
  // 与 bp_set / bp_remove / bp_list / bp_clear 四个 RPC 一一对应。
  state.bps = [];            // [{addr, type, len, kind, tid, hit_count, slot}, ...]
  state.bpPid = null;
  state.bpEvents = [];       // 最近命中事件

  function shortAddr(a) {
    return "0x" + Number(a).toString(16).padStart(8, "0");
  }

  // ---- P3：断点命中事件的寄存器 / 栈渲染（折叠面板）--------------------
  //
  // 架构判断与 DLL 侧一致：有 rip 即 x64、有 eip 即 x86；两者都缺则不显示
  // 寄存器面板（stack 字段为 [] 时同理不显示栈面板）。
  function hexVal(v) {
    if (v === undefined || v === null) return "0x0";
    try {
      return "0x" + BigInt(v).toString(16).toUpperCase();
    } catch (_) {
      const n = Number(v);
      return Number.isFinite(n) ? "0x" + n.toString(16).toUpperCase() : String(v);
    }
  }

  function bpArchOf(regs) {
    if (!regs || typeof regs !== "object") return "";
    if (Object.prototype.hasOwnProperty.call(regs, "rip")) return "x64";
    if (Object.prototype.hasOwnProperty.call(regs, "eip")) return "x86";
    return "";
  }

  // 展示顺序：IP / SP / BP / FLAGS 在前，再 GPR，最后 segments。x64 14 个
  // GPR；x86 6 个。每行 2 个寄存器 + 值。
  const BP_REG_ORDER = {
    x64: ["rip", "rsp", "rbp", "rflags",
          "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "cs", "ss"],
    x86: ["eip", "esp", "ebp", "eflags",
          "eax", "ebx", "ecx", "edx", "esi", "edi",
          "cs", "ss"],
  };

  function renderRegsHtml(regs) {
    const arch = bpArchOf(regs);
    if (!arch) return "";
    const order = BP_REG_ORDER[arch];
    const rows = [];
    for (let i = 0; i < order.length; i += 2) {
      const cells = [];
      for (let j = 0; j < 2; j++) {
        const name = order[i + j];
        if (!name) { cells.push('<span class="rg-cell muted-cell"></span>'); continue; }
        const has = Object.prototype.hasOwnProperty.call(regs, name);
        const val = has ? hexVal(regs[name]) : "—";
        cells.push(`<span class="rg-cell"><span class="rg-name">${escapeHtml(name)}</span>` +
                   `<span class="rg-val">${escapeHtml(val)}</span></span>`);
      }
      rows.push(`<div class="rg-row">${cells.join("")}</div>`);
    }
    return rows.join("");
  }

  function renderStackHtml(stack) {
    const arr = Array.isArray(stack) ? stack.slice(0, 16) : [];
    if (!arr.length) return "";
    return arr.map((it) => {
      const addr = hexVal(it && it.addr !== undefined ? it.addr : 0);
      const val = hexVal(it && it.value !== undefined ? it.value : 0);
      return `<div class="st-row"><span class="st-addr">${escapeHtml(addr)}</span>` +
             `<span class="st-val">${escapeHtml(val)}</span></div>`;
    }).join("");
  }

  function renderBps() {
    const tb = $("#bp-table tbody");
    tb.innerHTML = "";
    if (!state.bps.length) {
      const tr = document.createElement("tr");
      tr.innerHTML = '<td colspan="7" class="empty">先在进程表选中目标 → 输入地址/符号 → 装载</td>';
      tb.appendChild(tr);
    } else {
      state.bps.forEach((bp) => {
        const tr = document.createElement("tr");
        tr.innerHTML =
          `<td>${shortAddr(bp.addr)}</td>` +
          `<td>${escapeHtml(bp.type || "")}</td>` +
          `<td>${bp.len || 1}</td>` +
          `<td>${escapeHtml(bp.kind || (bp.slot >= 0 ? "hw" : "veh"))}</td>` +
          `<td>${bp.tid || 0}</td>` +
          `<td><b>${bp.hit_count || 0}</b></td>` +
          `<td><button class="warn small" data-addr="${bp.addr}" data-tid="${bp.tid || 0}">移除</button></td>`;
        tb.appendChild(tr);
      });
      tb.querySelectorAll("button[data-addr]").forEach((btn) => {
        btn.addEventListener("click", () => removeBpByAddr(
          Number(btn.dataset.addr), Number(btn.dataset.tid),
        ));
      });
    }
    $("#btn-bp-clear").disabled = state.bps.length === 0;
  }

  async function refreshBps() {
    if (!state.bpPid) {
      log("请先在进程表里选中一个进程后再刷新断点列表", "warn");
      return;
    }
    const r = await call("bp_list", state.bpPid);
    if (r && r.ok) {
      state.bps = Array.isArray(r.bps) ? r.bps : [];
      renderBps();
      log(`断点列表：hw ${r.hw_slots_used}/${r.hw_slots_total}，veh ${r.veh_slots_used}/${r.veh_slots_total}`, "ok");
    } else {
      log("bp_list 失败: " + (r && r.error || "未知错误"), "err");
    }
  }

  async function setBpFromForm() {
    if (!state.bpPid) {
      log("请先在进程表里选中一个目标进程", "warn");
      return;
    }
    const target = ($("#bp-target").value || "").trim();
    if (!target) {
      log("请先输入地址 / 模块符号", "warn");
      return;
    }
    const bp_type = $("#bp-type").value || "exec";
    const size = parseInt($("#bp-size").value || "1", 10);
    const tid = parseInt($("#bp-tid").value || "0", 10);
    log(`装载断点 pid=${state.bpPid} ${target} type=${bp_type} size=${size} tid=${tid}…`);
    const r = await call("bp_set", state.bpPid, target, tid, bp_type, size);
    if (r && r.ok) {
      log(`断点装载：${shortAddr(r.address)} slot=${r.slot} kind=${r.kind} ` +
          (r.resolved_symbol ? `(sym ${r.resolved_module}!${r.resolved_symbol})` : ""),
          "ok");
      $("#bp-target").value = "";
      await refreshBps();
    } else {
      log("bp_set 失败: " + (r && r.error || "未知错误"), "err");
    }
  }

  async function removeBpByAddr(addr, tid) {
    if (!state.bpPid) return;
    // 直接传数字字面量；GUI 不再经过符号解析层（断点已经按 addr 唯一定位）。
    const target = "0x" + Number(addr).toString(16);
    log(`移除断点 ${target} tid=${tid}…`);
    const r = await call("bp_remove", state.bpPid, target, tid);
    if (r && r.ok) {
      log(`已移除 (hw ${r.removed_hw}, veh ${r.removed_veh})`, "ok");
      await refreshBps();
    } else {
      log("bp_remove 失败: " + (r && r.error || "未知错误"), "err");
    }
  }

  async function clearAllBps() {
    if (!state.bpPid) return;
    if (!await confirmBox("移除所有断点", `即将清空 pid=${state.bpPid} 的所有断点。`)) return;
    const r = await call("bp_clear", state.bpPid);
    if (r && r.ok) {
      log(`已清空（hw ${r.cleared_hw}, veh ${r.cleared_veh}）`, "ok");
      await refreshBps();
    } else {
      log("bp_clear 失败: " + (r && r.error || "未知错误"), "err");
    }
  }

  async function refreshBpEvents() {
    if (!state.bpPid) return;
    const items = await call("list_events", state.bpPid, "breakpoint");
    const arr = Array.isArray(items) ? items : [];
    state.bpEvents = arr.slice(-20).reverse();   // 最新在上
    const box = $("#bp-events");
    if (!box) return;
    box.innerHTML = "";
    if (!state.bpEvents.length) {
      box.innerHTML = '<div class="muted pad">尚无命中事件</div>';
      $("#btn-bp-copy").disabled = true;
      return;
    }
    state.bpEvents.forEach((e, idx) => {
      const row = document.createElement("div");
      row.className = "bp-evt";
      const t = new Date(e.ts_ms || Date.now()).toLocaleTimeString();
      const arch = bpArchOf(e.regs);
      row.innerHTML =
        `<div class="meta">#${state.bpEvents.length - idx} ${t} · ` +
        `addr <b>${shortAddr(e.addr)}</b> · tid <b>${e.tid || 0}</b> · ` +
        `hit <b>${e.hit_count || 0}</b> · kind <b>${e.kind || (e.slot >= 0 ? "hw" : "veh")}</b>` +
        (arch ? ` · arch <b>${escapeHtml(arch)}</b>` : "") + `</div>`;

      // P3：寄存器折叠面板（有 rip/eip 才显示）
      const regsHtml = renderRegsHtml(e.regs);
      if (regsHtml) {
        const d = document.createElement("details");
        d.className = "bp-evt-regs";
        d.innerHTML = `<summary>展开寄存器（${escapeHtml(arch)}）</summary>` +
                      `<div class="rg-grid">${regsHtml}</div>`;
        row.appendChild(d);
      }

      // P3：栈折叠面板（前 16 项，addr  value 两列）
      const stackHtml = renderStackHtml(e.stack);
      if (stackHtml) {
        const n = Math.min(Array.isArray(e.stack) ? e.stack.length : 0, 16);
        const d = document.createElement("details");
        d.className = "bp-evt-stack";
        d.innerHTML = `<summary>展开栈（前 ${n} 项）</summary>` +
                      `<div class="st-list">${stackHtml}</div>`;
        row.appendChild(d);
      }

      // 原始 payload（折叠，方便整条贴给 Agent）
      const wrap = document.createElement("details");
      wrap.className = "bp-evt-raw";
      wrap.innerHTML = `<summary>原始 payload</summary>`;
      const pre = document.createElement("pre");
      pre.className = "bp-evt-payload";
      pre.textContent = JSON.stringify(e, null, 2);
      wrap.appendChild(pre);
      row.appendChild(wrap);
      box.appendChild(row);
    });
    $("#btn-bp-copy").disabled = !state.bpEvents.length;
  }

  async function copyLatestBpPayload() {
    if (!state.bpEvents.length) return;
    const text = JSON.stringify(state.bpEvents[0], null, 2);
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        // 降级走陈旧 Clipboard API
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand && document.execCommand("copy");
        document.body.removeChild(ta);
      }
      log("已复制最新一条命中 payload 到剪贴板", "ok");
    } catch (e) {
      log("复制失败: " + e, "err");
    }
  }

  function clearBpEvents() {
    if (!state.bpPid) return;
    // 取完清空（事件列表）
    call("list_events", state.bpPid, "breakpoint", true).then(() => {
      state.bpEvents = [];
      const box = $("#bp-events");
      if (box) box.innerHTML = '<div class="muted pad">已清空</div>';
      $("#btn-bp-copy").disabled = true;
    });
  }

  // 绑定 button + 表单 + 选中 PID 时联动
  (function initBpPanel() {
    $("#btn-bp-refresh").addEventListener("click", refreshBps);
    $("#btn-bp-set").addEventListener("click", setBpFromForm);
    $("#btn-bp-clear").addEventListener("click", clearAllBps);
    $("#bp-target").addEventListener("keydown", (e) => {
      if (e.key === "Enter") setBpFromForm();
    });
    $("#btn-bp-copy").addEventListener("click", copyLatestBpPayload);
    $("#btn-bp-clear-events").addEventListener("click", clearBpEvents);
  })();

  // 进程选择变化 → 同步刷新断点列表 + 命中事件。
  // 不是另开一条事件总线，而是直接订阅 checkbox 的 change 事件 / 行
  // click：因为不同区域（事件 / 断点 / patch_list 等）都依赖选中 PID，
  // 用统一的 state.sel.add / delete 钩子更稳。
  (function hookBpSelection() {
    const selTable = $("#proc-table");
    if (!selTable) return;
    const sync = () => {
      const arr = Array.from(state.sel);
      const pid = arr.length ? arr[0] : null;
      if (pid && pid !== state.bpPid) {
        state.bpPid = pid;
        refreshBps();
        refreshBpEvents();
      } else if (!pid) {
        state.bpPid = null;
      }
    };
    selTable.addEventListener("change", (e) => {
      if (e.target.tagName === "INPUT") sync();
    });
    selTable.addEventListener("click", (e) => {
      // 行级 click 在 tr.addEventListener 里跑；DOM 冒泡到 table 后再补一刀
      if (e.target.closest("tr")) sync();
    });
  })();

  // 与上面 hook 重复，避免一边 hook 不到；保留 null 占位以便将来扩展。
  const _origOnSel = window.__onProcSelForBp__;
  document.addEventListener("supinject:selection-changed", (ev) => {
    const pid = ev && ev.detail && ev.detail.pid;
    if (pid) {
      state.bpPid = pid;
      refreshBps();
      refreshBpEvents();
    }
  });

  // ---------------------------------------------------------- MCP 授权（v1.3.0 P5）
  //
  // GUI 的职责是「授权 + 复制配置」，**不是**在本进程里起 server —— 真正的
  // MCP server 由外部 Agent 以 stdio 拉起 `SuperInject.exe mcp`，读取同一份
  // consent 文件复用授权。状态全部来自后端 mcp_status()。
  state.mcp = { consent: { state: "none" }, server: {} };
  state.mcpTargets = [];

  const MCP_STATE_META = {
    none: ["未授权", "off"],
    valid: ["已授权", "on"],
    expired: ["已过期", "warn"],
  };

  function fmtLocalTime(ts) {
    const n = Number(ts);
    if (!n) return "—";
    try { return new Date(n * 1000).toLocaleString(); } catch (_) { return "—"; }
  }

  async function refreshMcpStatus() {
    const st = await call("mcp_status");
    if (!st || !st.consent) return;
    state.mcp = st;
    renderMcpStatus();
  }

  function renderMcpStatus() {
    const c = (state.mcp && state.mcp.consent) || { state: "none" };
    const meta = MCP_STATE_META[c.state] || MCP_STATE_META.none;
    const badge = $("#badge-mcp");
    if (badge) {
      badge.textContent = "MCP " + meta[0];
      badge.className = "badge " +
        (c.state === "valid" ? "ok" : c.state === "expired" ? "warn" : "");
    }
    const dot = $("#mcp-state-dot");
    if (dot) dot.className = "mcp-dot " + meta[1];
    const txt = $("#mcp-state-text");
    if (txt) txt.textContent = meta[0];
    const detail = $("#mcp-detail");
    if (detail) {
      if (c.state === "valid") {
        detail.innerHTML =
          "白名单：<b>" + escapeHtml(c.summary || "") + "</b><br>" +
          "能力：<b>" + escapeHtml((c.capabilities || []).join(", ") || "-") + "</b> · " +
          "到期：<b>" + escapeHtml(fmtLocalTime(c.expires_at)) + "</b>";
      } else if (c.state === "expired") {
        detail.innerHTML = "上次授权已于 <b>" + escapeHtml(fmtLocalTime(c.expires_at)) +
          "</b> 过期（白名单：" + escapeHtml(c.summary || "-") + "）。需要重新授权。";
      } else {
        detail.textContent =
          "尚未授权任何目标。点「授权…」勾选 PID 白名单 / 进程名通配与能力分档。";
      }
    }
    const revoke = $("#btn-mcp-revoke");
    if (revoke) revoke.disabled = c.state !== "valid";

    // v1.3.0 P6：命名管道服务状态（真实反映后端 PipeBridgeServer.running）
    const srv = (state.mcp && state.mcp.server) || {};
    const running = !!srv.running;
    const pipeName = $("#mcp-pipe-name");
    if (pipeName) pipeName.textContent = srv.pipe || "\\\\.\\pipe\\SuperInjectMCP";
    const pipeState = $("#mcp-pipe-state");
    if (pipeState) {
      pipeState.textContent = running ? "运行中" : "未启用";
      pipeState.className = running ? "ok" : "";
    }
    const startBtn = $("#btn-mcp-start");
    if (startBtn) startBtn.disabled = !c.valid || running;
    const stopBtn = $("#btn-mcp-stop");
    if (stopBtn) stopBtn.disabled = !running;
  }

  async function startMcpService() {
    const startBtn = $("#btn-mcp-start");
    if (startBtn) startBtn.disabled = true;
    let res;
    try {
      res = await call("start_mcp_service");
    } catch (e) {
      log("启用 MCP 服务失败：" + e, "err");
      return refreshMcpStatus();
    }
    if (res && res.ok) {
      log("MCP 服务已启用（命名管道 " + (res.pipe || "") +
          "）；Agent 可用 SuperInject.exe mcp-launcher 无 UAC 连接", "ok");
    } else {
      log("启用 MCP 服务失败：" + ((res && res.error) || "未知错误"), "err");
    }
    await refreshMcpStatus();
  }

  async function stopMcpService() {
    const res = await call("stop_mcp_service");
    if (res && res.ok) {
      log("MCP 服务已停止", "ok");
    } else {
      log("停止 MCP 服务失败：" + ((res && res.error) || "未知错误"), "err");
    }
    await refreshMcpStatus();
  }

  function collectConsentForm() {
    const caps = ["read"];
    if ($("#consent-cap-write").checked) caps.push("write");
    if ($("#consent-cap-dangerous").checked) caps.push("dangerous");
    return {
      pids: $("#consent-pids").value,
      names: $("#consent-names").value,
      capabilities: caps,
      ttl_seconds: parseInt($("#consent-ttl").value, 10) || 1800,
    };
  }

  function setConsentStatus(msg, cls) {
    const el = $("#consent-status");
    el.textContent = msg || "";
    el.className = "consent-status" + (cls ? " " + cls : "");
  }

  function openConsentModal() {
    const c = (state.mcp && state.mcp.consent) || {};
    if (c.pid_allowlist && c.pid_allowlist.length) {
      $("#consent-pids").value = c.pid_allowlist.join(",");
    }
    if (c.name_glob && c.name_glob.length) {
      $("#consent-names").value = c.name_glob.join(",");
    }
    const caps = c.capabilities || [];
    $("#consent-cap-write").checked = caps.indexOf("write") >= 0;
    $("#consent-cap-dangerous").checked = caps.indexOf("dangerous") >= 0;
    setConsentStatus("");
    $("#consent-modal").classList.remove("hidden");
  }

  function closeConsentModal() {
    $("#consent-modal").classList.add("hidden");
  }

  async function submitConsent() {
    const payload = collectConsentForm();
    if (!payload.capabilities.length) {
      return setConsentStatus("至少勾选一项能力分档", "err");
    }
    if (!payload.pids.trim() && !payload.names.trim()) {
      return setConsentStatus("PID 白名单与进程名通配不能同时为空", "err");
    }
    setConsentStatus("提交中…");
    let res;
    try {
      res = await call("submit_consent", payload);
    } catch (e) {
      return setConsentStatus("授权失败：" + e, "err");
    }
    if (res && res.ok) {
      setConsentStatus("已授权：" + (res.summary || ""), "ok");
      log("MCP 已授权：" + (res.summary || ""), "ok");
      await refreshMcpStatus();
      setTimeout(closeConsentModal, 400);
    } else {
      setConsentStatus("授权失败：" + ((res && res.error) || "未知错误"), "err");
    }
  }

  async function revokeConsent() {
    if (!await confirmBox("撤销 MCP 授权",
      "将删除本地授权文件；已连接的 Agent 会按旧会话运行到过期。确定？")) return;
    const res = await call("revoke_consent");
    if (res && res.ok) {
      log("MCP 授权已撤销", "ok");
      await refreshMcpStatus();
    } else {
      log("撤销失败: " + ((res && res.error) || "未知错误"), "err");
    }
  }

  async function copyMcpConfig() {
    const text = await call("mcp_config_snippet");
    if (typeof text !== "string" || !text) {
      log("获取 MCP 配置失败", "err");
      return;
    }
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        const ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand && document.execCommand("copy");
        document.body.removeChild(ta);
      }
      log("已复制 Agent 配置（贴进 claude_desktop_config.json / mcp.json）", "ok");
    } catch (e) {
      log("复制失败: " + e, "err");
    }
  }

  // ---- v1.3.0 P7：一键写入 Agent 端配置（合并 + 备份 + 用户确认，不静默） ----
  async function refreshAgentTargets() {
    let list = [];
    try {
      list = await call("list_agent_targets");
    } catch (e) {
      list = [];
    }
    state.mcpTargets = Array.isArray(list) ? list : [];
    renderAgentTargets();
  }

  function renderAgentTargets() {
    const box = $("#mcp-targets");
    if (!box) return;
    const list = state.mcpTargets || [];
    if (!list.length) {
      box.innerHTML = '<div class="muted">未发现可写入的 Agent 配置目标。</div>';
      return;
    }
    box.innerHTML = list.map((t) => {
      const tag = t.exists ? '<span class="mcp-target-tag on">已存在</span>'
                           : '<span class="mcp-target-tag off">未创建</span>';
      return '<div class="mcp-target" data-target-id="' + escapeHtml(t.id) + '">' +
        '<div class="mcp-target-info">' +
          '<div class="mcp-target-name">' + escapeHtml(t.label) + ' ' + tag + '</div>' +
          '<div class="mcp-target-path" title="' + escapeHtml(t.path || "") + '">' +
            escapeHtml(t.path || "") + '</div>' +
        '</div>' +
        '<button class="ghost mcp-target-write" data-target-id="' +
          escapeHtml(t.id) + '">写入</button>' +
      '</div>';
    }).join("");
    box.querySelectorAll(".mcp-target-write").forEach((btn) => {
      btn.addEventListener("click", () => writeAgentConfig(btn.dataset.targetId));
    });
  }

  async function writeAgentConfig(targetId) {
    const t = (state.mcpTargets || []).find((x) => x.id === targetId) || {};
    const label = t.label || targetId;
    const ok = await confirmBox("写入 Agent 配置",
      "将把 SuperInject 的 mcpServers 条目写入：\n" + (t.path || targetId) +
      "\n\n写入前会先备份原文件（<文件名>.bak-<时间戳>），并且只修改 " +
      "mcpServers.superinject 这一个键，其他内容（含别人的 MCP 条目）原样保留。\n\n确定写入？");
    if (!ok) return;
    let res;
    try {
      res = await call("write_agent_config", targetId, "launcher");
    } catch (e) {
      log("写入 " + label + " 配置失败：" + e, "err");
      return;
    }
    if (res && res.ok) {
      log("已写入 " + label + " 配置（" + (res.action || "") + "）：" + (res.path || "") +
          (res.backup ? "；原文件已备份到 " + res.backup : ""), "ok");
    } else {
      log("写入 " + label + " 配置失败：" + ((res && res.error) || "未知错误"), "err");
    }
    await refreshAgentTargets();
  }

  (function initMcpPanel() {
    const open = $("#btn-mcp-consent");
    if (open) open.addEventListener("click", openConsentModal);
    const revoke = $("#btn-mcp-revoke");
    if (revoke) revoke.addEventListener("click", revokeConsent);
    const startBtn = $("#btn-mcp-start");
    if (startBtn) startBtn.addEventListener("click", startMcpService);
    const stopBtn = $("#btn-mcp-stop");
    if (stopBtn) stopBtn.addEventListener("click", stopMcpService);
    const copy = $("#btn-mcp-copy");
    if (copy) copy.addEventListener("click", copyMcpConfig);
    const cancel = $("#consent-cancel");
    if (cancel) cancel.addEventListener("click", closeConsentModal);
    const submit = $("#consent-submit");
    if (submit) submit.addEventListener("click", submitConsent);
    const badge = $("#badge-mcp");
    if (badge) badge.addEventListener("click", () => {
      const target = document.getElementById("panel-mcp");
      if (target) target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    const seg = document.querySelector('button.nav-seg[data-target="panel-mcp"]');
    if (seg) seg.addEventListener("click", () => {
      refreshMcpStatus();
      refreshAgentTargets();
    });
    refreshAgentTargets();
  })();

  // 供后端 mcp_consent._open_consent_modal（parent.evaluate_js）调用。
  window.SIConsent = {
    open: openConsentModal,
    close: closeConsentModal,
    submit: submitConsent,
  };

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
    refreshMcpStatus();
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
