/* Ansible Lens UI. Talks to assets/worker.js, which runs lens/*.py in Pyodide. */
(() => {
  "use strict";
  const VERSION = "1.0.0";
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const TEXT_EXT = /\.(ya?ml|j2|jinja2?|json|ini|cfg|txt|conf|sh|py|toml|md|tpl|template)$/i;
  const STORE = "ansible-lens-state-v1";

  const state = { files: {}, current: null, entry: "", inventory: "", host: "", extra: "", facts: "" };
  let result = null;
  let lastDeleted = null;

  // ------------------------------------------------------------------ worker
  let worker, reqId = 0, pending = null, timer = null, engineReady = false;
  function startWorker() {
    worker = new Worker("assets/worker.js?v=" + VERSION);
    worker.onmessage = (e) => {
      const m = e.data;
      if (m.type === "status") setEngine(m.msg, "busy");
      else if (m.type === "ready") { engineReady = true; setEngine(`Jinja2 ${m.jinja} ready`, "ok"); schedule(0); }
      else if (m.type === "fatal") setEngine("Engine failed: " + m.error, "bad");
      else if (m.type === "result" && pending && m.id === pending) {
        clearTimeout(timer); pending = null; setEngine(engineReadyText(), "ok");
        if (m.error) return renderFatal(m.error);
        try { result = JSON.parse(m.out); } catch (err) { return renderFatal(String(err)); }
        if (result.fatal) return renderFatal(result.fatal + "\n\n" + (result.traceback || ""));
        render();
      }
    };
    worker.onerror = (e) => setEngine("Engine error: " + (e.message || "worker failed"), "bad");
  }
  const engineReadyText = () => "Ready";
  function setEngine(text, cls) {
    $("engineText").textContent = text;
    $("engine").className = "engine " + (cls || "");
  }
  function analyze() {
    if (!engineReady) return;
    const input = { files: state.files, entry: state.entry, inventory: state.inventory || null, host: state.host || null,
      extra_vars: state.extra, facts: state.facts };
    pending = ++reqId;
    setEngine("Analyzing…", "busy");
    worker.postMessage({ id: pending, input });
    clearTimeout(timer);
    timer = setTimeout(() => {
      // runaway template (huge range(), etc.): restart the engine
      worker.terminate(); pending = null; engineReady = false;
      renderFatal("Analysis took longer than 20 s and was stopped. Look for very large loops or ranges.");
      startWorker();
    }, 20000);
  }
  let debounce;
  function schedule(ms = 500) {
    clearTimeout(debounce);
    debounce = setTimeout(analyze, ms);
  }
  const auto = () => { if ($("chkAuto").checked) schedule(); };

  // ------------------------------------------------------------------ files
  const isPlaybook = (t) => /^\s*-\s+(name:.*\n\s+)?(hosts|import_playbook)\s*:/m.test(t);
  const isInventory = (p, t) => /(^|\/)(hosts|inventory)(\.(ya?ml|ini|cfg))?$/i.test(p) || /\.ini$/i.test(p) ||
    (/(^|\/)inventor(y|ies)\//i.test(p) && !/(group|host)_vars/.test(p)) || /^\s*all\s*:\s*\n\s+(hosts|children)\s*:/m.test(t);

  function guessDefaults() {
    const paths = Object.keys(state.files).sort();
    if (!state.files[state.entry]) {
      const pb = paths.filter((p) => isPlaybook(state.files[p]));
      const pref = pb.find((p) => /(^|\/)(site|playbook|main)\.ya?ml$/.test(p) && p.split("/").length === 1);
      state.entry = pref || pb.sort((a, b) => a.split("/").length - b.split("/").length)[0] || "";
    }
    if (state.inventory && !state.files[state.inventory]) state.inventory = "";
    if (!state.inventory) state.inventory = paths.find((p) => isInventory(p, state.files[p])) || "";
  }

  function setFiles(files, keepCurrent) {
    state.files = files;
    if (!keepCurrent || !state.files[state.current]) state.current = state.entry && files[state.entry] ? state.entry : Object.keys(files).sort()[0] || null;
    guessDefaults();
    if (!state.files[state.current]) state.current = state.entry || Object.keys(files)[0] || null;
    state.host = "";
    renderFiles(); openFile(state.current); renderSelects(); save(); schedule(0);
  }

  function renderFiles() {
    const paths = Object.keys(state.files).sort();
    const shown = new Set();
    let html = "";
    for (const p of paths) {
      const parts = p.split("/");
      const dir = parts.slice(0, -1);
      for (let i = 0; i < dir.length; i++) {
        const key = dir.slice(0, i + 1).join("/");
        if (shown.has(key)) continue;
        shown.add(key);
        html += `<button type="button" class="dir" style="padding-left:${10 + i * 12}px" tabindex="-1"><span>${esc(dir[i])}/</span></button>`;
      }
      const tag = p === state.entry ? '<span class="tag">play</span>' : p === state.inventory ? '<span class="tag">inv</span>' : "";
      html += `<button type="button" data-path="${esc(p)}" class="${p === state.current ? "on" : ""}" style="padding-left:${10 + dir.length * 12}px" title="${esc(p)}"><span>${esc(parts[parts.length - 1])}</span>${tag}</button>`;
    }
    $("files").innerHTML = html || '<p class="empty">No files</p>';
  }

  function openFile(p) {
    state.current = p;
    $("fileName").value = p || "";
    $("src").value = p ? state.files[p] : "";
    $("src").disabled = !p;
    updateGutter();
    renderFiles();
  }

  function updateGutter() {
    const n = $("src").value.split("\n").length;
    let s = "";
    for (let i = 1; i <= n; i++) s += i + "\n";
    $("gutter").textContent = s;
    $("gutter").scrollTop = $("src").scrollTop;
  }

  function gotoLine(path, line) {
    if (!state.files[path]) return;
    openFile(path);
    const ta = $("src"), lines = ta.value.split("\n");
    const l = Math.max(1, Math.min(line || 1, lines.length));
    const start = lines.slice(0, l - 1).join("\n").length + (l > 1 ? 1 : 0);
    ta.focus();
    ta.setSelectionRange(start, start + lines[l - 1].length);
    ta.scrollTop = Math.max(0, (l - 5) * 20);
    updateGutter();
  }

  async function readFileList(list, stripTop) {
    const files = {};
    for (const f of list) {
      let p = (f.webkitRelativePath || f.fullPath || f.name).replace(/^\/+/, "");
      if (/(^|\/)\.(git|venv|tox)\//.test(p) || /(^|\/)node_modules\//.test(p)) continue;
      const base = p.split("/").pop();
      if (!(TEXT_EXT.test(base) || !base.includes(".") || base === "hosts")) continue;
      if (f.size > 1024 * 1024) continue;
      files[p] = await f.text();
    }
    if (stripTop) {
      const tops = new Set(Object.keys(files).map((p) => p.split("/")[0]));
      if (tops.size === 1 && Object.keys(files).every((p) => p.includes("/"))) {
        const t = [...tops][0] + "/";
        for (const k of Object.keys(files)) { files[k.slice(t.length)] = files[k]; delete files[k]; }
      }
    }
    return files;
  }

  async function entriesToFiles(items) {
    const out = [];
    const walk = async (entry, path) => {
      if (entry.isFile) {
        const f = await new Promise((res, rej) => entry.file(res, rej));
        Object.defineProperty(f, "fullPath", { value: path + f.name });
        out.push(f);
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        let batch;
        do {
          batch = await new Promise((res, rej) => reader.readEntries(res, rej));
          for (const e of batch) await walk(e, path + entry.name + "/");
        } while (batch.length);
      }
    };
    for (const it of items) {
      const e = it.webkitGetAsEntry && it.webkitGetAsEntry();
      if (e) await walk(e, "");
    }
    return out;
  }

  // ------------------------------------------------------------------ selects
  function renderSelects() {
    const paths = Object.keys(state.files).sort();
    const pbs = paths.filter((p) => /\.ya?ml$/.test(p) && !/(group|host)_vars|\/(defaults|vars|meta|handlers)\//.test(p));
    $("selEntry").innerHTML = pbs.map((p) => `<option ${p === state.entry ? "selected" : ""}>${esc(p)}</option>`).join("") ||
      "<option value=''>(no playbook)</option>";
    $("selInv").innerHTML = `<option value="">(none: localhost)</option>` +
      paths.map((p) => `<option ${p === state.inventory ? "selected" : ""}>${esc(p)}</option>`).join("");
    renderHosts();
  }
  function renderHosts() {
    const hosts = result && result.meta ? result.meta.hosts : [];
    const cur = state.host || (result && result.meta && result.meta.host) || "";
    $("selHost").innerHTML = hosts.length ? hosts.map((h) => `<option ${h === cur ? "selected" : ""}>${esc(h)}</option>`).join("") :
      `<option value="">${esc(cur || "(auto)")}</option>`;
  }

  // ------------------------------------------------------------------ values
  function plain(v) {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      if ("$rt" in v) return `⟨runtime:${v.$rt}⟩`;
      if ("$undef" in v) return `⟨undefined:${v.$undef}⟩`;
      if ("$omit" in v) return "⟨omit⟩";
      if ("$obj" in v) return `⟨${v.$obj}⟩`;
      const o = {};
      for (const k in v) o[k] = plain(v[k]);
      return o;
    }
    if (Array.isArray(v)) return v.map(plain);
    return v;
  }
  function decorate(s) {
    return esc(s).replace(/⟨runtime:([^⟩]*)⟩/g, '<span class="v-rt">⟨runtime:$1⟩</span>')
      .replace(/⟨undefined:([^⟩]*)⟩/g, '<span class="v-undef">⟨undefined:$1⟩</span>')
      .replace(/⟨omit⟩/g, '<span class="v-omit">omit</span>')
      .replace(/⟨(error|syntax error)[^⟩]*⟩/g, (m) => `<span class="v-undef">${m}</span>`);
  }
  function val(v, inline) {
    if (v === undefined) return "";
    if (v && typeof v === "object" && !Array.isArray(v)) {
      if ("$rt" in v) return `<span class="v-rt">⟨runtime:${esc(v.$rt)}⟩</span>`;
      if ("$undef" in v) return `<span class="v-undef">⟨undefined:${esc(v.$undef)}⟩</span>`;
      if ("$omit" in v) return `<span class="v-omit">omit</span>`;
      if ("$obj" in v) return `<span class="v-omit">${esc(v.$obj)}</span>`;
    }
    if (typeof v === "string") {
      const multi = v.includes("\n");
      if (inline && !multi && v.length < 120) return `<code class="val">${decorate(v)}</code>`;
      return `<pre class="val">${decorate(v)}</pre>`;
    }
    const txt = JSON.stringify(plain(v), null, (v && typeof v === "object" && JSON.stringify(v).length > 70) ? 2 : 0);
    return inline && txt.length < 120 && !txt.includes("\n") ? `<code class="val">${decorate(txt)}</code>` : `<pre class="val">${decorate(txt)}</pre>`;
  }
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

  function refsHtml(tr) {
    if (!tr) return "";
    const seen = new Set();
    const chips = [];
    for (const r of tr.refs) {
      const key = r.name + "|" + r.source;
      if (seen.has(key)) continue;
      seen.add(key);
      const v = r.value === undefined ? r.raw : r.value;
      const short = JSON.stringify(plain(v));
      chips.push(`<span class="ref ${r.depth ? "ind" : ""}" title="${esc(r.depth ? "indirect (referenced by another variable)" : "direct reference")}&#10;raw: ${esc(JSON.stringify(plain(r.raw)))}">${esc(r.name)} <span class="src">← ${esc(r.source)}</span>${short && short.length < 60 ? " = " + decorate(short) : ""}</span>`);
    }
    for (const u of tr.undefined) chips.push(`<span class="ref v-undef">undefined: ${esc(u)}</span>`);
    for (const u of tr.runtime) chips.push(`<span class="ref v-rt">runtime: ${esc(u)}</span>`);
    for (const e of tr.errors) chips.push(`<span class="ref v-undef">${esc(e)}</span>`);
    return chips.length ? `<div class="refs">${chips.join("")}</div>` : "";
  }

  const resLabel = (r) => r === true ? ["true", "true"] : r === false ? ["false", "false"] : r === "unknown" ? ["unknown", "unknown at runtime"] : ["error", "error"];
  function condsHtml(list, title) {
    if (!list || !list.length) return "";
    return `<div><div class="label">${title}</div>` + list.map((w) => {
      const [c, t] = resLabel(w.result);
      return `<div class="cond-row"><code class="val">${esc(typeof w.expr === "string" ? w.expr : JSON.stringify(w.expr))}</code>` +
        `<span class="res ${c}">${t}</span>${w.origin && w.origin !== "task" ? `<span class="note">from ${esc(w.origin)}</span>` : ""}` +
        `${w.warn ? `<span class="note warn">${esc(w.warn)}</span>` : ""}${refsHtml(w.trace)}</div>`;
    }).join("") + "</div>";
  }

  function argsTable(args) {
    if (!args.length) return '<p class="note">no arguments</p>';
    return `<table><thead><tr><th>argument</th><th>evaluated value</th><th>source expression</th></tr></thead><tbody>` +
      args.map((a) => {
        const changed = !same(a.raw, a.value);
        return `<tr><td class="k">${esc(a.key === "_raw_params" ? "(free form)" : a.key)}</td>` +
          `<td>${a.omitted ? '<span class="v-omit">omitted: not passed to module</span>' : val(a.value, true)} <span class="type">${esc(a.type)}</span>${refsHtml(a.trace)}</td>` +
          `<td class="raw">${changed ? val(a.raw, true) : '<span class="note">literal</span>'}</td></tr>`;
      }).join("") + "</tbody></table>";
  }

  function kwTable(kws, title) {
    if (!kws || !kws.length) return "";
    return `<div><div class="label">${title}</div><table><tbody>` + kws.map((k) =>
      `<tr><td class="k">${esc(k.key)}</td><td>${val(k.value === undefined ? k.raw : k.value, true)}${refsHtml(k.trace)}</td>` +
      `<td class="raw">${k.value !== undefined && !same(k.raw, k.value) ? val(k.raw, true) : ""}</td></tr>`).join("") + "</tbody></table></div>";
  }

  function extraHtml(x) {
    let h = "";
    if (x.debug) h += `<div><div class="label">debug output${x.debug.var ? ` (var: ${esc(x.debug.var)})` : ""}</div>${val(x.debug.var ? x.debug.value : x.debug.msg)}${refsHtml(x.debug.trace)}</div>`;
    if (x.template) {
      const t = x.template;
      h += `<div><div class="label">template ${t.found ? esc(t.found) : '<span class="note bad">not found</span>'}</div>` +
        (t.output !== undefined ? `<pre class="val out">${decorate(t.output)}</pre>${refsHtml(t.trace)}` : `<p class="note">tried: ${esc(t.tried.join(", "))}</p>`) + "</div>";
    }
    if (x.content !== undefined) h += `<div><div class="label">file content</div>${val(x.content)}</div>`;
    if (x.assert) h += condsHtml(x.assert.map((a) => ({ ...a, origin: "task" })), "assert that");
    if (x.fails) h += `<p class="note bad">would fail: ${esc(JSON.stringify(plain(x.fails)))}</p>`;
    if (x.sets) h += `<p class="note">sets host facts: ${x.sets.map((s) => `<code>${esc(s)}</code>`).join(", ")}</p>`;
    if (x.include) h += `<p class="note">include ${esc(JSON.stringify(plain(x.include.file)))} → ${x.include.found ? `<code>${esc(x.include.found)}</code>` : `<span class="note bad">not found (tried ${esc(x.include.tried.join(", "))})</span>`}</p>`;
    if (x.include_vars) h += `<p class="note">loaded ${x.include_vars.files.map((f) => `<code>${esc(f)}</code>`).join(", ") || "nothing"}: ${x.include_vars.keys.map(esc).join(", ")}</p>`;
    if (x.meta) h += `<p class="note">meta: <code>${esc(JSON.stringify(x.meta))}</code></p>`;
    if (x.note) h += `<p class="note warn">${esc(x.note)}</p>`;
    return h;
  }

  function loc(n) {
    return n.file ? `<span class="loc" data-file="${esc(n.file)}" data-line="${n.line || 1}">${esc(n.file)}${n.line ? ":" + n.line : ""}</span>` : "";
  }
  const titleOf = (n) => typeof n.name === "string" && n.name ? n.name : typeof n.name_raw === "string" && n.name_raw ? n.name_raw : "";

  function iterHtml(n, it) {
    let h = "";
    if (it.item !== null && it.item !== undefined) h += `<div><div class="label">${esc(n.loop.loop_control && n.loop.loop_control.loop_var || "item")}</div>${val(it.item, true)}</div>`;
    h += condsHtml(it.when, "conditions (when)");
    h += `<div><div class="label">module arguments → ${esc(n.fqcn || n.module)}</div>${argsTable(it.args)}</div>`;
    h += extraHtml(it.extra || {});
    if (it.children && it.children.length) h += `<div class="children">${it.children.map(nodeHtml).join("")}</div>`;
    return h;
  }

  function taskHtml(n) {
    const t = titleOf(n);
    const its = n.iterations || [];
    let sum = `<span class="st st-${n.status}">${esc(statusText(n.status))}</span>` +
      (n.handler ? '<span class="kind">handler</span>' : "") +
      `<span class="title">${esc(t || n.fqcn || "task")}</span>` + (n.fqcn ? `<span class="mod">${esc(n.fqcn)}</span>` : "") +
      (n.loop ? `<span class="chip">${esc(n.loop.key)} × ${n.loop.runtime ? "runtime" : n.loop.count}</span>` : "") +
      (n.register ? `<span class="chip">register: <b>${esc(n.register)}</b></span>` : "") +
      (n.notify ? `<span class="chip">notify: ${esc(plain(n.notify).join(", "))}</span>` : "") + loc(n);
    let body = "";
    if (n.notes && n.notes.length) body += n.notes.map((x) => `<p class="note warn">${esc(x)}</p>`).join("");
    if (n.module_kind === "collection") body += `<p class="note">collection module: only the arguments are shown</p>`;
    if (n.loop) body += `<div><div class="label">loop source</div><code class="val">${esc(JSON.stringify(plain(n.loop.raw)))}</code>${refsHtml(n.loop.trace)}</div>`;
    if (its.length > 1) {
      body += `<div class="iters" data-node="${n.id}">` + its.map((it, i) =>
        `<button type="button" class="${i === 0 ? "on" : ""}" data-i="${i}">${esc(shortItem(it))}</button>`).join("") + "</div>";
    }
    body += its.map((it, i) => `<div class="iter" data-i="${i}" ${i ? "hidden" : ""}>${iterHtml(n, it)}</div>`).join("");
    body += kwTable(n.keywords, "task keywords");
    if (n.after_run && n.after_run.length) body += `<div><div class="label">evaluated after the module runs</div>` +
      n.after_run.map((k) => `<div class="cond-row"><code>${esc(k.key)}</code><code class="val">${esc(JSON.stringify(plain(k.raw)))}</code></div>`).join("") + "</div>";
    return `<details class="node st-${n.status}" id="${n.id}"><summary>${sum}</summary><div class="body">${body}</div></details>`;
  }
  function shortItem(it) {
    const v = it.label !== null && it.label !== undefined ? it.label : it.item;
    const s = typeof v === "string" ? v : JSON.stringify(plain(v));
    return s.length > 32 ? s.slice(0, 30) + "…" : s;
  }
  const statusText = (s) => ({ run: "runs", conditional: "runtime", skipped: "skipped", error: "error" }[s] || s);

  function blockHtml(n) {
    let body = condsHtml(n.when, "block condition");
    if (n.vars.length) body += `<div><div class="label">block vars</div>${n.vars.map((v) => `<code class="val">${esc(v.name)}: ${esc(JSON.stringify(plain(v.raw)))}</code>`).join(" ")}</div>`;
    for (const sec of ["block", "rescue", "always"]) if (n.sections[sec]) body += `<div><div class="label">${sec}</div><div class="children">${n.sections[sec].map(nodeHtml).join("")}</div></div>`;
    return `<details class="node st-${n.status}" id="${n.id}" open><summary><span class="kind">block</span><span class="title">${esc(titleOf(n))}</span>${loc(n)}</summary><div class="body">${body}</div></details>`;
  }

  function roleHtml(n) {
    const st = !n.found ? "error" : n.skipped ? "skipped" : "run";
    let body = "";
    if (!n.found) body += `<p class="note bad">role not found in loaded files</p>`;
    if (n.note) body += `<p class="note">${esc(n.note)}</p>`;
    if (n.whens && n.whens.length) body += `<p class="note">applies: ${n.whens.map((w) => `<code>${esc(JSON.stringify(plain(w.expr)))}</code>`).join(" and ")}</p>`;
    const tbl = (rows, title) => rows && rows.length ? `<div><div class="label">${title}</div><table><tbody>${rows.map((r) => `<tr><td class="k">${esc(r.name)}</td><td>${val(r.raw, true)}</td></tr>`).join("")}</tbody></table></div>` : "";
    body += tbl(n.params, "role params") + tbl(n.defaults, "defaults/") + tbl(n.vars, "vars/");
    if (n.deps && n.deps.length) body += `<div><div class="label">dependencies</div><div class="children">${n.deps.map(nodeHtml).join("")}</div></div>`;
    if (n.children && n.children.length) body += `<div class="children">${n.children.map(nodeHtml).join("")}</div>`;
    return `<details class="node st-${st}" id="${n.id}" open><summary><span class="kind">role</span><span class="title">${esc(n.name)}</span><span class="chip">${esc(n.how)}</span>${n.path ? `<span class="chip mono">${esc(n.path)}</span>` : ""}${loc(n)}</summary><div class="body">${body}</div></details>`;
  }

  function nodeHtml(n) {
    if (!n) return "";
    if (n.kind === "task") return taskHtml(n);
    if (n.kind === "block") return blockHtml(n);
    if (n.kind === "role") return roleHtml(n);
    return "";
  }

  function playHtml(p) {
    if (p.kind === "import_playbook") return `<div class="play"><header><span class="kind">import_playbook</span> <code>${esc(JSON.stringify(plain(p.target)))}</code> → ${p.found ? `<code>${esc(p.found)}</code>` : '<span class="note bad">not found</span>'}</header></div>`;
    const meta = [`<span class="chip">hosts: <b>${esc(JSON.stringify(plain(p.hosts_raw)))}</b></span>`,
      `<span class="chip">matches ${p.matched.length}: ${esc(p.matched.slice(0, 6).join(", "))}${p.matched.length > 6 ? "…" : ""}</span>`,
      p.targeted ? `<span class="st st-run">targets ${esc(result.meta.host)}</span>` : `<span class="st st-skipped">does not target ${esc(result.meta.host)}</span>`,
      `<span class="chip">gather_facts: ${p.gather_facts}</span>`];
    for (const vf of p.vars_files) meta.push(`<span class="chip">vars_files: ${vf.loaded ? `<b>${esc(vf.loaded)}</b>` : `<span class="v-undef">${esc(JSON.stringify(plain(vf.raw)))}</span>`}</span>`);
    let h = `<div class="play"><header><h2>${esc(typeof p.name_raw === "string" ? p.name_raw : "play")}</h2><div class="meta">${meta.join("")}${loc(p)}</div>${kwTable(p.keywords, "play keywords")}</header>`;
    for (const sec of ["pre_tasks", "roles", "tasks", "post_tasks"]) {
      if (p.sections[sec]) h += `<div class="sec"><h3>${sec}</h3>${p.sections[sec].map(nodeHtml).join("") || '<p class="note">empty</p>'}</div>`;
    }
    if (p.handlers.length) h += `<div class="sec"><h3>handlers</h3>${p.handlers.map(nodeHtml).join("")}</div>`;
    return h + "</div>";
  }

  // ------------------------------------------------------------------ render
  function countNodes(nodes, acc) {
    for (const n of nodes || []) {
      if (n.kind === "task") {
        acc[n.status] = (acc[n.status] || 0) + 1;
        for (const it of n.iterations || []) countNodes(it.children, acc);
      } else if (n.kind === "block") for (const s in n.sections) countNodes(n.sections[s], acc);
      else if (n.kind === "role") { countNodes(n.deps, acc); countNodes(n.children, acc); }
    }
    return acc;
  }

  function render() {
    renderHosts();
    const m = result.meta;
    const acc = {};
    for (const p of result.plays) if (p.kind === "play") { for (const s in p.sections) countNodes(p.sections[s], acc); countNodes(p.handlers, acc); }
    const errs = result.diagnostics.filter((d) => d.level === "error").length;
    const warns = result.diagnostics.filter((d) => d.level === "warn").length;
    $("summary").innerHTML = `<span class="big">${esc(m.host)}</span>` +
      `<span class="chip">groups: ${esc(m.host_groups.filter((g) => g !== "all").join(", ") || "none")}</span>` +
      ["run", "conditional", "skipped", "error"].map((s) => acc[s] ? `<span class="st st-${s}">${acc[s]} ${statusText(s)}</span>` : "").join("") +
      (errs ? `<span class="chip" style="color:var(--err)"><b>${errs}</b> problems</span>` : '<span class="chip">no problems</span>') +
      (warns ? `<span class="chip" style="color:var(--cond)"><b>${warns}</b> warnings</span>` : "");
    $("diagCount").textContent = errs || "";
    $("view-tasks").innerHTML = result.plays.length ? result.plays.map(playHtml).join("") : '<p class="empty">No plays. Pick a playbook.</p>';
    renderVars();
    renderDiag();
    $("jsonOut").textContent = JSON.stringify(result, null, 1).slice(0, 400000);
  }

  function renderVars() {
    if (!result) return;
    const q = $("varFilter").value.trim().toLowerCase();
    $("varsBody").innerHTML = result.plays.filter((p) => p.kind === "play").map((p) => {
      const rows = p.vars.filter((v) => !q || v.name.toLowerCase().includes(q) || v.source.toLowerCase().includes(q) ||
        JSON.stringify(v.value).toLowerCase().includes(q));
      return `<div class="play vars"><header><h2>${esc(p.name_raw)}</h2><p class="note">State at the end of the play for ${esc(result.meta.host)}; winning source first, overridden sources struck through.</p></header>` +
        `<div class="sec"><table><thead><tr><th>variable</th><th>value</th><th>source</th><th>defined as</th></tr></thead><tbody>` +
        rows.map((v) => `<tr><td class="k">${esc(v.name)}</td><td>${val(v.value, true)}${v.trace && !v.trace.refs.length ? "" : refsHtml({ refs: v.trace.refs.filter((r) => r.depth > 0 || r.name !== v.name), undefined: v.trace.undefined, runtime: [], errors: v.trace.errors })}</td>` +
          `<td><span class="src-pill">${esc(v.source)}</span> ${v.shadowed.map((s) => `<span class="shadow">${esc(s)}</span>`).join(" ")}</td>` +
          `<td class="raw">${same(v.raw, v.value) ? "" : val(v.raw, true)}</td></tr>`).join("") +
        `</tbody></table>${rows.length ? "" : '<p class="note">no match</p>'}</div></div>`;
    }).join("") || '<p class="empty">Nothing yet.</p>';
  }

  function renderDiag() {
    const d = result.diagnostics;
    $("view-diag").innerHTML = d.length ? `<div class="diag">${d.map((x) =>
      `<div class="d" data-node="${esc(x.node || "")}" data-where="${esc(x.where || "")}"><span class="lvl ${x.level}">${x.level}</span><div>${esc(x.msg)}${x.where ? `<div class="where">${esc(x.where)}</div>` : ""}</div></div>`).join("")}</div>` :
      '<p class="empty">No diagnostics.</p>';
  }

  function renderFatal(msg) {
    $("view-tasks").innerHTML = `<div class="play"><header><h2>Analyzer error</h2></header><div class="sec"><pre class="val">${esc(msg)}</pre></div></div>`;
    setEngine("Ready", "ok");
  }

  // ------------------------------------------------------------------ persistence & share
  function save() {
    try { localStorage.setItem(STORE, JSON.stringify(state)); } catch (e) { /* storage unavailable */ }
  }
  function load() {
    try { const s = JSON.parse(localStorage.getItem(STORE) || "null"); if (s && s.files) { Object.assign(state, s); return true; } } catch (e) { /* ignore */ }
    return false;
  }
  const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  async function pack(obj) {
    const stream = new Blob([JSON.stringify(obj)]).stream().pipeThrough(new CompressionStream("deflate-raw"));
    return b64u(await new Response(stream).arrayBuffer());
  }
  async function unpack(s) {
    const stream = new Blob([unb64u(s)]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
    return JSON.parse(await new Response(stream).text());
  }
  async function share() {
    try {
      const code = await pack({ f: state.files, e: state.entry, i: state.inventory, h: state.host, x: state.extra, m: state.facts });
      const url = location.href.split("#")[0] + "#z=" + code;
      history.replaceState(null, "", url);
      try { await navigator.clipboard.writeText(url); toast(`Link copied (${Math.round(url.length / 1024)} KB)`); }
      catch (e) { toast("Link is in the address bar"); }
    } catch (e) { toast("Share failed: " + e.message); }
  }
  let toastT;
  function toast(msg) {
    const t = $("toast"); t.textContent = msg; t.classList.add("show");
    clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove("show"), 2600);
  }

  async function loadExample() {
    const r = await fetch("example.json?v=" + VERSION);
    const ex = await r.json();
    state.extra = ex.extra_vars || ""; state.facts = ex.facts || "";
    $("extraVars").value = state.extra; $("facts").value = state.facts;
    state.entry = ex.entry; state.inventory = ex.inventory;
    setFiles(ex.files);
    state.host = ex.host || ""; save();
  }

  // ------------------------------------------------------------------ events
  function bind() {
    $("files").addEventListener("click", (e) => { const b = e.target.closest("button[data-path]"); if (b) openFile(b.dataset.path); });
    $("src").addEventListener("input", () => { if (!state.current) return; state.files[state.current] = $("src").value; updateGutter(); save(); auto(); });
    $("src").addEventListener("scroll", () => { $("gutter").scrollTop = $("src").scrollTop; });
    $("src").addEventListener("keydown", (e) => {
      if (e.key === "Tab" && !e.shiftKey && !e.ctrlKey && !e.metaKey) {
        e.preventDefault();
        const ta = e.target, s = ta.selectionStart;
        ta.setRangeText("  ", s, ta.selectionEnd, "end");
        ta.dispatchEvent(new Event("input"));
      }
    });
    $("fileName").addEventListener("change", () => {
      const nv = $("fileName").value.trim().replace(/^\/+/, "");
      const old = state.current;
      if (!old || !nv || nv === old) return;
      if (state.files[nv] !== undefined) { toast("A file with that path exists"); $("fileName").value = old; return; }
      state.files[nv] = state.files[old]; delete state.files[old];
      if (state.entry === old) state.entry = nv;
      if (state.inventory === old) state.inventory = nv;
      openFile(nv); renderSelects(); save(); auto();
    });
    $("btnDelete").addEventListener("click", () => {
      const p = state.current;
      if (!p) return;
      const content = state.files[p];
      delete state.files[p];
      if (state.entry === p) state.entry = "";
      guessDefaults();
      openFile(Object.keys(state.files).sort()[0] || null); renderSelects(); save(); auto();
      lastDeleted = [p, content];
      toast(`Deleted ${p}. Press Ctrl+Z outside the editor to restore.`);
    });
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "z" && lastDeleted && !e.target.closest("textarea,input")) {
        const [p, c] = lastDeleted; lastDeleted = null;
        state.files[p] = c; openFile(p); renderSelects(); save(); auto(); toast(`Restored ${p}`);
      }
    });
    $("btnNew").addEventListener("click", () => {
      let n = 1, p = "new.yml";
      while (state.files[p] !== undefined) p = `new${++n}.yml`;
      state.files[p] = "";
      openFile(p); renderSelects(); save();
      $("fileName").focus(); $("fileName").select();
    });
    $("btnExample").addEventListener("click", () => loadExample().catch((e) => toast("Example failed: " + e.message)));
    $("btnShare").addEventListener("click", share);
    $("inFolder").addEventListener("change", async (e) => { const f = await readFileList(e.target.files, true); e.target.value = ""; state.entry = ""; state.inventory = ""; setFiles(f); toast(`${Object.keys(f).length} files loaded`); });
    $("inFiles").addEventListener("change", async (e) => { const f = await readFileList(e.target.files, false); e.target.value = ""; setFiles({ ...state.files, ...f }, true); toast(`${Object.keys(f).length} files added`); });
    document.addEventListener("dragover", (e) => { e.preventDefault(); document.body.classList.add("dragging"); });
    document.addEventListener("dragleave", (e) => { if (!e.relatedTarget) document.body.classList.remove("dragging"); });
    document.addEventListener("drop", async (e) => {
      e.preventDefault(); document.body.classList.remove("dragging");
      const list = e.dataTransfer.items && e.dataTransfer.items[0] && e.dataTransfer.items[0].webkitGetAsEntry ? await entriesToFiles([...e.dataTransfer.items]) : [...e.dataTransfer.files];
      const f = await readFileList(list, true);
      if (!Object.keys(f).length) return toast("No text files found");
      state.entry = ""; state.inventory = ""; setFiles(f); toast(`${Object.keys(f).length} files loaded`);
    });
    $("selEntry").addEventListener("change", (e) => { state.entry = e.target.value; renderFiles(); save(); schedule(0); });
    $("selInv").addEventListener("change", (e) => { state.inventory = e.target.value; state.host = ""; renderFiles(); save(); schedule(0); });
    $("selHost").addEventListener("change", (e) => { state.host = e.target.value; save(); schedule(0); });
    $("extraVars").addEventListener("input", (e) => { state.extra = e.target.value; save(); auto(); });
    $("facts").addEventListener("input", (e) => { state.facts = e.target.value; save(); auto(); });
    $("btnRun").addEventListener("click", () => schedule(0));
    $("varFilter").addEventListener("input", renderVars);
    $("btnCopyJson").addEventListener("click", async () => { try { await navigator.clipboard.writeText(JSON.stringify(result, null, 1)); toast("JSON copied"); } catch (e) { toast("Copy blocked by browser"); } });
    document.querySelector(".tabs").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-tab]");
      if (b) showTab(b.dataset.tab);
    });
    document.querySelector(".right").addEventListener("click", (e) => {
      const l = e.target.closest(".loc");
      if (l) { e.preventDefault(); gotoLine(l.dataset.file, +l.dataset.line); return; }
      const ib = e.target.closest(".iters button");
      if (ib) {
        const wrap = ib.parentElement, i = ib.dataset.i;
        wrap.querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === ib));
        wrap.parentElement.querySelectorAll(":scope > .iter").forEach((x) => { x.hidden = x.dataset.i !== i; });
        return;
      }
      const d = e.target.closest(".diag .d");
      if (d) {
        if (d.dataset.node && document.getElementById(d.dataset.node)) {
          showTab("tasks");
          const n = document.getElementById(d.dataset.node);
          for (let p = n; p; p = p.parentElement) if (p.tagName === "DETAILS") p.open = true;
          n.scrollIntoView({ block: "center", behavior: "smooth" });
          n.classList.remove("flash"); void n.offsetWidth; n.classList.add("flash");
        } else if (d.dataset.where) {
          const [f, ln] = d.dataset.where.split(":");
          gotoLine(f, +ln || 1);
        }
      }
    });
  }
  function showTab(name) {
    document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
    for (const v of ["tasks", "vars", "diag", "json"]) $("view-" + v).hidden = v !== name;
  }

  // ------------------------------------------------------------------ boot
  async function boot() {
    bind();
    startWorker();
    const m = location.hash.match(/^#z=([\w-]+)/);
    if (m) {
      try {
        const s = await unpack(m[1]);
        Object.assign(state, { entry: s.e || "", inventory: s.i || "", extra: s.x || "", facts: s.m || "" });
        $("extraVars").value = state.extra; $("facts").value = state.facts;
        setFiles(s.f || {});
        state.host = s.h || ""; save();
        return;
      } catch (e) { toast("Could not read shared link"); }
    }
    if (load() && Object.keys(state.files).length) {
      $("extraVars").value = state.extra || ""; $("facts").value = state.facts || "";
      renderFiles(); openFile(state.current && state.files[state.current] !== undefined ? state.current : state.entry); renderSelects();
      return;
    }
    await loadExample().catch(() => setFiles({ "site.yml": "- hosts: localhost\n  tasks:\n    - debug: msg=\"{{ 1 + 1 }}\"\n" }));
  }
  boot();
})();
