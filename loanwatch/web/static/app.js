// LoanWatch web front end — plain JS, no build step, no external libraries.
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (p) => String(p).replace("android.permission.", "").toUpperCase();
const icon = (id) => `<svg><use href="#${id}"/></svg>`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const reduced = matchMedia("(prefers-reduced-motion: reduce)").matches;

const CAT_ICON = {
  "Contacts": "c-contacts", "Call log": "c-calllog", "SMS": "c-sms",
  "Photos, media & storage": "c-photos", "Phone": "c-phone", "Location": "c-location",
  "Calendar": "c-calendar", "Camera": "c-camera", "Microphone": "c-mic",
  "Installed apps": "c-apps", "Body sensors": "c-sensors", "Content provider data": "c-photos",
  "Other": "c-apps",
};
const CAT_SHORT = { "Photos, media & storage": "Photos", "Content provider data": "Content data" };
const DEVICE_CATS = ["Contacts", "Call log", "SMS", "Photos, media & storage", "Location", "Phone", "Camera", "Microphone"];
const EXTRA_CAT = { QUERY_ALL_PACKAGES: "Installed apps", BODY_SENSORS: "Body sensors" };
const PHASE_B = ["manifest", "trackers", "api_map", "static", "taint", "frida"];

let status = {}, jobId = null, logCount = 0, pollTimer = null, prevState = "";
let rendered = { review: false, report: false, scanBuilt: false };
let scanStart = 0, elapsedTimer = null, groupOf = {}, groups = {};

// ── Utilities ─────────────────────────────────────────────────────────────
async function getJSON(url, opts) {
  const r = await fetch(url, opts);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw Object.assign(new Error(body.error || r.statusText), { status: r.status });
  return body;
}
function toast(msg, bad = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast show" + (bad ? " bad" : "");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { t.className = "toast" + (bad ? " bad" : ""); }, 3800);
}
function countUp(el, to, ms = 900) {
  to = Number(to) || 0;
  if (reduced || to === 0) { el.textContent = to; return; }
  const t0 = performance.now();
  const step = (t) => {
    const k = Math.min(1, (t - t0) / ms), e = 1 - Math.pow(1 - k, 3);
    el.textContent = Math.round(to * e);
    if (k < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
const catOf = (p) => groupOf[short(p)] || EXTRA_CAT[short(p)] || "Other";
const iconUrl = (id, info) => info && info.icon ? `/api/jobs/${id}/files/${info.icon}` : "";
function appIcon(id, info) {
  const u = iconUrl(id, info);
  return u ? `<img src="${u}" alt="" onerror="this.replaceWith(document.createRange().createContextualFragment('${icon("i-phone-device")}'))">`
           : icon("i-phone-device");
}

// ── Theme ─────────────────────────────────────────────────────────────────
function setTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("lw-theme", t); } catch (e) { /* storage blocked */ }
  $("themeBtn").innerHTML = icon(t === "dark" ? "i-sun" : "i-moon");
}
try { setTheme(localStorage.getItem("lw-theme") || "dark"); } catch (e) { setTheme("dark"); }
$("themeBtn").onclick = () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");

// ── Navigation ────────────────────────────────────────────────────────────
const STEPS = ["new", "review", "scan", "report"];
function show(screen) {
  const target = $("s-" + screen);
  if (!target.classList.contains("active")) {
    document.querySelectorAll(".screen.active").forEach((s) => s.classList.remove("active"));
    target.classList.add("active");
    window.scrollTo({ top: 0 });
  }
  const navKey = STEPS.includes(screen) ? "new" : screen;
  document.querySelectorAll(".nav").forEach((n) => n.classList.toggle("active", n.dataset.nav === navKey));
  const stepper = $("stepper");
  stepper.classList.toggle("hidden", !STEPS.includes(screen));
  const idx = STEPS.indexOf(screen);
  stepper.querySelectorAll("li").forEach((li, i) => {
    li.classList.toggle("done", i < idx);
    li.classList.toggle("current", i === idx);
  });
  if (screen !== "scan") $("drawer").classList.remove("open");
  $("logTab").classList.toggle("hidden", screen !== "scan");
}

function route() {
  const [, page, id] = (location.hash || "#/new").split("/");
  if (page === "job" && id) return openJob(id);
  clearTimeout(pollTimer);
  jobId = null;
  const p = ["new", "history", "setup"].includes(page) ? page : "new";
  show(p);
  if (p === "history") loadHistory();
  if (p === "setup") renderSetup();
}
window.addEventListener("hashchange", route);

// ── Tool status ───────────────────────────────────────────────────────────
async function loadStatus() {
  status = await getJSON("/api/status");
  renderLights();
  if (status.groq_key) {
    getJSON("/api/key/check").then((c) => { status.keyCheck = c; renderLights(); if ($("s-setup").classList.contains("active")) renderSetup(); })
      .catch(() => {});
  }
  return status;
}
function aiLevel() {
  if (!status.groq_key) return "warn";
  if (!status.keyCheck) return "";
  return status.keyCheck.ok === false ? "bad" : status.keyCheck.ok ? "ok" : "warn";
}
function renderLights() {
  const L = (lvl, name) => `<span class="light ${lvl}"><i></i>${name}</span>`;
  $("lights").innerHTML = [
    L(aiLevel(), "AI"),
    L(status.java ? "ok" : "warn", "Java"),
    L(status.flowdroid_jar ? "ok" : "warn", "FlowDroid"),
    L((status.platform_levels || []).length ? "ok" : "warn", "Android"),
  ].join("");
}
function renderSetup() {
  const card = (lvl, ic, title, text) => `<div class="scard ${lvl}"><div class="stop"><span class="sic">${icon(ic)}</span>${title}</div><p>${text}</p></div>`;
  const k = status.keyCheck;
  $("setupGrid").innerHTML = [
    card(aiLevel() || "warn", "i-zap", "AI (Groq)", !status.groq_key ? "No key yet. Add one below to turn on the AI steps."
      : `Key ${esc(status.groq_key_hint)} (${esc(status.groq_key_source)})<br>${k ? esc(k.message) : "checking…"}`),
    card(status.java ? "ok" : "warn", "i-terminal", "Java", status.java ? "Version " + esc(status.java) : "Install Java 11+ (adoptium.net) for FlowDroid."),
    card(status.flowdroid_jar ? "ok" : "warn", "i-globe", "FlowDroid", status.flowdroid_jar ? "Installed · memory " + esc(status.java_mem) : "Run <code>setup_tools.py</code>."),
    card((status.platform_levels || []).length ? "ok" : "warn", "i-phone-device", "Android platform",
      (status.platform_levels || []).length ? "API " + status.platform_levels.join(", ") : "Run <code>setup_tools.py</code>."),
  ].join("");
  $("keyState").innerHTML = status.groq_key
    ? `Current key ${esc(status.groq_key_hint)}, ${esc(status.groq_key_source)}. Paste a new one to replace it.`
    : "No key saved yet.";
}
$("saveKey").onclick = async () => {
  const key = $("keyInput").value.trim();
  if (!key) return;
  $("saveKey").disabled = true;
  try {
    const res = await getJSON("/api/key", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key }) });
    $("keyInput").value = "";
    toast(res.checked ? "Key saved: " + res.message : "Saved, but " + res.message, !res.checked);
    await loadStatus();
    renderSetup();
  } catch (e) { toast(e.message, true); }
  $("saveKey").disabled = false;
};

// ── Step 1: upload ────────────────────────────────────────────────────────
document.querySelectorAll(".drop").forEach((drop) => {
  const input = drop.querySelector("input");
  const update = () => {
    const f = input.files[0];
    drop.classList.toggle("has-file", !!f);
    if (f) {
      drop.querySelector(".fname").textContent = f.name;
      drop.querySelector(".fsize").textContent = (f.size / 1048576).toFixed(1) + " MB";
    }
  };
  input.addEventListener("change", update);
  ["dragenter", "dragover"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.add("drag")));
  ["dragleave", "drop"].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove("drag")));
});

$("uploadForm").onsubmit = (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  const apk = fd.get("apk");
  if (!apk || !apk.name) { toast("Choose an APK first", true); return; }
  const btn = $("startBtn");
  btn.disabled = true;
  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/jobs");
  xhr.upload.onprogress = (ev) => {
    if (ev.lengthComputable) btn.innerHTML = `${icon("i-download")} Uploading ${Math.round(ev.loaded / ev.total * 100)}%`;
  };
  xhr.onload = () => {
    btn.disabled = false;
    btn.innerHTML = `${icon("i-search")} Start inspection`;
    let res = {};
    try { res = JSON.parse(xhr.responseText); } catch (err) { /* not JSON */ }
    if (xhr.status >= 400) { toast(res.error || "Upload failed", true); return; }
    e.target.reset();
    document.querySelectorAll(".drop").forEach((d) => d.classList.remove("has-file"));
    location.hash = "#/job/" + res.id;
  };
  xhr.onerror = () => { btn.disabled = false; btn.innerHTML = `${icon("i-search")} Start inspection`; toast("Upload failed", true); };
  xhr.send(fd);
};

// ── Job polling ───────────────────────────────────────────────────────────
function openJob(id) {
  if (jobId !== id) {
    jobId = id; logCount = 0; prevState = "";
    rendered = { review: false, report: false, scanBuilt: false };
    $("log").textContent = "";
    scanStart = 0;
    clearInterval(elapsedTimer);
  }
  clearTimeout(pollTimer);
  poll();
}

async function poll() {
  const id = jobId;
  let j;
  try { j = await getJSON(`/api/jobs/${id}?since=${logCount}`); }
  catch (e) {
    if (e.status === 404) { toast("That report no longer exists", true); location.hash = "#/history"; return; }
    pollTimer = setTimeout(poll, 2000); return;
  }
  if (id !== jobId) return;
  if (j.logs.length) {
    const log = $("log");
    log.textContent += j.logs.join("\n") + "\n";
    log.scrollTop = log.scrollHeight;
  }
  logCount = j.log_count;

  const was = prevState;
  prevState = j.state;
  if (j.state === "queued" || j.state === "reading_policy") showReading(j);
  else if (j.state === "awaiting_confirmation") renderReview(j);
  else if (j.state === "running") renderScan(j);
  else if (j.state === "error") renderScan(j);
  else if (j.state === "done") {
    if (was === "running" || (rendered.scanBuilt && !rendered.report)) {
      renderScan(j);
      await sleep(reduced ? 0 : 1500);
      if (id === jobId) renderReport(j);
    } else renderReport(j);
  }
  if (!["done", "error", "awaiting_confirmation"].includes(j.state)) pollTimer = setTimeout(poll, 900);
}

// ── App card ──────────────────────────────────────────────────────────────
function appCard(id, info, extra = "") {
  if (!info) {
    return `<div class="icon skeleton"></div><div class="grow"><div class="skeleton" style="height:18px;width:50%"></div>
      <div class="skeleton" style="height:12px;width:70%;margin-top:8px"></div></div>`;
  }
  return `<div class="icon">${appIcon(id, info)}</div>
    <div class="grow"><h2>${esc(info.app_name || "Unknown app")}</h2>
      <div class="meta"><code>${esc(info.package)}</code><span>v${esc(info.version || "?")}</span>
      <span>targets API ${esc(info.target_sdk)}</span>${info.size_mb ? `<span>${info.size_mb} MB</span>` : ""}
      <span>${(info.declared_permissions || []).length} permissions declared</span></div></div>${extra}`;
}

// ── Step 2: review the policy ─────────────────────────────────────────────
function showReading(j) {
  show("review");
  $("appCard").innerHTML = appCard(j.id, j.apk_info);
  $("reviewLoading").classList.remove("hidden");
  $("reviewBody").classList.add("hidden");
  const st = Object.fromEntries(j.stages.map((s) => [s.key, s]));
  $("readingText").textContent = st.policy.status === "running"
    ? (j.has_llm ? "The AI is reading the policy…" : "Reading the policy…")
    : "Decompiling the app with Androguard…";
}

function groupRows(perms, opts) {
  // perms: Set of explicit permissions; opts: {declared, expand, skip, removable}
  const byCat = new Map();
  const add = (p, via) => {
    const c = catOf(p);
    if (!byCat.has(c)) byCat.set(c, []);
    byCat.get(c).push({ p, via });
  };
  [...perms].forEach((p) => add(p, false));
  if (opts.expand) {
    [...perms].forEach((p) => {
      const g = groupOf[p];
      if (!g || (opts.skip || []).includes(g)) return;
      groups[g].forEach((q) => { if (!perms.has(q) && !byCat.get(g).some((x) => x.p === q)) add(q, true); });
    });
  }
  let n = 0;
  return [...byCat.entries()].map(([cat, items], gi) => `
    <div class="group" style="animation-delay:${gi * 60}ms"><div class="gicon">${icon(CAT_ICON[cat] || "c-apps")}</div>
      <div><div class="gname">${esc(cat)}</div><div class="chips">${items.map(({ p, via }) => `
        <span class="chip ${via ? "via" : ""} ${opts.declared.has(p) ? "declared" : ""}" style="animation-delay:${(n++) * 35}ms"
          title="${opts.declared.has(p) ? "The app declares this permission" : ""}">${esc(p)}${via ? " <small>via group</small>" : ""}
          ${opts.removable && !via ? `<button type="button" data-rm="${esc(p)}" title="Remove">${icon("i-x")}</button>` : ""}</span>`).join("")}
      </div></div></div>`).join("") || `<p class="fine">No permissions selected. Use a preset or add one below.</p>`;
}

function highlightExcerpt(text, quotes) {
  let html = esc(text);
  (quotes || []).forEach((q) => {
    const words = esc(q.quote || "").split(/\s+/).filter(Boolean).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    if (words.length < 3) return;
    html = html.replace(new RegExp(words.join("\\s+"), "i"), (m) => `<mark>${m}</mark>`);
  });
  return html;
}

function renderReview(j) {
  if (rendered.review) { show("review"); return; }
  rendered.review = true;
  show("review");
  const s1 = j.stage1;
  groups = s1.groups || {};
  groupOf = {};
  Object.entries(groups).forEach(([g, ps]) => ps.forEach((p) => { groupOf[p] = g; }));
  const declared = new Set(j.apk_info.declared_short);
  const national = new Set(s1.permissions.map(short));

  $("appCard").innerHTML = appCard(j.id, j.apk_info);
  $("reviewLoading").classList.add("hidden");
  $("reviewBody").classList.remove("hidden");

  const note = $("policyNote");
  if (s1.source === "ai") {
    note.className = "note ai";
    note.innerHTML = `${icon("i-zap")} The AI read the policy and found <b>${national.size}</b> prohibited permission(s). Check them against the quotes; remove anything the policy doesn't ban.`;
  } else {
    note.className = "note warn";
    note.textContent = (j.stages[0] && j.stages[0].note) || "The AI did not read the policy. Pick a preset or add the prohibited permissions yourself.";
  }
  $("nationalTitle").textContent = s1.source === "ai" ? "AI-extracted from your policy" : "Choose the prohibited data";

  $("evidence").innerHTML = (s1.evidence || []).map((e, i) =>
    `<div class="quote" style="animation-delay:${200 + i * 80}ms"><b>${esc(e.data_type)}</b>: “${esc(e.quote)}”</div>`).join("");
  $("excerpt").innerHTML = highlightExcerpt(s1.clause_text || "", s1.evidence);
  $("excerptBox").classList.toggle("hidden", !s1.clause_text);
  $("permList").innerHTML = (s1.catalog || []).map((c) => `<option value="${esc(c.permission)}">${esc(c.label)}</option>`).join("");

  $("presets").innerHTML = `<span class="fine">Presets:</span>` +
    Object.keys(s1.presets || {}).map((n) => `<button type="button" data-p="${esc(n)}">${esc(n)}</button>`).join("");

  const draw = () => {
    const expand = $("expandGroups").checked;
    $("nationalGroups").innerHTML = groupRows(national, { declared, expand, removable: true });
    $("googleGroups").innerHTML = groupRows(new Set(s1.google_fsp || []), { declared, expand, skip: ["Location"] });
    $("pNational").classList.toggle("off", !$("useNational").checked);
    $("pGoogle").classList.toggle("off", !$("useGoogle").checked);
  };
  $("nationalGroups").onclick = (e) => {
    const b = e.target.closest("[data-rm]");
    if (b) { national.delete(b.dataset.rm); draw(); }
  };
  $("presets").onclick = (e) => {
    const b = e.target.closest("[data-p]");
    if (!b) return;
    national.clear();
    s1.presets[b.dataset.p].forEach((p) => national.add(short(p)));
    $("useNational").checked = true;
    draw();
    toast("Loaded preset: " + b.dataset.p);
  };
  const addPerm = () => {
    const p = short($("customPerm").value.trim());
    if (!p) return;
    national.add(p);
    $("customPerm").value = "";
    draw();
  };
  $("addPerm").onclick = addPerm;
  $("customPerm").onkeydown = (e) => { if (e.key === "Enter") { e.preventDefault(); addPerm(); } };
  ["expandGroups", "useNational", "useGoogle"].forEach((id) => { $(id).onchange = draw; });
  $("useNational").checked = national.size > 0 || s1.source === "ai";
  $("runFd").checked = !!status.flowdroid_ready;
  $("runFd").disabled = !status.flowdroid_ready;
  $("fdHint").textContent = status.flowdroid_ready ? "Slower (up to ~8 min), needs 4 GB+ free memory."
    : "Not installed on this computer: run setup_tools.py to enable it.";
  draw();

  $("runBtn").onclick = async () => {
    const useNat = $("useNational").checked, useG = $("useGoogle").checked;
    if ((!useNat || !national.size) && !useG) { toast("Turn on at least one policy", true); return; }
    $("runBtn").disabled = true;
    try {
      await getJSON(`/api/jobs/${jobId}/confirm`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ permissions: useNat ? [...national] : [], include_google: useG,
          expand_groups: $("expandGroups").checked, run_flowdroid: $("runFd").checked }),
      });
      prevState = "running";
      poll();
    } catch (e) { toast(e.message, true); }
    $("runBtn").disabled = false;
  };
}

// ── Step 3: scan ──────────────────────────────────────────────────────────
const tlIcon = { done: "i-check", failed: "i-x", skipped: "i-arrow", running: "", pending: "" };
function renderScan(j) {
  show("scan");
  if (!rendered.scanBuilt) {
    rendered.scanBuilt = true;
    const info = j.apk_info || {};
    $("deviceApp").innerHTML = `<div class="icon">${appIcon(j.id, info)}</div><b>${esc(info.app_name || "App")}</b><small>${esc(info.package || "")}</small>`;
    $("catGrid").innerHTML = DEVICE_CATS.map((c) =>
      `<div class="cat" data-cat="${esc(c)}"><span class="ci">${icon(CAT_ICON[c])}</span>${esc(CAT_SHORT[c] || c)}</div>`).join("");
    $("timeline").innerHTML = j.stages.map((s) =>
      `<li data-key="${s.key}" class="pending"><span class="tl-dot"></span><div><div class="tl-label">${esc(s.label)}</div><div class="tl-note"></div></div></li>`).join("");
    document.querySelectorAll("[data-live]").forEach((b) => { b.textContent = "–"; b.dataset.v = ""; });
    $("device").className = "device";
    $("scanError").classList.add("hidden");
    scanStart = Date.now();
    clearInterval(elapsedTimer);
    elapsedTimer = setInterval(() => {
      const s = Math.floor((Date.now() - scanStart) / 1000);
      $("elapsed").textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
    }, 500);
  }
  // timeline
  j.stages.forEach((s) => {
    const li = $("timeline").querySelector(`[data-key="${s.key}"]`);
    if (!li || li.dataset.st === s.status + s.note) return;
    li.dataset.st = s.status + s.note;
    li.className = s.status;
    li.querySelector(".tl-dot").innerHTML = tlIcon[s.status] ? icon(tlIcon[s.status]) : "";
    li.querySelector(".tl-note").textContent = s.note;
  });
  // counters
  const live = j.live || {};
  document.querySelectorAll("[data-live]").forEach((b) => {
    const v = live[b.dataset.live];
    if (v === undefined || String(v) === b.dataset.v) return;
    b.dataset.v = v;
    countUp(b, v, 700);
    const c = b.closest(".counter");
    c.classList.remove("bump"); void c.offsetWidth; c.classList.add("bump");
  });
  // data categories light up on the phone
  const hits = new Set(live.categories || []);
  ((j.report && j.report.exposure) || []).forEach((r) => { if (r.asks.length || r.reads || r.sends) hits.add(r.category); });
  document.querySelectorAll(".cat").forEach((c) => c.classList.toggle("hit", hits.has(c.dataset.cat)));

  const running = j.stages.find((s) => s.status === "running");
  if (j.state === "done") {
    $("scanTitle").textContent = "Scan complete";
    $("device").classList.add("done");
    clearInterval(elapsedTimer);
  } else if (j.state === "error") {
    $("scanTitle").textContent = "Scan stopped";
    $("device").classList.add("error");
    $("scanError").classList.remove("hidden");
    $("scanError").textContent = j.error + " (open the technical log for details)";
    clearInterval(elapsedTimer);
  } else {
    $("scanTitle").textContent = running ? running.label + "…" : "Scanning…";
  }
}
$("logTab").onclick = () => $("drawer").classList.toggle("open");

// ── Step 4: report ────────────────────────────────────────────────────────
function shortApi(sig) {
  const m = /<([\w.$]+):\s*\S+\s+(\w+)\(/.exec(sig || "");
  return m ? m[1].split(".").pop() + "." + m[2] : sig || "";
}
function pill(kind, text, ic, detail = "") {
  return `<span class="ex-pill ${kind}">${ic ? icon(ic) : ""}${esc(text)}${detail ? `<span class="pd"> · ${esc(detail)}</span>` : ""}</span>`;
}

function renderReport(j) {
  if (rendered.report) { show("report"); return; }
  rendered.report = true;
  clearInterval(elapsedTimer);
  show("report");
  const r = j.report, app = r.app;
  if (!Object.keys(groupOf).length && j.stage1 && j.stage1.groups) {
    groups = j.stage1.groups;
    Object.entries(groups).forEach(([g, ps]) => ps.forEach((p) => { groupOf[p] = g; }));
  }
  const policies = r.policies || [{ name: "Policy", permissions: (r.policy.permissions || []).map(short), via_group: {},
    matched: r.manifest.matched_permissions.map(short), violating: r.verdict === "VIOLATING" }];
  const file = (n) => `/api/jobs/${j.id}/files/${n}`;
  const stageOf = Object.fromEntries((j.stages || []).map((s) => [s.key, s]));
  const staticRan = stageOf.static ? stageOf.static.status === "done" : r.static_sources.length > 0;

  const verdicts = policies.map((p, i) => `
    <div class="verdict ${p.violating ? "bad" : "good"}" style="animation-delay:${i * 120}ms">
      <div class="vtop"><span class="vbadge">${icon(p.violating ? "i-alert" : "i-check")}</span>
        <div><div class="vname">${esc(p.name)}</div><div class="vtitle">${p.violating ? "Violates" : "No prohibited permission"}</div></div>
        <div class="vnum"><b data-n="${p.matched.length}">0</b><span>prohibited declared</span></div></div>
      ${p.matched.length ? `<div class="chips">${p.matched.map((m) =>
        `<span class="chip declared">${esc(m)}${p.via_group[m] ? ` <small>via ${esc(p.via_group[m])}</small>` : ""}</span>`).join("")}</div>` : ""}
    </div>`).join("");

  const fdRan = r.flowdroid.ran;
  const exRows = (r.exposure || []).filter((e) => e.prohibited_by.length || e.asks.length || e.reads || e.sends);
  const exposure = exRows.length ? `
    <div class="exposure">
      <div class="ex-row head"><div>Data</div>
        <div class="colh">Asks<small>permission declared</small></div>
        <div class="colh">Reads<small>code accesses it</small></div>
        <div class="colh">Sends<small>FlowDroid traced it out</small></div></div>
      ${exRows.map((e) => `<div class="ex-row">
        <div class="ex-cat"><span class="ci">${icon(CAT_ICON[e.category] || "c-apps")}</span>
          <div>${esc(e.category)}<small>${e.prohibited_by.length ? "prohibited by " + e.prohibited_by.map((n) => n.replace(" Financial Services policy", "").replace(" national policy", "")).map(esc).join(", ") : "not prohibited"}</small></div></div>
        <div class="ex-cell" title="${esc(e.asks.join(", "))}">${e.asks.length ? pill("yes", "Yes", "i-alert", String(e.asks.length)) : pill("no", "No")}</div>
        <div class="ex-cell">${!staticRan ? pill("na", "Not checked") : e.reads ? pill("yes", "Yes", "i-code", `${e.reads} place${e.reads > 1 ? "s" : ""}`) : pill("no", "Not found")}</div>
        <div class="ex-cell">${!fdRan ? pill("na", "Not traced") : e.sends ? pill("yes", "Yes", "i-globe", `${e.sends} flow${e.sends > 1 ? "s" : ""}`) : pill("no", "None found")}</div>
      </div>`).join("")}
    </div>` : `<p class="fine">No prohibited data categories to show.</p>`;

  const flows = r.flowdroid.flows.map((f, i) => `
    <div class="flow" style="animation-delay:${i * 90}ms">
      <div class="fnode src"><div class="k">${icon(CAT_ICON[f.category] || "c-apps")} ${esc(f.category || f.data_type || "Data")}</div><code>${esc(shortApi(f.source_api) || "source")}</code></div>
      <div class="flink"></div>
      <div class="fnode"><div class="k">${icon("i-code")} App code</div><code>${esc(f.source_class)}.${esc(f.source_method)}</code></div>
      <div class="flink"></div>
      <div class="fnode sink"><div class="k">${icon("i-globe")} Sent via</div><code>${esc(shortApi(f.sink_api) || (f.sink_class + "." + f.sink_method))}</code></div>
    </div>`).join("");

  const cell = (p, s) => !p.permissions.includes(s) ? "" :
    `<span class="tag-bad">Prohibited</span>${p.via_group[s] ? `<br><small class="fine">via ${esc(p.via_group[s])} group</small>` : ""}`;
  const declaredRows = app.declared_permissions.map((p) => {
    const s = short(p);
    return `<tr><td><code>${esc(p)}</code></td>${policies.map((pol) => `<td>${cell(pol, s)}</td>`).join("")}</tr>`;
  }).join("");
  const sources = r.static_sources.map((s) => `<tr><td>${esc(s.data_type)}</td>
    <td><code>${esc(s.source_class.replace(/^L|;$/g, "").replace(/\//g, "."))}.${esc(s.source_method)}</code></td>
    <td><code>${esc(s.matched_api)}</code><br><small class="fine">${esc(s.call_type)}</small></td></tr>`).join("");
  const trackers = r.trackers.map((t) => `<tr><td>${t.website ? `<a href="${esc(t.website)}" target="_blank" rel="noopener">${esc(t.name)}</a>` : esc(t.name)}</td>
    <td>${esc(t.categories)}</td><td><code>${esc(t.example_class)}</code></td></tr>`).join("");
  const evidence = (r.policy.evidence || []).map((e) => `<div class="quote"><b>${esc(e.data_type)}</b>: “${esc(e.quote)}”</div>`).join("");

  // ── fact cards: registry · Google Play · code hiding
  const reg = r.registry, st = r.store, hid = r.hiding;
  const fact = (lvl, ic, kicker, title, sub) => `<div class="fact ${lvl}"><span class="fic">${icon(ic)}</span>
    <div><div class="kicker">${kicker}</div><b>${title}</b><small>${sub}</small></div></div>`;
  const facts = [
    reg ? (reg.verdict === "flagged"
      ? fact("bad", "i-alert", "Lender registry", "Flagged", esc(reg.matches.filter((m) => /delisted|reported/.test(m.status || m.kind)).map((m) => m.label)[0] || "on a delisted / reported list"))
      : reg.verdict === "listed"
        ? fact("ok", "i-check", "Lender registry", "On a lender list", esc([...new Set(reg.matches.map((m) => m.source))].slice(0, 2).join(" · ")) + (reg.matches.some((m) => m.match === "name") ? " · name match, verify" : ""))
        : fact("warn", "i-search", "Lender registry", "Not on any list", `${reg.sources_checked.length} lists checked`)) : "",
    st ? (st.status === "live"
      ? fact("", "i-globe", "Google Play", "Live", `${esc(st.installs || "?")} installs · ${esc(st.developer || "")}${st.updated ? " · updated " + esc(st.updated) : ""}`)
      : st.status === "not_found"
        ? fact("warn", "i-x", "Google Play", "Not on Google Play", "removed, region-locked or never listed")
        : fact("", "i-alert", "Google Play", "Check failed", esc(st.error || "no connection"))) : "",
    hid ? (hid.hides_code
      ? fact("bad", "i-eye", "Code hiding", hid.packers.length ? "Packed" : "Hides code", esc(hid.reasons.join(" · ")))
      : fact("ok", "i-check", "Code hiding", "No packer found", `${hid.native_libs.length} native librar${hid.native_libs.length === 1 ? "y" : "ies"} · ${hid.dex_files} dex file(s)`)) : "",
  ].join("");

  // ── store claims vs the app
  const ds = st && st.data_safety;
  const cmpRows = (r.store_compare || []).map((c) => `<tr class="${c.declared ? "" : "contra"}">
      <td>${icon(CAT_ICON[c.category] || "c-apps")} ${esc(c.category)}</td>
      <td>${c.declared ? '<span class="ok-txt">Declared</span>' : '<b class="tag-bad">Not declared</b>'}<br><small class="fine">${esc(c.data_safety_category)}</small></td>
      <td>${esc({ asks: "Asks for it", reads: "Code reads it", sends: "Traced to network" }[c.evidence])}</td></tr>`).join("");
  const pp = r.privacy_policy;
  const ppRows = pp && pp.status === "done" ? (pp.items || []).map((i) => `<tr><td>${esc(i.category)}</td>
      <td>${i.stated === "yes" ? '<span class="ok-txt">States it</span>' : i.stated === "no" ? '<b class="tag-bad">Says it does not</b>' : '<span class="fine">Not mentioned</span>'}</td>
      <td><small>${esc(i.quote || "")}</small></td></tr>`).join("") : "";
  let storeSection = "";
  if (st && st.status === "live") {
    storeSection = `<h2 class="section-title">${icon("i-globe")} Store claims vs. the app <small>Google Play Data safety and privacy policy</small></h2>
      <div class="store-grid">
        <div class="pcard"><div class="kicker">Data safety section</div>
          ${!ds || !ds.parsed ? `<p class="fine">Couldn't read the Data safety section${ds && ds.error ? " (" + esc(ds.error) + ")" : ""}. Check it by hand on <a href="${esc(st.url)}" target="_blank" rel="noopener">Google Play</a>.</p>`
            : `<p class="fine">Collected: ${esc((ds.collected || []).join(", ") || (ds.no_data_collected ? "none" : "—"))}<br>Shared: ${esc((ds.shared || []).join(", ") || (ds.no_data_shared ? "none" : "—"))}</p>
               ${cmpRows ? `<div class="tablewrap"><table><thead><tr><th>Data</th><th>Data safety says</th><th>LoanWatch found</th></tr></thead><tbody>${cmpRows}</tbody></table></div>` : `<p class="fine">Nothing to compare.</p>`}`}
        </div>
        <div class="pcard"><div class="kicker">Privacy policy (AI)</div>
          ${!pp ? `<p class="fine">No privacy policy link on the store page.</p>`
            : pp.status !== "done" ? `<p class="fine">${esc(pp.note || "Not checked")}${pp.url ? ` · <a href="${esc(pp.url)}" target="_blank" rel="noopener">open policy</a>` : ""}</p>`
            : `<p class="fine">${esc(pp.summary || "")} · <a href="${esc(pp.url)}" target="_blank" rel="noopener">open policy</a></p>
               <div class="tablewrap"><table><thead><tr><th>Data</th><th>Policy</th><th>Quote</th></tr></thead><tbody>${ppRows}</tbody></table></div>`}
        </div>
      </div>
      <p class="fine">Store page checked ${esc(st.checked_at_utc || "")} (${esc((st.store_country || "").toUpperCase())} store). Developer: ${esc(st.developer || "?")}${st.developerEmail ? " · " + esc(st.developerEmail) : ""}${st.developerWebsite ? ` · <a href="${esc(st.developerWebsite)}" target="_blank" rel="noopener">website</a>` : ""}${st.released ? " · released " + esc(st.released) : ""}${st.score ? ` · rating ${Number(st.score).toFixed(1)} (${esc(st.ratings)} ratings)` : ""}</p>`;
  }

  // ── detail panels: registry, code hiding, evidence
  const regRows = reg ? reg.matches.map((m) => `<tr><td>${esc(m.country || "")}</td><td>${esc(m.label)}</td>
      <td><small>${esc(m.source)}${m.date ? " · " + esc(m.date) : ""}</small></td>
      <td>${m.match === "package" ? "Exact (package)" : `Name: “${esc(m.name)}” <small class="fine">verify</small>`}</td></tr>`).join("") : "";
  const ev = r.evidence || {};
  const cert = (ev.certificates || [])[0] || {};
  const evText = ev.apk_hashes ? [
    `File: ${ev.apk_file} (${ev.apk_bytes} bytes)`, `SHA-256: ${ev.apk_hashes.sha256}`, `SHA-1: ${ev.apk_hashes.sha1}`, `MD5: ${ev.apk_hashes.md5}`,
    `Package: ${app.package}  version ${ev.version_name} (code ${ev.version_code})`,
    cert.sha256 ? `Signing cert SHA-256: ${cert.sha256}` : "Signing cert: NONE READABLE (APK is unsigned or was modified after signing)",
    cert.subject ? `Signer: ${cert.subject}` : "", `Signature schemes: ${(ev.signature_schemes || []).join(", ") || "none"}`,
    ev.policy_sha256 ? `Policy: ${ev.policy_file}  SHA-256 ${ev.policy_sha256}` : "",
    `Scanned (UTC): ${ev.scanned_at_utc}`,
    `Tools: ${Object.entries(ev.tool_versions || {}).map(([k, v]) => k + " " + v).join(", ")}${r.llm_model ? ", model " + r.llm_model : ""}`,
  ].filter(Boolean).join("\n") : "";
  const hidBody = hid ? `
      ${hid.packers.length ? `<p><b class="tag-bad">Packer:</b> ${hid.packers.map((p) => `${esc(p.name)} <small class="fine">(${esc(p.evidence.join(", "))})</small>`).join("; ")}</p>` : `<p class="fine">No known packer signature found.</p>`}
      <div class="tablewrap"><table><tbody>
        <tr><td>Native libraries</td><td>${hid.native_libs.length ? hid.native_libs.map((n) => `<code>${esc(n)}</code>`).join(" ") + ` <small class="fine">(${esc(hid.native_abis.join(", "))})</small>` : "none"}</td></tr>
        <tr><td>Data strings inside native code</td><td>${hid.native_data_strings.length ? hid.native_data_strings.map((d) => `<code>${esc(d.library)}</code> → <code>${esc(d.string)}</code> (${esc(d.category)})`).join("<br>") : "none"}</td></tr>
        <tr><td>Runtime code loading</td><td>${hid.dynamic_loading.length ? hid.dynamic_loading.map((d) => `${esc(d.api)} × ${d.call_sites}`).join(", ") : "none from app code"}</td></tr>
        <tr><td>Extra code files</td><td>${hid.embedded_dex_or_jar.length ? hid.embedded_dex_or_jar.map((f) => `<code>${esc(f)}</code>`).join(" ") : "none"}</td></tr>
        <tr><td>Reflection calls</td><td>${hid.reflection_calls}</td></tr>
        <tr><td>Obfuscation</td><td>${hid.obfuscation ? Math.round(hid.obfuscation.short_name_share * 100) + "% of " + hid.obfuscation.app_classes + " app classes have 1–2 letter names" : "?"}</td></tr>
      </tbody></table></div>` : "";
  const pkg = esc(app.package);
  const cmd = `pip install frida-tools\nadb install "${esc(app.file_name)}"\nfrida -U -f ${pkg} -l loanwatch_frida.js -o ${pkg}_frida_log.txt`;

  $("report").innerHTML = `
    <div class="r-head">
      <div class="app-card">${appCard(j.id, app)}</div>
      <div class="r-actions">
        <a class="btn" href="${file("report.json")}">${icon("i-download")} JSON</a>
        ${r.frida_files.map((n) => `<a class="btn" href="${file(n)}">${icon("i-download")} ${esc(n.replace("loanwatch_", "").replace(".js", ""))}.js</a>`).join("")}
        <button class="btn" id="printBtn">${icon("i-printer")} Print / PDF</button>
        <a class="btn primary" href="#/new">${icon("i-plus")} New scan</a>
      </div>
    </div>
    <div class="verdicts">${verdicts}</div>
    ${facts ? `<div class="facts">${facts}</div>` : ""}
    <ul class="summary">${r.summary.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>

    ${storeSection}
    <h2 class="section-title">${icon("i-eye")} Asks → Reads → Sends <small>what the app can do with prohibited data</small></h2>
    ${exposure}

    <h2 class="section-title">${icon("i-globe")} Data-flow paths <small>${fdRan ? r.flowdroid.flows.length + " found by FlowDroid" : "FlowDroid not run"}</small></h2>
    ${flows ? `<div class="flows">${flows}</div>` : `<p class="fine">${fdRan
      ? "FlowDroid finished and found no complete path. Static tracing misses many real flows, so confirm on a device."
      : "Data-flow tracing was not run for this report."}</p>`}

    <details class="panel"><summary>${icon("i-code")} Where the code reads it <small>${r.static_sources.length}</small></summary><div class="pbody">
      ${sources ? `<div class="tablewrap"><table><thead><tr><th>Data</th><th>App method</th><th>Matched API</th></tr></thead><tbody>${sources}</tbody></table></div>`
        : `<p class="fine">${staticRan ? "No code calling the matching Android APIs was found (the app may use native code, reflection or packing)." : "Not checked: no prohibited permission declared."}</p>`}</div></details>
    <details class="panel"><summary>${icon("i-phone-device")} Permissions the app declares <small>${app.declared_permissions.length}</small></summary><div class="pbody">
      <div class="tablewrap"><table><thead><tr><th>Permission</th>${policies.map((p) => `<th>${esc(p.name)}</th>`).join("")}</tr></thead><tbody>${declaredRows}</tbody></table></div></div></details>
    <details class="panel"><summary>${icon("i-eye")} Tracking SDKs <small>${r.trackers.length}</small></summary><div class="pbody">
      ${trackers ? `<div class="tablewrap"><table><thead><tr><th>Tracker</th><th>Category</th><th>Example class</th></tr></thead><tbody>${trackers}</tbody></table></div>` : `<p class="fine">None of the Exodus Privacy signatures matched.</p>`}</div></details>
    ${reg ? `<details class="panel"><summary>${icon("i-shield")} Lender registries <small>${reg.matches.length} match(es) · ${reg.sources_checked.length} lists</small></summary><div class="pbody">
      ${regRows ? `<div class="tablewrap"><table><thead><tr><th>Country</th><th>Status</th><th>Source</th><th>Match</th></tr></thead><tbody>${regRows}</tbody></table></div>` : `<p class="fine">No match by package, app name or developer name.</p>`}
      <p class="fine">${esc(reg.note)} Lists checked: ${reg.sources_checked.map(esc).join("; ")}.</p></div></details>` : ""}
    ${hid ? `<details class="panel"><summary>${icon("i-eye")} Packing & hidden code <small>${hid.hides_code ? "indicators found" : "none found"}</small></summary><div class="pbody">${hidBody}</div></details>` : ""}
    ${evText ? `<details class="panel"><summary>${icon("i-key")} Evidence fingerprint <small>SHA-256 ${esc((ev.apk_hashes.sha256 || "").slice(0, 12))}…</small></summary><div class="pbody">
      <pre class="cmd"><button class="btn ghost copy" id="copyEv">${icon("i-copy")}</button>${esc(evText)}</pre>
      <p class="fine">Anyone can re-hash the APK to confirm this report is about the same file.</p></div></details>` : ""}
    <details class="panel"><summary>${icon("i-file")} Policy evidence <small>${r.policy.source === "ai" ? "AI" : "manual"}${r.llm_model ? " · " + esc(r.llm_model) : ""}</small></summary><div class="pbody">
      ${evidence || `<p class="fine">No quotes recorded${r.policy.source === "ai" ? "" : " (permissions chosen by hand or from a preset)"}.</p>`}
      ${r.policy_file ? `<p class="fine">Policy file: ${esc(r.policy_file)}</p>` : ""}</div></details>
    <details class="panel"><summary>${icon("i-terminal")} Confirm on a device <small>dynamic analysis</small></summary><div class="pbody">
      <p>This step can't run in the browser. Use an Android test phone or emulator that you control, with
        <a href="https://frida.re/docs/android/" target="_blank" rel="noopener">frida-server</a> on it and only <b>dummy</b> contacts, SMS and photos.
        As in the paper, just launch the app and answer its permission prompts. Don't register or enter real data.</p>
      <pre class="cmd"><button class="btn ghost copy" id="copyCmd">${icon("i-copy")}</button>${cmd}</pre>
      <p class="fine"><code>[LW][DATA-ACCESS]</code> lines show the app opening contacts, SMS, call logs or media; <code>[LW][NET]</code> lines show where it connects.
        Data read and sent before sign-up matches the paper's pre-registration finding.</p></div></details>`;

  document.querySelectorAll(".vnum b[data-n]").forEach((b) => countUp(b, b.dataset.n, 1100));
  const pills = [...document.querySelectorAll("#report .ex-pill")];
  pills.forEach((p, i) => setTimeout(() => p.classList.add("on"), reduced ? 0 : 300 + i * 70));
  $("printBtn").onclick = () => window.print();
  if ($("copyEv")) $("copyEv").onclick = () => navigator.clipboard.writeText(evText).then(() => toast("Fingerprint copied"), () => toast("Copy failed", true));
  $("copyCmd").onclick = () => {
    navigator.clipboard.writeText(cmd.replace(/&quot;/g, '"').replace(/&amp;/g, "&")).then(() => toast("Commands copied"), () => toast("Copy failed", true));
  };
}
window.addEventListener("beforeprint", () => {
  document.querySelectorAll("#report details").forEach((d) => { d.open = true; });
  document.querySelectorAll("#report .ex-pill").forEach((p) => p.classList.add("on"));
});

// ── Past reports ──────────────────────────────────────────────────────────
async function loadHistory() {
  const list = await getJSON("/api/jobs").catch(() => []);
  $("historyGrid").innerHTML = list.length ? list.map((j, i) => {
    const v = j.violations || [];
    const badges = v.length ? v.map((p) => `<span class="badge ${p.violating ? "bad" : "good"}">${esc(p.name.replace(" Financial Services policy", "").replace(" national policy", ""))}: ${p.violating ? p.count + " violation(s)" : "ok"}</span>`).join(" ")
      : `<span class="badge ${j.verdict === "VIOLATING" ? "bad" : j.verdict ? "good" : "mid"}">${esc(j.verdict || j.state)}</span>`;
    return `<a class="hcard" href="#/job/${j.id}" style="animation-delay:${i * 50}ms">
      <span class="icon">${j.icon ? `<img src="/api/jobs/${j.id}/files/${esc(j.icon)}" alt="">` : icon("i-phone-device")}</span>
      <span><b>${esc(j.app_name || "Untitled scan")}</b><small>${esc(j.package)}</small>
      <small>${new Date(j.created * 1000).toLocaleString()}</small>${badges}</span></a>`;
  }).join("") : `<div class="empty">No reports yet. <a href="#/new">Start your first scan</a>.</div>`;
}

// ── Start ─────────────────────────────────────────────────────────────────
loadStatus().catch(() => {}).finally(route);
