// LoanWatch web front end (no build step, no external libraries)
"use strict";

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const short = (p) => String(p).replace("android.permission.", "").toUpperCase();

let jobId = null, logCount = 0, pollTimer = null, status = {}, lastState = "";

// ── Status ────────────────────────────────────────────────────────────────
async function loadStatus() {
  status = await (await fetch("/api/status")).json();
  const item = (ok, title, detail, level) =>
    `<li><b class="${ok ? "good" : level || "bad"}">${ok ? "✓" : "✗"} ${title}</b>${detail}</li>`;
  $("statusList").innerHTML = [
    `<li id="keyItem"><b class="${status.groq_key ? "" : "warnc"}">${status.groq_key ? "… AI (Groq key)" : "✗ AI (Groq key)"}</b>` +
      (status.groq_key
        ? `key ${esc(status.groq_key_hint)} (${esc(status.groq_key_source)}) · <span id="keyCheck">checking…</span>
           · <a href="#" id="changeKey">change key</a>`
        : "Add a key below to turn on the AI steps") + "</li>",
    item(!!status.java, "Java", status.java ? "version " + esc(status.java) : "Install Java 11+ for FlowDroid", "warnc"),
    item(!!status.flowdroid_jar, "FlowDroid", status.flowdroid_jar ? "installed" : "run setup_tools.py", "warnc"),
    item(status.platform_levels.length > 0, "Android platform",
      status.platform_levels.length ? "API " + status.platform_levels.join(", ") : "run setup_tools.py", "warnc"),
  ].join("");
  $("keyBox").classList.toggle("hidden", status.groq_key);
  if (status.groq_key) {
    $("changeKey").onclick = (e) => { e.preventDefault(); $("keyBox").classList.remove("hidden"); $("keyInput").focus(); };
    const c = await (await fetch("/api/key/check")).json();
    const head = $("keyItem").querySelector("b");
    head.textContent = (c.ok === false ? "✗" : c.ok ? "✓" : "?") + " AI (Groq key)";
    head.className = c.ok === false ? "bad" : c.ok ? "good" : "warnc";
    $("keyCheck").textContent = c.message;
    if (c.ok === false) $("keyBox").classList.remove("hidden");
  }
  $("runFd").checked = status.flowdroid_ready;
  $("runFd").disabled = !status.flowdroid_ready;
}

$("saveKey").onclick = async () => {
  const key = $("keyInput").value.trim();
  if (!key) return;
  const r = await fetch("/api/key", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key }) });
  const res = await r.json();
  if (!r.ok) { alert(res.error || "Could not save the key"); return; }
  $("keyInput").value = "";
  if (!res.checked) alert("Saved, but " + res.message);
  loadStatus();
};

// ── History ───────────────────────────────────────────────────────────────
$("historyBtn").onclick = async () => {
  const card = $("historyCard");
  if (!card.classList.contains("hidden")) { card.classList.add("hidden"); return; }
  const list = await (await fetch("/api/jobs")).json();
  $("historyList").innerHTML = list.length ? list.map((j) =>
    `<li><a href="#${j.id}">${esc(j.app_name || j.id)}</a> <span class="hint">${esc(j.package)} ·
     ${new Date(j.created * 1000).toLocaleString()} · ${esc(j.verdict || j.state)}</span></li>`).join("")
    : "<li class='hint'>No reports yet.</li>";
  card.classList.remove("hidden");
};
window.addEventListener("hashchange", () => openJob(location.hash.slice(1)));

// ── Step 1: upload ────────────────────────────────────────────────────────
$("uploadForm").onsubmit = async (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  if ($("keyInput").value.trim()) fd.append("groq_key", $("keyInput").value.trim());
  $("startBtn").disabled = true;
  $("startBtn").textContent = "Uploading…";
  try {
    const r = await fetch("/api/jobs", { method: "POST", body: fd });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || r.statusText);
    location.hash = j.id;
  } catch (err) {
    alert(err.message);
  } finally {
    $("startBtn").disabled = false;
    $("startBtn").textContent = "Read policy and open app";
  }
};

function openJob(id) {
  if (!id) return;
  jobId = id; logCount = 0; lastState = "";
  $("log").textContent = "";
  ["confirmCard", "reportCard"].forEach((c) => $(c).classList.add("hidden"));
  $("progressCard").classList.remove("hidden");
  clearTimeout(pollTimer);
  poll();
}

async function poll() {
  const r = await fetch(`/api/jobs/${jobId}?since=${logCount}`);
  if (!r.ok) { $("progressCard").classList.add("hidden"); return; }
  const j = await r.json();
  if (j.logs.length) {
    $("log").textContent += j.logs.join("\n") + "\n";
    $("log").scrollTop = $("log").scrollHeight;
  }
  logCount = j.log_count;
  renderStages(j.stages);
  if (j.state !== lastState) {
    lastState = j.state;
    if (j.state === "awaiting_confirmation") renderConfirm(j);
    if (j.state === "done") { $("confirmCard").classList.add("hidden"); renderReport(j); }
    if (j.state === "error") $("logBox").open = true;
  }
  if (j.state === "error") {
    $("stages").insertAdjacentHTML("beforeend",
      `<li><span class="icon bad">!</span><span class="bad">${esc(j.error)}</span></li>`);
  }
  if (!["done", "error", "awaiting_confirmation"].includes(j.state)) pollTimer = setTimeout(poll, 1000);
}

const ICON = { pending: "○", running: "◐", done: "✓", skipped: "–", failed: "✗" };
function renderStages(stages) {
  $("stages").innerHTML = stages.map((s) =>
    `<li><span class="icon ${s.status === "done" ? "good" : s.status === "failed" ? "bad" : ""}">${ICON[s.status] || "○"}</span>
     <span><b>${esc(s.label)}</b> <span class="snote">${esc(s.note)}</span></span></li>`).join("");
}

// ── Step 2: confirm the prohibited permissions ────────────────────────────
function renderConfirm(j) {
  const s1 = j.stage1, declared = new Set(j.apk_info.declared_short);
  const card = $("confirmCard");
  card.classList.remove("hidden");

  const note = $("policyNote");
  if (s1.source === "ai") {
    note.className = "note";
    note.textContent = `The AI read the policy and marked ${s1.permissions.length} permission(s) as prohibited. Check them against the quotes below; untick anything the policy does not actually ban.`;
  } else {
    note.className = "note warn";
    note.textContent = j.stages[0].note ||
      "The AI did not read the policy. Tick the prohibited permissions yourself, or use a preset.";
  }
  $("evidence").innerHTML = (s1.evidence || []).map((e) =>
    `<div class="quote"><b>${esc(e.data_type)}</b>: “${esc(e.quote)}”</div>`).join("");
  $("excerpt").textContent = s1.clause_text || "";
  $("excerptBox").classList.toggle("hidden", !s1.clause_text);

  // Checklist: catalog + AI results + any declared-but-unknown permissions stay addable
  const chosen = new Set(s1.permissions.map(short));
  const items = new Map(s1.catalog.map((c) => [c.permission, c]));
  s1.permissions.forEach((p) => { if (!items.has(short(p))) items.set(short(p), { permission: short(p), label: "from policy" }); });
  const grid = $("permGrid");
  grid.innerHTML = "";
  const addItem = (c, checked) => {
    grid.insertAdjacentHTML("beforeend",
      `<label class="perm"><input type="checkbox" value="${esc(c.permission)}" ${checked ? "checked" : ""}>
       <span><code>${esc(c.permission)}</code>${declared.has(c.permission) ? '<span class="pill declared">declared</span>' : ""}
       <small>${esc(c.label || "")}</small></span></label>`);
  };
  [...items.values()]
    .sort((a, b) => (chosen.has(b.permission) - chosen.has(a.permission)) ||
                    (declared.has(b.permission) - declared.has(a.permission)))
    .forEach((c) => addItem(c, chosen.has(c.permission)));

  $("presets").innerHTML = "<span class='hint'>Presets from the paper:</span>" +
    Object.keys(s1.presets || {}).map((name) => `<button type="button" data-p="${esc(name)}">${esc(name)}</button>`).join("");
  $("presets").querySelectorAll("button").forEach((b) => b.onclick = () => {
    s1.presets[b.dataset.p].forEach((p) => {
      let box = grid.querySelector(`input[value="${p}"]`);
      if (!box) { addItem({ permission: p, label: "preset" }, true); box = grid.querySelector(`input[value="${p}"]`); }
      box.checked = true;
    });
  });
  $("addPerm").onclick = () => {
    const p = short($("customPerm").value.trim());
    if (!p) return;
    const box = grid.querySelector(`input[value="${p}"]`);
    if (box) box.checked = true; else addItem({ permission: p, label: "added by you" }, true);
    $("customPerm").value = "";
  };
  const groupOf = {};
  Object.entries(s1.groups || {}).forEach(([g, ps]) => ps.forEach((p) => { groupOf[p] = g; }));
  const extras = (list, skip = []) => {
    const set = new Set(list), out = [];
    list.forEach((p) => {
      const g = groupOf[p];
      if (!g || skip.includes(g)) return;
      s1.groups[g].forEach((q) => { if (!set.has(q)) { set.add(q); out.push(q); } });
    });
    return out;
  };
  const tag = (p) => `<code>${esc(p)}</code>${declared.has(p) ? ' <span class="pill declared">declared</span>' : ""}`;
  const refresh = () => {
    const on = $("expandGroups").checked;
    const ticked = [...grid.querySelectorAll("input:checked")].map((i) => i.value);
    const add = on ? extras(ticked) : [];
    $("groupPreview").innerHTML = add.length
      ? "Also prohibited through their permission group: " + add.map(tag).join(" · ") : "";
    const g = s1.google_fsp || [], gAdd = on ? extras(g, ["Location"]) : [];
    $("googleList").innerHTML = "Prohibits: " + g.map(tag).join(" · ") +
      (gAdd.length ? "<br>Through their group: " + gAdd.map(tag).join(" · ") +
        " <span class='hint'>(precise location only, so the location group is not expanded)</span>" : "");
    $("googleList").style.opacity = $("useGoogle").checked ? 1 : 0.4;
  };
  grid.addEventListener("change", refresh);
  ["expandGroups", "useGoogle"].forEach((id) => { $(id).onchange = refresh; });
  $("addPerm").addEventListener("click", refresh);
  $("presets").addEventListener("click", refresh);
  refresh();

  $("runBtn").onclick = async () => {
    const permissions = [...grid.querySelectorAll("input:checked")].map((i) => i.value);
    const r = await fetch(`/api/jobs/${jobId}/confirm`, { method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ permissions, run_flowdroid: $("runFd").checked,
        include_google: $("useGoogle").checked, expand_groups: $("expandGroups").checked }) });
    const res = await r.json();
    if (!r.ok) { alert(res.error); return; }
    card.classList.add("hidden");
    lastState = "running";
    poll();
  };
  card.scrollIntoView({ behavior: "smooth" });
}

// ── Report ────────────────────────────────────────────────────────────────
function renderReport(j) {
  const r = j.report, app = r.app, bad = r.verdict === "VIOLATING";
  const matched = new Set(r.manifest.matched_permissions.map(short));
  const policies = r.policies || [{ name: "Policy", permissions: r.policy.permissions.map(short),
    via_group: {}, matched: [...matched], violating: bad }];
  const file = (n) => `/api/jobs/${j.id}/files/${n}`;
  const cell = (pol, s) => !pol.permissions.includes(s) ? ""
    : `<b class="bad">Prohibited</b>${pol.via_group[s] ? `<br><small class="hint">via ${esc(pol.via_group[s])} group</small>` : ""}`;

  const declaredRows = app.declared_permissions.map((p) => {
    const s = short(p);
    return `<tr><td><code>${esc(p)}</code></td>${policies.map((pol) => `<td>${cell(pol, s)}</td>`).join("")}</tr>`;
  }).join("");

  const verdicts = policies.map((pol) => `
    <div class="verdict ${pol.violating ? "bad" : "good"}">${esc(pol.name)}:
      ${pol.violating ? `violates. Declares ${pol.matched.length} prohibited permission(s)` : "no prohibited permission declared"}
      ${pol.violating ? `<div class="vlist">${pol.matched.map((p) => `<code>${esc(p)}</code>${pol.via_group[p] ? ` <small>(via ${esc(pol.via_group[p])} group)</small>` : ""}`).join(" · ")}</div>` : ""}
    </div>`).join("");

  const sources = r.static_sources.map((s) => `<tr>
      <td>${esc(s.data_type)}</td>
      <td><code>${esc(s.source_class.replace(/^L|;$/g, "").replace(/\//g, "."))}.${esc(s.source_method)}</code></td>
      <td><code>${esc(s.matched_api)}</code><br><small class="hint">${esc(s.call_type)}</small></td></tr>`).join("");

  const flows = r.flowdroid.flows.map((f) => `<tr>
      <td>${esc(f.data_type || "")}<br><small class="hint"><code>${esc(f.source_api || "")}</code></small></td>
      <td><code>${esc(f.source_class)}.${esc(f.source_method)}</code></td>
      <td><code>${esc(f.sink_class)}.${esc(f.sink_method)}</code><br><small class="hint">called from ${esc(f.dispatcher_class)}.${esc(f.dispatcher_method)}</small></td></tr>`).join("");

  const trackers = r.trackers.map((t) =>
    `<tr><td>${t.website ? `<a href="${esc(t.website)}" target="_blank" rel="noopener">${esc(t.name)}</a>` : esc(t.name)}</td>
     <td>${esc(t.categories)}</td><td><code>${esc(t.example_class)}</code></td></tr>`).join("");

  const pkg = esc(app.package);
  $("reportCard").innerHTML = `
    <h2>Report: ${esc(app.app_name)}</h2>
    <p class="hint">${pkg} · version ${esc(app.version || "?")} · targets Android API ${esc(app.target_sdk)} · file ${esc(app.file_name)}
       ${r.policy_file ? " · policy " + esc(r.policy_file) : ""}</p>
    ${verdicts}
    <ul class="summary">${r.summary.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>

    <div class="downloads">
      <a href="${file("report.json")}">Download full report (JSON)</a>
      ${r.frida_files.map((n) => `<a href="${file(n)}">Download ${esc(n)}</a>`).join("")}
      <a href="#" onclick="window.print();return false;">Print / save as PDF</a>
    </div>

    ${policies.map((pol) => `<h3>${esc(pol.name)}: prohibited (${pol.permissions.length})</h3>
      <p>${pol.permissions.map((p) => `<code>${esc(p)}</code>${pol.matched.includes(p) ? ' <span class="pill declared">declared</span>' : ""}${pol.via_group[p] ? ' <small class="hint">group</small>' : ""}`).join(" · ")}</p>`).join("")}

    <h3>Permissions the app declares (${app.declared_permissions.length})</h3>
    <div class="tablewrap"><table><thead><tr><th>Permission</th>${policies.map((pol) => `<th>${esc(pol.name)}</th>`).join("")}</tr></thead><tbody>${declaredRows}</tbody></table></div>
    ${r.llm_model ? `<p class="hint">AI model: ${esc(r.llm_model)}</p>` : ""}

    <h3>Where the code reads the prohibited data (${r.static_sources.length})</h3>
    ${sources ? `<div class="tablewrap"><table><thead><tr><th>Data</th><th>App method</th><th>Matched API</th></tr></thead><tbody>${sources}</tbody></table></div>`
              : `<p class="hint">${bad ? "None found in the Java/Kotlin bytecode." : "Not checked: no prohibited permission declared."}</p>`}

    <h3>Data-flow paths (FlowDroid)</h3>
    ${!r.flowdroid.ran ? '<p class="hint">FlowDroid was not run for this report.</p>'
      : flows ? `<div class="tablewrap"><table><thead><tr><th>Data</th><th>Collected in</th><th>Sent via</th></tr></thead><tbody>${flows}</tbody></table></div>`
      : '<p class="hint">FlowDroid finished and found no complete path. Static tracing misses many real flows, so confirm on a device.</p>'}

    <h3>Tracking SDKs (${r.trackers.length})</h3>
    ${trackers ? `<div class="tablewrap"><table><thead><tr><th>Tracker</th><th>Category</th><th>Example class</th></tr></thead><tbody>${trackers}</tbody></table></div>` : '<p class="hint">None of the Exodus Privacy signatures matched.</p>'}

    <h3>Next: confirm on a device (dynamic analysis)</h3>
    <p>This part can't run in the browser. It needs an Android test phone or emulator that you control, with
       <a href="https://frida.re/docs/android/" target="_blank" rel="noopener">frida-server</a> running on it. As in the paper,
       only launch the app and answer its permission prompts. Do not register or enter real personal data.
       Use a test device with dummy contacts, SMS and photos.</p>
    <pre>pip install frida-tools
adb install "${esc(app.file_name)}"
frida -U -f ${pkg} -l loanwatch_frida.js -o ${pkg}_frida_log.txt</pre>
    <p class="hint">Lines tagged <code>[LW][DATA-ACCESS]</code> show the app opening contacts, SMS, call logs or media.
       <code>[LW][NET]</code> lines show where it connects. If data is read and sent before you sign up, that matches the paper's pre-registration finding.</p>
  `;
  $("reportCard").classList.remove("hidden");
  $("reportCard").scrollIntoView({ behavior: "smooth" });
}

loadStatus();
if (location.hash.length > 1) openJob(location.hash.slice(1));
