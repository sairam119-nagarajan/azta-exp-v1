"use strict";
// Displays what the API returns and sends typed intents. It computes no trust value and keeps no state beyond this page: a failed refresh turns the view stale, never green.
let csrf = null, view = null, selected = null, lastOk = 0;
const $ = (id) => document.getElementById(id);
const num = (v, d = 3) => (typeof v === "number" ? (Math.abs(v) >= 1000 ? v.toExponential(2) : v.toFixed(d)) : "-");
const dubai = (ns) => (typeof ns === "number" ? new Date(ns / 1e6).toLocaleString("en-GB", { timeZone: "Asia/Dubai" }) : "-");
const key = () => "ui-" + crypto.randomUUID();

function cell(row, text, cls) { const td = document.createElement("td"); td.textContent = text === null || text === undefined ? "-" : String(text); if (cls) td.className = cls; row.appendChild(td); return td; }

async function api(path, body) {
  const options = body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf || "" }, body: JSON.stringify(body) };
  const response = await fetch(path, options);
  const data = await response.json();
  return { status: response.status, data };
}

function showLogin(message) { $("login-panel").hidden = false; $("app").hidden = true; $("logout").hidden = true; $("login-error").textContent = message || ""; }

$("login").addEventListener("submit", async (e) => {
  e.preventDefault();
  const { status, data } = await api("/api/login", { password: $("password").value });
  $("password").value = "";
  if (status !== 200) return showLogin(data.error === "LOCKED_OUT" ? "Too many attempts. Try again in a minute." : "Sign-in failed.");
  csrf = data.csrf;
  $("login-panel").hidden = true; $("app").hidden = false; $("logout").hidden = false;
  refresh(); loadSimulator(); loadMetrics();
});

$("logout").addEventListener("click", async () => { await api("/api/logout", {}); csrf = null; showLogin(); });

function renderHeader() {
  const s = view.session || {};
  $("mode").textContent = "Mode: " + (s.mode || "unknown");
  $("approval").textContent = s.approval_valid ? "Written scope valid until " + dubai(s.expires_utc_ns) : "No valid scope: nothing can be applied";
  $("approval").className = "badge " + (s.approval_valid ? "good" : "warn");
  $("stopped").hidden = !view.actions_stopped;
  const problems = Object.entries(view.problems || {}).map(([k, v]) => k + ": " + v);
  if ((view.missing || []).length) problems.push("no data yet: " + view.missing.join(", "));
  $("problems").textContent = problems.join(" | ");
  $("guide-panel").hidden = !(view.guide || []).length;
  $("guide").textContent = (view.guide || []).join("\n");
}

function renderFleet() {
  const body = $("fleet").tBodies[0];
  body.replaceChildren();
  for (const d of view.devices) {
    const row = document.createElement("tr");
    row.dataset.device = d.device;
    if (d.evidence_stale) row.className = "stale";
    cell(row, d.device);
    cell(row, d.authority_mode);
    cell(row, d.ae_status);
    cell(row, num(d.ae_loss, 4)); cell(row, num(d.a_ae, 2)); cell(row, num(d.s_b_ae, 2)); cell(row, num(d.s_id, 0)); cell(row, num(d.s_c, 0)); cell(row, num(d.t_ae, 2));
    cell(row, d.recommendation + (d.origin && d.recommendation !== "FULL_ACCESS" && d.recommendation !== "NONE" ? " (" + d.origin + ")" : ""), d.recommendation === "QUARANTINE" || d.recommendation === "RESTRICT" ? "bad" : "");
    const c = d.confirmation || {};
    cell(row, (c.needed ? (c.confirmations || 0) + "/" + c.needed + " (PEP)" : "-") + (d.recovery_window_open ? " recovery window" : ""));
    const broker = d.broker || {};
    const noop = d.restrict_is_permission_noop && broker.state && broker.state.includes("RESTRICT") ? " (RESTRICT changes no permission here)" : "";
    cell(row, broker.state + noop, broker.state === "UNKNOWN" || broker.state === "STALE" ? "warn" : "");
    cell(row, d.evidence_age_ns === null ? "none" : (d.evidence_age_ns / 1e9).toFixed(0) + " s" + (d.evidence_stale ? " STALE" : ""), d.evidence_stale ? "warn" : "");
    cell(row, d.model_id);
    row.addEventListener("click", () => select(d.device));
    body.appendChild(row);
  }
}

function field(list, name, value) { const dt = document.createElement("dt"); dt.textContent = name; const dd = document.createElement("dd"); dd.textContent = typeof value === "string" ? value : JSON.stringify(value); list.append(dt, dd); }

function renderReviews() {
  const host = $("reviews");
  const pending = view.reviews.filter((r) => r.state === "PENDING");
  const focus = document.activeElement && host.contains(document.activeElement);
  if (focus) return;
  host.replaceChildren();
  if (!pending.length) { const p = document.createElement("p"); p.className = "hint"; p.textContent = "Nothing is waiting for review."; host.appendChild(p); return; }
  for (const r of pending) {
    const box = document.createElement("div"); box.className = "review";
    const title = document.createElement("strong"); title.textContent = r.action + " " + r.device; box.appendChild(title);
    const list = document.createElement("dl");
    field(list, "Basis", r.origin); field(list, "Why review", r.reason); field(list, "Risk", r.risk); field(list, "Currently", r.current_state || "unknown");
    field(list, "Evidence", r.evidence_ids); field(list, "Model and scores", r.digests); field(list, "Opened", dubai(r.opened_utc_ns)); field(list, "Expires", dubai(r.expires_utc_ns));
    box.appendChild(list);
    const say = document.createElement("p"); say.setAttribute("role", "status");
    for (const [label, kind] of [["Approve once", "APPROVE_ONCE"], ["Reject", "REJECT"], ["Defer", "DEFER"]]) {
      const button = document.createElement("button"); button.textContent = label; button.type = "button";
      const idempotency = key();                 // a double click sends one key
      button.addEventListener("click", async () => {
        button.disabled = true;
        const { status, data } = await api("/api/intent", { kind, idempotency_key: idempotency, device: r.device, review_id: r.review_id, action: r.action, evidence_ids: r.evidence_ids, generation: r.generation });
        say.textContent = status === 202 ? label + " sent. Waiting for the PEP's verified result." : "Refused: " + data.error;
        button.disabled = false;
      });
      box.append(button, " ");
    }
    box.appendChild(say);
    host.appendChild(box);
  }
}

async function select(device) {
  selected = device;
  $("detail").hidden = false; $("detail-name").textContent = device;
  const row = view.devices.find((d) => d.device === device);
  $("noop-note").textContent = row && row.restrict_is_permission_noop ? "This device has no operations role: RESTRICT and FULL_ACCESS have the same broker permissions." : "";
  const { status, data } = await api("/api/device/" + device);
  if (status !== 200) return;
  const history = $("history").tBodies[0]; history.replaceChildren();
  for (const h of data.history.slice().reverse()) {
    const tr = document.createElement("tr");
    cell(tr, h.window_index); cell(tr, h.behavior_source); cell(tr, h.ae_status); cell(tr, num(h.ae_loss, 4)); cell(tr, num(h.a_ae, 2)); cell(tr, num(h.t_ae, 2)); cell(tr, h.recommendation);
    cell(tr, h.supplementary && h.supplementary.timing_advisory ? JSON.stringify(h.supplementary.timing_advisory) : "-");
    history.appendChild(tr);
  }
  const timeline = $("timeline").tBodies[0]; timeline.replaceChildren();
  for (const t of data.policy_timeline.slice().reverse()) {
    const tr = document.createElement("tr");
    cell(tr, dubai(t.ts_utc_ns)); cell(tr, t.kind); cell(tr, t.desired_state); cell(tr, t.status);
    timeline.appendChild(tr);
  }
}

$("restore").addEventListener("submit", async (e) => {
  e.preventDefault();
  const row = view.devices.find((d) => d.device === selected);
  const request = { kind: "RESTORE", idempotency_key: key(), device: selected, confirm_device: $("restore-confirm").value, generation: row ? row.generation : null };
  let { status, data } = await api("/api/intent", request);
  if (status === 409 && data.error === "RESTORE_WOULD_CANCEL_PENDING_REVIEWS") {
    const listed = data.pending_reviews.map((r) => r.action + " (" + r.origin + ") " + r.review_id).join("\n");
    if (window.confirm("This RESTORE of " + selected + " will CANCEL its pending review(s):\n" + listed + "\n\nCancel them and restore anyway?")) {
      ({ status, data } = await api("/api/intent", Object.assign({}, request, { idempotency_key: key(), acknowledge_superseded: data.pending_review_ids })));
    } else {
      status = 0; data = { error: "NOT_SENT: the pending review(s) were kept" };
    }
  }
  $("restore-confirm").value = "";
  $("restore-result").textContent = status === 202 ? "RESTORE sent. The broker column shows the verified result." : "Refused: " + data.error;
});

async function action(kind) {
  const { status, data } = await api("/api/intent", { kind, idempotency_key: key() });
  $("actions-result").textContent = status === 202 ? kind + " sent." : "Refused: " + data.error;
}
$("stop").addEventListener("click", () => action("STOP_NEW_ACTIONS"));
$("resume").addEventListener("click", () => action("RESUME_ACTIONS"));

async function loadSimulator() {
  const { status, data } = await api("/api/simulator");
  if (status !== 200) return;
  $("sim-state").textContent = data.enabled ? data.limits : "Disabled: no simulator session is running.";
  for (const id of ["sim-start", "sim-stop", "sim-device", "sim-anomaly"]) $(id).disabled = !data.enabled;
  $("sim-device").replaceChildren(...view_devices().map((d) => new Option(d, d)));
  $("sim-anomaly").replaceChildren(...data.catalogue.map((a) => new Option(a, a)));
}
const view_devices = () => Array.from({ length: 10 }, (_, i) => "device" + String(i + 1).padStart(2, "0"));
async function simulate(act) {
  const { status, data } = await api("/api/simulator", { action: act, device: $("sim-device").value, anomaly: $("sim-anomaly").value });
  $("sim-result").textContent = status === 202 ? act + ": " + data.outcome : "Refused: " + (data.detail || data.error);
}
$("sim").addEventListener("submit", (e) => { e.preventDefault(); simulate("start"); });
$("sim-stop").addEventListener("click", () => simulate("stop"));

async function loadMetrics() {
  const { status, data } = await api("/api/metrics");
  if (status !== 200) return;
  const text = JSON.stringify(data, null, 1);
  $("metrics").textContent = text;
  $("metrics-export").href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
}
$("metrics-refresh").addEventListener("click", loadMetrics);

async function refresh() {
  if (!csrf) return;
  try {
    const { status, data } = await api("/api/state");
    if (status === 401) { csrf = null; return showLogin("Your session ended. Sign in again."); }
    if (status !== 200) throw new Error(String(status));
    view = data; lastOk = Date.now();
    renderHeader(); renderFleet(); renderReviews();
    if (selected) select(selected);
  } catch (error) { /* the staleness badge below says it */ }
  const age = (Date.now() - lastOk) / 1000;
  $("freshness").textContent = lastOk && age < 6 ? "Live" : "STALE: last update " + (lastOk ? age.toFixed(0) + " s ago" : "never") + ". Do not rely on this view.";
  $("freshness").className = "badge " + (lastOk && age < 6 ? "good" : "bad");
  $("app").classList.toggle("stale", !(lastOk && age < 6));
}
setInterval(refresh, 2000);
