"use strict";
/* pry dashboard — vanilla JS, no build step.
 *
 * Shape: one state object (S), small render functions per block, and a
 * signature cache so a block only touches the DOM when what it shows
 * actually changed (polls no longer wipe hover/focus every few seconds).
 * Every action goes through act(): busy spinner, double-click guard and a
 * toast with the outcome. */

// =========================================================================
// helpers
// =========================================================================
const $ = (id) => document.getElementById(id);
const enc = encodeURIComponent;

function h(tag, props, ...kids) {
  const e = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "text") e.textContent = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v === true ? "" : v);
    }
  }
  for (const k of kids.flat(Infinity)) {
    if (k == null || k === false) continue;
    e.append(k instanceof Node ? k : String(k));
  }
  return e;
}

/** replaceChildren that skips null/false (the native one stringifies them). */
function fill(el, ...kids) {
  el.replaceChildren(...kids.flat(Infinity).filter((k) => k != null && k !== false));
  return el;
}

const _sig = Object.create(null);
/** True when `value` differs from what block `key` last rendered. */
function changed(key, value) {
  const s = JSON.stringify(value);
  if (_sig[key] === s) return false;
  _sig[key] = s;
  return true;
}

const short = (s, n = 180) => {
  s = String(s ?? "").replace(/\s+/g, " ").trim();
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
};
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
/** Agent strings can carry bytes past a NUL (over-long wide-string
 *  conversions); show only the C string. */
const cstr = (s) => (s == null ? "" : String(s).split("\0")[0].trim());

function fmtDur(ms) {
  if (ms == null || ms === "" || isNaN(ms)) return "—";
  let s = Math.floor(Number(ms) / 1000);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const hh = Math.floor(s / 3600); s -= hh * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  if (d) return `${d}d ${hh}h`;
  if (hh) return `${hh}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}
function fmtAgo(ms) {
  if (ms == null) return "";
  const s = Math.round(ms / 1000);
  if (s < 2) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}
const fmtClock = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
function fmtWhen(ts) {
  if (!ts) return "";
  const d = new Date(ts * 1000);
  const today = new Date().toDateString() === d.toDateString();
  return today ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })
    : d.toLocaleDateString([], { month: "short", day: "numeric" });
}
function fmtDate(v) {
  if (!v) return "—";
  const d = new Date(v);
  return isNaN(d) ? String(v) : d.toLocaleString([], { hour12: false });
}

// =========================================================================
// state
// =========================================================================
const store = {
  get: (k, d) => { try { return localStorage.getItem("pry." + k) ?? d; } catch (_) { return d; } },
  set: (k, v) => { try { localStorage.setItem("pry." + k, v); } catch (_) { /* private mode */ } },
};

const S = {
  machines: [],
  focus: null,
  loadedMachines: false,
  selected: store.get("sel", ""),
  status: null,          // /api/status payload for S.statusFor
  statusFor: "",
  toollog: [],
  lastToolTs: 0,
  events: [],
  findings: [],
  tab: store.get("tab", "calls"),
  filter: "",
  fErrors: false, fDestr: false, fMine: false,
  sev: "all",
  mFilter: "",
  showShells: false,
  openRows: new Set(),
  openFindings: new Set(),
  busy: new Set(),
  wsLive: false,
  apiDown: false,
};

const cur = () => S.machines.find((m) => m.machine === S.selected) || null;

// =========================================================================
// network
// =========================================================================
async function api(method, url, body) {
  const init = { method, cache: "no-store", headers: {} };
  if (method !== "GET") {
    // The control-plane guard refuses browser writes without a JSON
    // content type, so every write carries one (and a body).
    init.headers["content-type"] = "application/json";
    init.body = JSON.stringify(body ?? {});
  }
  let r;
  try {
    r = await fetch(url, init);
  } catch (_) {
    setApiDown(true);
    return { ok: false, status: 0, data: { error: "orchestrator unreachable" } };
  }
  setApiDown(false);
  let data = {};
  try { data = await r.json(); } catch (_) { /* empty body */ }
  const okFlag = !(data && !Array.isArray(data) && data.ok === false);
  return { ok: r.ok && okFlag, status: r.status, data };
}
const getJSON = (url) => api("GET", url);

function setApiDown(down) {
  if (S.apiDown === down) return;
  S.apiDown = down;
  renderLive();
}

// =========================================================================
// toasts, menu, dialogs
// =========================================================================
function toast(msg, kind = "info", ms) {
  const box = $("toasts");
  const t = h("div", { class: `toast ${kind}`, role: kind === "err" ? "alert" : "status" },
    h("div", { class: "toast-msg", text: msg }),
    h("button", { class: "icon-btn", "aria-label": "Dismiss", text: "×", onclick: () => t.remove() }));
  box.append(t);
  while (box.children.length > 4) box.firstElementChild.remove();
  setTimeout(() => t.remove(), ms ?? (kind === "err" ? 12000 : 5000));
}

const menu = $("menu");
function openMenu(anchor, items) {
  menu.replaceChildren(...items.map((it) => {
    if (it === "-") return h("hr");
    return h("button", {
      role: "menuitem", class: it.danger ? "danger" : null, disabled: it.disabled,
      title: it.title, text: it.label,
      onclick: () => { closeMenu(); it.onClick(); },
    });
  }));
  menu.hidden = false;
  const r = anchor.getBoundingClientRect();
  const w = menu.offsetWidth, mh = menu.offsetHeight;
  let left = Math.min(r.right - w, window.innerWidth - w - 8);
  left = Math.max(8, left);
  let top = r.bottom + 4;
  if (top + mh > window.innerHeight - 8) top = Math.max(8, r.top - mh - 4);
  menu.style.left = left + "px";
  menu.style.top = top + "px";
  const first = menu.querySelector("button:not(:disabled)");
  if (first) first.focus({ preventScroll: true });
}
function closeMenu() { menu.hidden = true; }
document.addEventListener("click", (e) => {
  if (!menu.hidden && !menu.contains(e.target)) closeMenu();
});
window.addEventListener("resize", closeMenu);
document.addEventListener("scroll", closeMenu, true);

function confirmDlg({ title, body, list, ok = "OK", danger = true }) {
  return new Promise((resolve) => {
    const d = $("confirm-dlg");
    $("confirm-title").textContent = title;
    const paras = (Array.isArray(body) ? body : [body]).filter(Boolean);
    fill($("confirm-body"),
      paras.map((p) => h("p", { text: p })),
      list && list.length ? h("ul", { class: "confirm-list" }, list.map((a) => h("li", { text: a }))) : null);
    const okBtn = $("confirm-ok");
    okBtn.textContent = ok;
    okBtn.classList.toggle("safe", !danger);
    d.returnValue = "";
    d.addEventListener("close", () => resolve(d.returnValue === "ok"), { once: true });
    d.showModal();
    (danger ? d.querySelector('button[value="cancel"]') : okBtn).focus();
  });
}

/** Run an action once at a time per key, with a busy spinner on the
 *  buttons that render that key. */
async function act(key, fn) {
  if (S.busy.has(key)) return;
  S.busy.add(key);
  renderDetail();
  try { return await fn(); }
  finally {
    S.busy.delete(key);
    renderDetail();
  }
}

// =========================================================================
// machines
// =========================================================================
async function loadMachines() {
  const r = await getJSON("/api/machines");
  if (!r.ok) return;
  S.machines = r.data.machines || [];
  S.focus = r.data.focus || null;
  S.loadedMachines = true;
  ensureSelection();
  renderMachines();
  renderPicker();
  renderDetail();
  renderLive();
}

function ensureSelection() {
  const names = S.machines.map((m) => m.machine);
  if (S.selected && names.includes(S.selected)) return;
  const focus = S.focus && S.focus.machine;
  const pick = (focus && names.includes(focus) && focus)
    || (S.machines.find((m) => m.connected) || {}).machine
    || (S.machines.find((m) => !m.shell) || {}).machine
    || names[0] || "";
  selectMachine(pick);
}

function selectMachine(name) {
  if (S.selected === name) return;
  S.selected = name;
  store.set("sel", name);
  S.status = null;
  S.statusFor = "";
  renderMachines();
  renderPicker();
  renderDetail();
  if (S.tab === "calls" && S.fMine) renderCalls();
  loadStatus();
}

function sortRank(m) { return m.connected ? 0 : (m.shell ? 2 : 1); }
function sortedMachines() {
  return S.machines.slice().sort((a, b) =>
    sortRank(a) - sortRank(b) || a.machine.localeCompare(b.machine));
}
function machineMatches(m, q) {
  if (!q) return true;
  const hay = [m.machine, m.purpose, m.note, m.computer_name, m.trust,
    ...(m.tags || []), ...Object.values(m.endpoints || {})];
  return hay.some((s) => String(s || "").toLowerCase().includes(q));
}
const liveStale = (m) => (m.live || []).some((l) => l.state === "stale");

function renderMachines() {
  const q = S.mFilter.trim().toLowerCase();
  const all = sortedMachines();
  const shells = all.filter((m) => m.shell && !m.connected);
  const visible = all.filter((m) => (S.showShells || q || !(m.shell && !m.connected)) && machineMatches(m, q));
  const sig = {
    sel: S.selected, q, shells: shells.length, show: S.showShells, loaded: S.loadedMachines,
    rows: visible.map((m) => [m.machine, m.trust, m.connected_views, m.purpose, m.shell, liveStale(m),
      Object.values(m.endpoints || {})]),
  };
  $("m-count").textContent = S.machines.length ? String(S.machines.length - shells.length) : "";
  if (!changed("machines", sig)) return;

  const list = $("m-list");
  if (!S.loadedMachines) {
    list.replaceChildren(h("li", { class: "empty", text: "Loading…" }));
  } else if (!S.machines.length) {
    list.replaceChildren(h("li", { class: "empty" },
      "No machines yet. ", h("button", { class: "linkish", text: "Add one", onclick: () => openMachineDlg(null) })));
  } else if (!visible.length) {
    list.replaceChildren(h("li", { class: "empty", text: "No machine matches the filter." }));
  } else {
    list.replaceChildren(...visible.map(machineRow));
  }

  const sh = $("m-shells");
  sh.hidden = !shells.length;
  if (shells.length) {
    sh.replaceChildren(
      h("span", null, plural(shells.length, "empty shell"), " · ",
        h("button", { class: "linkish", text: S.showShells ? "hide" : "show",
          onclick: () => { S.showShells = !S.showShells; renderMachines(); } })),
      h("button", { class: "btn btn-sm", text: "Clean up", title: "Preview and remove empty shell entries",
        onclick: cleanupShells }));
  }
}

function machineRow(m) {
  const views = new Set(m.connected_views || []);
  const trust = String(m.trust || "untrusted").toLowerCase();
  const sel = m.machine === S.selected;
  const ep = Object.values(m.endpoints || {})[0];
  const sub = m.purpose || (m.shell ? "empty shell" : ep || "no endpoint");
  return h("li", {
    class: "m-item" + (sel ? " sel" : ""), role: "option", tabindex: "0",
    "aria-selected": sel ? "true" : "false", title: m.machine,
    onclick: () => selectMachine(m.machine),
    onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); selectMachine(m.machine); } },
  },
  h("span", { class: "sdot" + (m.connected ? (liveStale(m) ? " stale" : " on") : ""),
    title: m.connected ? "connected" : "offline" }),
  h("span", { class: "m-name", text: m.machine }),
  h("span", { class: "m-right" },
    h("span", { class: "vbadges" },
      h("span", { class: "vb" + (views.has("kernel") ? " on" : ""), title: "kernel view", text: "K" }),
      h("span", { class: "vb" + (views.has("user") ? " on" : ""), title: "user view", text: "U" })),
    h("span", { class: `trust-tag ${trust}`, text: trust })),
  h("span", { class: "m-sub", text: sub }));
}

function renderPicker() {
  const sel = $("machine-select");
  const opts = sortedMachines().filter((m) => !m.shell || m.connected || m.machine === S.selected);
  if (!changed("picker", [S.selected, opts.map((m) => [m.machine, m.connected])])) return;
  sel.replaceChildren(...(opts.length ? opts : [{ machine: "", none: true }]).map((m) =>
    h("option", { value: m.machine, selected: m.machine === S.selected },
      m.none ? "—" : (m.connected ? "● " : "○ ") + m.machine)));
  sel.disabled = !opts.length;
}
$("machine-select").addEventListener("change", (e) => selectMachine(e.target.value));

// ---- actions -------------------------------------------------------------
function defaultViews(m) {
  const e = m.endpoints || {};
  if (e.kernel && e.user) return "both";
  if (e.user && !e.kernel) return "user";
  return "kernel";
}
const VIEW_LABEL = { kernel: "kernel view", user: "user view", both: "kernel + user views" };

function connectMachine(m, views) {
  return act("conn:" + m.machine, async () => {
    const r = await api("POST", `/api/machines/${enc(m.machine)}/connect`, { views });
    const vs = (r.data && r.data.views) || {};
    const lines = [];
    let good = 0, bad = 0;
    for (const [kind, v] of Object.entries(vs)) {
      if (v.ok) { good++; lines.push(`${kind}: connected ${v.endpoint || v.view || ""}`.trim()); }
      else if (v.skipped) lines.push(`${kind}: skipped — ${short(v.error, 120)}`);
      else { bad++; lines.push(`${kind}: failed — ${short(v.error, 160)}`); }
    }
    if (!lines.length) { bad++; lines.push(short(r.data.error || `HTTP ${r.status}`)); }
    toast(`${m.machine}\n${lines.join("\n")}`, bad ? (good ? "info" : "err") : "ok");
    await loadMachines();
    loadStatus(true);
  });
}

async function disconnectMachine(m) {
  const views = m.connected_views || [];
  const ok = await confirmDlg({
    title: "Disconnect",
    body: [`Disconnect ${views.join(" + ") || "all"} view${views.length === 1 ? "" : "s"} of “${m.machine}”?`,
      "This is a management override: an agent chat using this machine loses its connection too."],
    ok: "Disconnect", danger: false,
  });
  if (!ok) return;
  await act("conn:" + m.machine, async () => {
    const r = await api("POST", `/api/machines/${enc(m.machine)}/disconnect`);
    if (!r.ok) toast(`Disconnect failed: ${short(r.data.error || r.status)}`, "err");
    else toast(`${m.machine}: disconnected ${(r.data.disconnected || []).join(", ") || "(nothing was connected)"}`, "ok");
    await loadMachines();
    loadStatus();
  });
}

async function removeMachine(m) {
  const views = m.connected_views || [];
  const body = [`Remove “${m.machine}” from the machine registry?`];
  if (m.source === "yaml") body.push("It is defined in the YAML config: only its dashboard metadata overlay is removed, the YAML entry stays.");
  if (m.source === "adhoc" || m.source === "default") body.push("It is a live view without a registry entry: removing it drops the connection.");
  if (views.length) body.push(`Its live ${views.join(" + ")} view${views.length === 1 ? "" : "s"} will be disconnected.`);
  if (!(await confirmDlg({ title: "Remove machine", body, ok: "Remove" }))) return;
  await act("rm:" + m.machine, async () => {
    const r = await api("DELETE", `/api/machines/${enc(m.machine)}`);
    if (!r.ok) { toast(`Remove failed: ${short(r.data.error || r.status)}`, "err"); return; }
    const dropped = r.data.disconnected || [];
    toast(`Removed ${m.machine}` + (dropped.length ? ` · dropped ${dropped.join(", ")}` : ""), "ok");
    if (S.selected === m.machine) { S.selected = ""; store.set("sel", ""); }
    await loadMachines();
  });
}

async function cleanupShells() {
  const preview = await api("POST", "/api/machines/prune", { dry_run: true });
  if (!preview.ok) { toast(`Clean-up preview failed: ${short(preview.data.error || preview.status)}`, "err"); return; }
  const d = preview.data;
  const removed = Array.isArray(d.removed) ? d.removed : [];
  if (!removed.length) { toast("No empty shells to remove.", "info"); return; }
  const kept = (d.kept_connected || []).length + (d.kept_registered || []).length;
  const ok = await confirmDlg({
    title: "Clean up empty shells",
    body: [`Remove ${removed.length} alias-only ${removed.length === 1 ? "entry" : "entries"} with no host, trust, purpose, note, tags or token?`,
      kept ? `${kept} similar entr${kept === 1 ? "y is" : "ies are"} kept (connected, YAML-defined or token set).` : ""],
    list: removed, ok: `Remove ${removed.length}`,
  });
  if (!ok) return;
  const r = await api("POST", "/api/machines/prune", { dry_run: false });
  if (!r.ok) { toast(`Clean-up failed: ${short(r.data.error || r.status)}`, "err"); return; }
  toast(`Removed ${plural(r.data.count_removed || 0, "empty shell")}.`, "ok");
  S.showShells = false;
  await loadMachines();
}

// ---- add / edit dialog ---------------------------------------------------
const mDlg = $("machine-dlg");
const mForm = $("machine-form");
let editAlias = null;

function splitHostPort(ep) {
  const s = String(ep || "");
  const i = s.lastIndexOf(":");
  return i < 0 ? [s, ""] : [s.slice(0, i), s.slice(i + 1)];
}

function openMachineDlg(m) {
  mForm.reset();
  $("machine-err").textContent = "";
  editAlias = m ? m.machine : null;
  $("machine-dlg-title").textContent = m ? `Edit ${m.machine}` : "Add machine";
  const f = (n) => mForm.elements.namedItem(n);
  // readOnly, NOT disabled: FormData drops disabled inputs, which once
  // turned every edit into a silent no-op.
  f("alias").readOnly = !!m;
  f("token").placeholder = m ? (m.token_set ? "set — leave blank to keep" : "not set") : "${LAB3_TOKEN}";
  if (m) {
    const eps = m.endpoints || {};
    const [kh, kp] = splitHostPort(eps.kernel);
    const [uh, up] = splitHostPort(eps.user);
    f("alias").value = m.machine;
    f("host").value = kh || uh || "";
    f("kernel_port").value = kp || "";
    f("user_port").value = up || "";
    f("trust").value = ["untrusted", "restricted", "lab"].includes(m.trust) ? m.trust : "untrusted";
    f("purpose").value = m.purpose || "";
    f("note").value = m.note || "";
    f("tags").value = (m.tags || []).join(", ");
  }
  mDlg.showModal();
  (m ? f("host") : f("alias")).focus();
}

mDlg.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => mDlg.close()));

mForm.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const fd = new FormData(mForm);
  const str = (k) => String(fd.get(k) ?? "").trim();
  const port = (k) => {
    const v = str(k);
    if (!v) return { v: 0 };
    const n = Number(v);
    return Number.isInteger(n) && n > 0 && n < 65536 ? { v: n } : { err: `${k.replace("_", " ")} must be 1–65535` };
  };
  const kp = port("kernel_port"), up = port("user_port");
  const body = {
    alias: str("alias") || editAlias || "",
    host: str("host"),
    kernel_port: kp.v || 0,
    user_port: up.v || 0,
    token: str("token"),
    trust: str("trust"),
    purpose: str("purpose"),
    note: str("note"),
    tags: str("tags"),
    // YAML machines refuse endpoint edits unless force is set.
    force: fd.get("force") === "on",
  };
  const err = !body.alias ? "Alias is required." : (kp.err || up.err);
  if (err) { $("machine-err").textContent = err; return; }
  const save = $("machine-save");
  save.disabled = true; save.classList.add("busy");
  const url = editAlias ? `/api/machines/${enc(editAlias)}` : "/api/machines";
  const r = await api("POST", url, body);
  save.disabled = false; save.classList.remove("busy");
  if (!r.ok) { $("machine-err").textContent = r.data.error || `Save failed (HTTP ${r.status}).`; return; }
  mDlg.close();
  toast(editAlias ? `Saved ${body.alias}` : `Added ${body.alias}`, "ok");
  const added = !editAlias;
  await loadMachines();
  if (added) selectMachine(body.alias);
});

$("add-btn").addEventListener("click", () => openMachineDlg(null));

// =========================================================================
// selected machine: header, meta, views
// =========================================================================
function renderDetail() {
  renderDetailHead();
  renderDetailMeta();
  renderViews();
  renderHost();
  renderPosture();
}

function renderDetailHead() {
  const m = cur();
  const busyConn = m && S.busy.has("conn:" + m.machine);
  const busyRef = m && S.busy.has("ref:" + m.machine);
  const busyRm = m && S.busy.has("rm:" + m.machine);
  const sig = m ? [m.machine, m.trust, m.source, m.connected_views, m.endpoints, busyConn, busyRef, busyRm]
    : [S.loadedMachines, S.machines.length];
  if (!changed("dhead", sig)) return;
  const box = $("d-head");
  if (!m) {
    box.replaceChildren(h("div", { class: "empty" },
      !S.loadedMachines ? "Loading…"
        : S.machines.length ? "Select a machine on the left."
          : [h("strong", { text: "No machines registered." }), " Add one to connect to a lab target."]));
    return;
  }
  const trust = String(m.trust || "untrusted").toLowerCase();
  const actions = [];
  if (m.connected) {
    actions.push(h("button", {
      class: "btn" + (busyRef ? " busy" : ""), disabled: busyRef, title: "Re-read host info and driver probe now",
      text: busyRef ? "Refreshing" : "↻ Refresh",
      onclick: () => act("ref:" + m.machine, async () => { await Promise.all([loadStatus(true), loadMachines()]); }),
    }));
    actions.push(h("button", {
      class: "btn btn-danger" + (busyConn ? " busy" : ""), disabled: busyConn,
      text: busyConn ? "Working" : "Disconnect", onclick: () => disconnectMachine(m),
    }));
  } else {
    const dv = defaultViews(m);
    actions.push(h("span", { class: "split" },
      h("button", {
        class: "btn btn-primary" + (busyConn ? " busy" : ""), disabled: busyConn,
        title: `Connect ${VIEW_LABEL[dv]}`, text: busyConn ? "Connecting" : "Connect",
        onclick: () => connectMachine(m, dv),
      }),
      h("button", {
        class: "btn btn-primary", disabled: busyConn, "aria-label": "Choose views to connect",
        onclick: (e) => { e.stopPropagation(); openMenu(e.currentTarget, connectItems(m)); },
      }, h("span", { class: "caret", text: "▼" }))));
  }
  actions.push(h("button", {
    class: "icon-btn" + (busyRm ? " busy" : ""), "aria-label": "More actions", title: "More actions", text: "⋯",
    onclick: (e) => { e.stopPropagation(); openMenu(e.currentTarget, moreItems(m)); },
  }));
  box.replaceChildren(
    h("div", { class: "d-title" },
      h("span", { class: "d-name", text: m.machine }),
      h("span", { class: `trust-tag ${trust}`, text: trust }),
      m.connected ? null : h("span", { class: "src-tag", text: "offline" }),
      h("span", { class: "src-tag", title: "where this machine is defined", text: m.source || "" })),
    h("div", { class: "d-actions" }, actions));
}

function connectItems(m) {
  const have = new Set(m.connected_views || []);
  const eps = m.endpoints || {};
  return ["kernel", "user", "both"].map((v) => ({
    label: `Connect ${VIEW_LABEL[v]}`,
    disabled: v === "both" ? (have.has("kernel") && have.has("user")) : have.has(v),
    title: v !== "both" && !eps[v] ? `no ${v} endpoint registered — the orchestrator will try its defaults` : null,
    onClick: () => connectMachine(m, v),
  }));
}

function moreItems(m) {
  const items = [{ label: "Edit…", onClick: () => openMachineDlg(m) }];
  if (m.connected) {
    const have = new Set(m.connected_views || []);
    for (const v of ["kernel", "user"]) {
      if (!have.has(v)) items.push({ label: `Connect ${VIEW_LABEL[v]}`, onClick: () => connectMachine(m, v) });
    }
  }
  const ep = Object.values(m.endpoints || {})[0];
  if (ep && navigator.clipboard) {
    items.push({ label: "Copy endpoint", onClick: () => navigator.clipboard.writeText(ep).then(() => toast(`Copied ${ep}`, "ok", 2500)) });
  }
  items.push("-", { label: "Remove…", danger: true, onClick: () => removeMachine(m) });
  return items;
}

function renderDetailMeta() {
  const m = cur();
  const sig = m ? [m.machine, m.purpose, m.note, m.tags, m.operator, m.computer_name, m.source, m.connected] : null;
  if (!changed("dmeta", sig)) return;
  const box = $("d-meta");
  if (!m) { box.replaceChildren(); return; }
  const extra = [m.computer_name && `computer ${m.computer_name}`, m.operator && `operator ${m.operator}`]
    .filter(Boolean).join(" · ");
  fill(box,
    m.purpose ? h("div", { class: "d-purpose", text: m.purpose }) : null,
    m.note ? h("div", { class: "d-note", text: m.note }) : null,
    extra ? h("div", { class: "d-note mono", text: extra }) : null,
    (m.tags || []).length ? h("div", { class: "tags" }, m.tags.map((t) => h("span", { class: "tag", text: t }))) : null,
    m.source === "adhoc" ? h("div", { class: "d-note", text: "Live view without a registry entry. Edit to register it." }) : null);
}

function renderViews() {
  const m = cur();
  const box = $("d-views");
  if (!m) { if (changed("views", null)) box.replaceChildren(); return; }
  const live = m.live || [];
  const have = new Set(m.connected_views || []);
  const kinds = ["kernel", "user", ...live.map((l) => l.kind).filter((k) => k !== "kernel" && k !== "user")];
  const rows = kinds.map((kind) => {
    const reg = (m.endpoints || {})[kind] || "";
    // Older orchestrators don't send `live`; fall back to connected_views
    // so a connected view never reads as offline.
    const l = live.find((x) => x.kind === kind)
      || (have.has(kind) ? { kind, endpoint: reg, state: "connected", last_rtt_ms: null, inflight: 0 } : null);
    return { kind, l, reg, stale: (m.endpoints_stale || {})[kind] || "" };
  });
  // Ages tick every poll; round them so the block doesn't redraw for
  // sub-second noise.
  const sig = rows.map((r) => [r.kind, r.reg, r.stale, r.l && [r.l.endpoint, r.l.state, r.l.inflight,
    r.l.last_rtt_ms == null ? null : Math.round(r.l.last_rtt_ms / 5000)]]);
  if (!changed("views", [m.machine, sig])) return;
  box.replaceChildren(...rows.map(({ kind, l, reg, stale }) => {
    let state = "offline", ep;
    if (l) {
      state = l.state === "cold" ? "no reply yet"
        : l.last_rtt_ms == null ? "connected"
          : l.state === "stale" ? `idle · ${fmtAgo(l.last_rtt_ms)}`
            : `answered ${fmtAgo(l.last_rtt_ms)}`;
      if (l.inflight) state += ` · ${l.inflight} in flight`;
      ep = [h("span", { text: l.endpoint || "—" }),
        reg && reg !== l.endpoint ? h("span", { class: "was", title: "registry endpoint (differs from the live connection)", text: reg }) : null];
    } else {
      ep = reg || (stale ? `last seen ${stale}` : "no endpoint registered");
    }
    return h("div", { class: "view " + (l ? "on" : "off") },
      h("span", { class: "sdot" + (l ? (l.state === "stale" ? " stale" : " on") : "") }),
      h("span", { class: "view-kind", text: kind }),
      h("span", { class: "view-state", text: state }),
      h("span", { class: "view-ep", title: l ? "live endpoint" : "registry endpoint" }, ep));
  }));
}

// =========================================================================
// selected machine: host + protections (/api/status)
// =========================================================================
let statusInflight = "";
async function loadStatus(refresh = false) {
  const name = S.selected;
  const m = cur();
  if (statusInflight === name && !refresh) return;
  statusInflight = name;
  try {
    // A machine with no live view is answered without any agent RPC; the
    // call still keeps the tool-call counter fresh.
    const r = await getJSON(`/api/status?machine=${enc(name)}${refresh ? "&refresh=1" : ""}`);
    if (r.status === 0) return;
    if (r.data && typeof r.data.tool_calls === "number") $("calls-pill").textContent = plural(r.data.tool_calls, "call");
    if (name !== S.selected) return;   // selection moved on meanwhile
    if (r.data && !("view" in r.data) && S.machines.filter((x) => x.connected).length > 1) {
      // Pre-upgrade orchestrator: it ignores ?machine= and always answers
      // for the primary view, so with several machines the data could
      // belong to a different box. Don't show it under this name.
      r.data = { ...r.data, agent: undefined, agent_error: "this orchestrator predates per-machine status; restart it to load the new dashboard API" };
    }
    S.status = r.data || null;
    S.statusFor = name;
    if (m && m.connected && r.data && !r.data.agent && !r.data.agent_error && r.data.view == null) {
      // Machines list is behind the session (just disconnected) — resync.
      loadMachines();
    }
    renderHost();
    renderPosture();
  } finally {
    if (statusInflight === name) statusInflight = "";
  }
}

function statusAgent() {
  const st = S.status && S.statusFor === S.selected ? S.status : null;
  return { st, agent: st && st.agent };
}

function osDisplayName(agent) {
  // Win11 still reports version 10.0; derive the marketing name from the
  // build plus the registry DisplayVersion (25H2/24H2/...).
  const os = agent.os || {};
  const build = parseInt(os.build_major || agent.os_build || "0", 10) || 0;
  const disp = os.display_version || "";
  const edition = os.edition_id || "";
  let name = build >= 22000 ? "Windows 11" : build >= 10240 ? "Windows 10" : "";
  if (!name) name = agent.os_version || os.product_name || "—";
  else if (disp) name += " " + disp;
  if (edition && !name.toLowerCase().includes(edition.toLowerCase())) name += " " + edition;
  const ubr = os.build_ubr ? `.${os.build_ubr}` : "";
  return name + (build ? ` (${build}${ubr})` : "") + (os.arch ? ` · ${os.arch}` : "");
}

const DRIVER_STATE = {
  DRIVER_SERVICE: "loaded · service", SERVICE: "loaded · service",
  DRIVER_MANUAL_MAPPED: "loaded · manual map", MANUAL_MAPPED: "loaded · manual map",
  DRIVER_ABSENT: "absent", ABSENT: "absent",
};
const VERDICT = {
  loaded: "loaded",
  service_registered_not_started: "service registered, not started",
  orphan_service: "orphan service (.sys missing)",
  file_present_no_service: ".sys on disk, no service",
  absent_clean: "not installed",
};

function renderHost() {
  const m = cur();
  const { st, agent } = statusAgent();
  const sig = [S.selected, m && m.connected, st && st.agent_error, agent, st && st.rich_age_s != null && Math.round(st.rich_age_s / 10)];
  if (!changed("host", sig)) return;
  const dl = $("host-dl");
  const note = $("host-note");
  note.textContent = "";
  if (!m) { dl.replaceChildren(); return; }
  if (!m.connected) {
    dl.replaceChildren(h("div", { class: "empty", text: "Connect to read host and driver details." }));
    return;
  }
  if (!st) { dl.replaceChildren(h("div", { class: "empty", text: "Reading host info…" })); return; }
  if (!agent) {
    dl.replaceChildren(h("div", { class: "empty" },
      st.agent_error ? `Agent status failed: ${short(st.agent_error, 240)}` : "No status from this machine yet."));
    return;
  }
  const idn = agent.identity || {};
  const health = agent.pry_driver_health || {};
  let drv;
  if (health.verdict) {
    drv = h("dd", { class: health.loaded ? "good" : "warn" },
      VERDICT[health.verdict] || health.verdict,
      !health.loaded && health.hint ? h("span", { class: "sub-line", text: health.hint }) : null);
  } else if (health.ok === false) {
    drv = h("dd", { class: "warn", text: short(health.error || "probe failed", 200) });
  } else {
    drv = h("dd", { text: "—" });
  }
  const ds = String(agent.driver_state || "");
  const rows = [
    ["Computer", [cstr(idn.computer_name), cstr(idn.logged_on_user) && `user ${cstr(idn.logged_on_user)}`].filter(Boolean).join(" · ") || null],
    ["OS", osDisplayName(agent)],
    ["Agent", [agent.agent_version && `v${agent.agent_version}`, cstr(idn.agent_run_as), idn.is_elevated ? "elevated" : null]
      .filter(Boolean).join(" · ") || null],
    ["Driver", (DRIVER_STATE[ds] || ds.replace(/^DRIVER_/, "").replace(/_/g, " ").toLowerCase() || "—")
      + (agent.driver_version ? ` · v${agent.driver_version}` : "")],
    ["Pry driver", drv],
    ["Uptime", `PC ${fmtDur(agent.pc_uptime_ms)} · service ${fmtDur(agent.service_uptime_ms ?? agent.agent_uptime_ms)}`],
    ["Booted", fmtDate(agent.boot_time || (agent.boot_epoch_ms ? Number(agent.boot_epoch_ms) : ""))],
  ];
  dl.replaceChildren(...rows.filter(([, v]) => v != null).flatMap(([k, v]) =>
    [h("dt", { text: k }), v instanceof Node ? v : h("dd", { text: String(v) })]));
  if (agent.host_info_hint) note.textContent = "HostInfo unavailable";
  else if (st.rich_age_s != null) note.textContent = st.rich_age_s < 3 ? "fresh" : `cached ${Math.round(st.rich_age_s)}s`;
}

const POSTURE = [
  ["memory_integrity", "HVCI"],
  ["vbs_enabled", "VBS"],
  ["secureboot", "Secure Boot"],
  ["credential_guard", "Credential Guard"],
  ["lsa_protected", "LSA protection"],
  ["kva_shadow", "KVA shadow"],
  ["driver_blocklist_on", "Driver blocklist"],
  ["kernel_debugger", "Kernel debugger"],
  ["testsigning", "Test signing"],
];

/** {value, confidence} pairs and loose strings -> on/off/unknown. */
function triState(v) {
  let soft = false;
  if (v && typeof v === "object" && "value" in v) {
    soft = v.confidence === "driver-absent-default";
    v = v.value;
  }
  if (v === true) return { state: "on", soft, label: "on" };
  if (v === false) return { state: "off", soft, label: "off" };
  if (v == null || v === "") return { state: "unknown", soft, label: "?" };
  const s = String(v).toLowerCase();
  if (["on", "true", "1", "yes", "enabled", "active", "running"].includes(s)) return { state: "on", soft, label: "on" };
  if (["off", "false", "0", "no", "disabled", "inactive", "absent"].includes(s)) return { state: "off", soft, label: "off" };
  return { state: "unknown", soft, label: String(v) };
}

function renderPosture() {
  const m = cur();
  const { agent } = statusAgent();
  const sig = [S.selected, m && m.connected, agent && POSTURE.map(([k]) => agent[k]),
    agent && (agent.patchguard_state ?? agent.patchguard_expected), agent && agent.driver_present];
  if (!changed("posture", sig)) return;
  const grid = $("posture-grid");
  const note = $("posture-note");
  note.textContent = "";
  if (!m || !m.connected || !agent) {
    grid.replaceChildren(m && m.connected ? h("div", { class: "empty", text: "Waiting for status…" })
      : m ? h("div", { class: "empty", text: "Not connected." }) : "");
    return;
  }
  const chips = POSTURE.map(([key, label]) => {
    const t = triState(agent[key]);
    return h("div", { class: `chip ${t.state}`, title: `${label}: ${t.label}${t.soft ? " (driver-absent default, unverified)" : ""}` },
      h("span", { class: "chip-dot" }),
      h("span", { class: "chip-k", text: label }),
      t.soft ? h("span", { class: "chip-soft", title: "driver absent — default value, not verified", text: "⚠" }) : null,
      h("span", { class: "chip-v", text: t.label }));
  });
  const pg = agent.patchguard_state ?? agent.patchguard_expected;
  if (pg != null && pg !== "") {
    const t = triState(pg);
    chips.push(h("div", { class: `chip ${t.state} wide`, title: "PatchGuard" },
      h("span", { class: "chip-dot" }),
      h("span", { class: "chip-k", text: "PatchGuard" }),
      h("span", { class: "chip-v", text: typeof pg === "boolean" ? (pg ? "expected" : "not expected") : String(pg) })));
  }
  grid.replaceChildren(...chips);
  note.textContent = agent.driver_present ? "driver-verified" : "driver absent · some values unverified";
}

// =========================================================================
// activity: tool calls
// =========================================================================
let toollogInflight = false;
async function loadToollog() {
  if (toollogInflight) return;
  toollogInflight = true;
  try {
    const r = await getJSON("/api/toollog?limit=300");
    if (!r.ok || !Array.isArray(r.data)) return;
    S.toollog = r.data;
    S.lastToolTs = r.data.length ? r.data[r.data.length - 1].ts : 0;
    renderCalls();
  } finally { toollogInflight = false; }
}

const callKey = (c) => `${c.ts}|${c.tool}|${c.action}`;
function callMatches(c, q) {
  if (S.fErrors && c.ok) return false;
  if (S.fDestr && !c.destructive) return false;
  if (S.fMine) {
    const t = String(c.target || "").toLowerCase();
    const sel = S.selected.toLowerCase();
    if (!sel || !(t === sel || t.startsWith(sel + "."))) return false;
  }
  if (!q) return true;
  return [c.tool, c.action, c.target, c.error, JSON.stringify(c.args || {})]
    .some((s) => String(s || "").toLowerCase().includes(q));
}

function renderCalls() {
  $("tab-calls").textContent = S.toollog.length ? String(S.toollog.length) : "";
  if (S.tab !== "calls") return;
  const q = S.filter.trim().toLowerCase();
  const rows = S.toollog.filter((c) => callMatches(c, q)).reverse();
  const keys = rows.map(callKey);
  const open = keys.filter((k) => S.openRows.has(k));
  if (!changed("calls", [keys, open])) return;
  const body = $("log-body");
  if (!rows.length) {
    body.replaceChildren(h("tr", null, h("td", { colspan: "5", class: "empty" },
      S.toollog.length ? "No tool calls match the filter." : "No tool calls yet. They appear here as agents use pry.")));
    return;
  }
  const out = [];
  for (const c of rows) {
    const k = callKey(c);
    const isOpen = S.openRows.has(k);
    const tool = String(c.tool || "");
    const sfx = tool.endsWith("_manage") ? "_manage" : "";
    out.push(h("tr", {
      class: "row" + (c.ok ? "" : " err") + (c.destructive ? " destr" : "") + (isOpen ? " open" : ""),
      "aria-expanded": isOpen ? "true" : "false", tabindex: "0",
      onclick: () => toggleRow(k),
      onkeydown: (e) => { if (e.key === "Enter") toggleRow(k); },
    },
    h("td", { class: "t-time", title: new Date(c.ts * 1000).toLocaleString() }, fmtClock(c.ts)),
    h("td", { class: "t-tool" }, sfx ? tool.slice(0, -sfx.length) : tool, sfx ? h("span", { class: "sfx", text: sfx }) : null),
    h("td", { title: c.action }, c.action || "", c.destructive ? h("span", { class: "destr-tag", text: "DESTRUCTIVE" }) : null),
    h("td", { class: "t-target", text: c.target || "—" }),
    h("td", { title: c.ok ? "" : c.error || "" },
      c.ok ? h("span", { class: "res-ok", text: "ok" }) : h("span", { class: "res-err", text: c.error || "error" }))));
    if (isOpen) {
      const argsTxt = JSON.stringify(c.args || {}, null, 2);
      out.push(h("tr", { class: "row-detail" }, h("td", { colspan: "5" },
        h("div", { class: "detail-box" },
          c.ok ? null : h("div", null, h("div", { class: "lbl", text: "error" }), h("pre", { class: "code err", text: c.error || "error" })),
          h("div", null, h("div", { class: "lbl", text: `args · ${new Date(c.ts * 1000).toLocaleString()}` }),
            h("pre", { class: "code", text: argsTxt === "{}" ? "(no args recorded)" : argsTxt }))))));
    }
  }
  body.replaceChildren(...out);
}
function toggleRow(k) {
  if (S.openRows.has(k)) S.openRows.delete(k); else S.openRows.add(k);
  renderCalls();
}

// =========================================================================
// activity: events + findings
// =========================================================================
const EV_FIELDS = ["pid", "tid", "address", "code", "exception_code", "module"];
function renderEvents() {
  $("tab-events").textContent = S.events.length ? String(S.events.length) : "";
  if (S.tab !== "events") return;
  const q = S.filter.trim().toLowerCase();
  const evs = S.events.slice().reverse().filter((e) => !q || JSON.stringify(e).toLowerCase().includes(q));
  if (!changed("events", evs)) return;
  const list = $("event-list");
  if (!evs.length) {
    list.replaceChildren(h("div", { class: "empty", style: "padding:0.6rem 1rem" },
      S.events.length ? "No events match the filter." : "No debug events. Breakpoint hits and exceptions show up here."));
    return;
  }
  list.replaceChildren(...evs.map((e) => h("div", { class: "ev" },
    h("span", { class: "ev-kind", text: `[${e.kind || e.type || "debug"}]` }),
    EV_FIELDS.filter((f) => e[f] != null && e[f] !== "").map((f) =>
      h("span", { class: "ev-f" }, `${f}=`, h("b", { text: String(e[f]) }))),
    e.description ? h("span", { text: e.description }) : null)));
}

async function loadFindings() {
  const r = await getJSON("/api/findings");
  if (!r.ok || !Array.isArray(r.data)) return;
  S.findings = r.data;
  renderFindings();
}

const SEVS = ["critical", "high", "medium", "low", "info"];
const sevOf = (f) => { const s = String(f.severity || "").toLowerCase(); return SEVS.includes(s) ? s : "info"; };

function renderFindings() {
  const counts = {};
  for (const f of S.findings) counts[sevOf(f)] = (counts[sevOf(f)] || 0) + 1;
  $("tab-findings").textContent = S.findings.length ? String(S.findings.length) : "";
  if (S.tab !== "findings") return;
  if (changed("sevchips", [counts, S.sev, S.findings.length])) {
    $("sev-filter").replaceChildren(
      h("button", { class: "sev-chip" + (S.sev === "all" ? " active" : ""), text: `all ${S.findings.length}`,
        onclick: () => { S.sev = "all"; renderFindings(); } }),
      ...SEVS.filter((s) => counts[s]).map((s) => h("button", {
        class: `sev-chip sev-${s}` + (S.sev === s ? " active" : ""), text: `${counts[s]} ${s}`,
        onclick: () => { S.sev = S.sev === s ? "all" : s; renderFindings(); },
      })));
  }
  const q = S.filter.trim().toLowerCase();
  const rows = S.findings
    .filter((f) => S.sev === "all" || sevOf(f) === S.sev)
    .filter((f) => !q || [f.title, f.description, f.module, f.address, f.status, f.refs]
      .some((s) => String(s || "").toLowerCase().includes(q)))
    .sort((a, b) => SEVS.indexOf(sevOf(a)) - SEVS.indexOf(sevOf(b)) || (b.updated || 0) - (a.updated || 0));
  const open = rows.map((f) => f.id).filter((id) => S.openFindings.has(id));
  if (!changed("findings", [rows, open])) return;
  const list = $("findings-list");
  if (!rows.length) {
    list.replaceChildren(h("div", { class: "empty", style: "padding:0.6rem 1rem" },
      S.findings.length ? "No findings match the filter." : "No findings yet. Agents record them with knowledge_manage."));
    return;
  }
  list.replaceChildren(...rows.map((f) => {
    const isOpen = S.openFindings.has(f.id);
    const where = [f.module, f.address].filter(Boolean).join(" @ ");
    const meta = [sevOf(f), f.status, where].filter(Boolean).join(" · ");
    return h("div", {
      class: "finding" + (isOpen ? " open" : ""), tabindex: "0", "aria-expanded": isOpen ? "true" : "false",
      onclick: () => { if (isOpen) S.openFindings.delete(f.id); else S.openFindings.add(f.id); renderFindings(); },
      onkeydown: (e) => { if (e.key === "Enter") e.currentTarget.click(); },
    },
    h("span", { class: `sev-dot sev-${sevOf(f)}`, title: sevOf(f) }),
    h("span", { class: "f-title", text: f.title || "(untitled)" }),
    h("span", { class: "f-when", title: f.updated ? new Date(f.updated * 1000).toLocaleString() : "", text: fmtWhen(f.updated || f.created) }),
    h("span", { class: "f-meta", text: meta }),
    isOpen ? h("div", { class: "f-desc", text: [f.description || "(no description)", f.refs ? `\nrefs: ${f.refs}` : ""].join("") })
      : (f.description ? h("div", { class: "f-meta", style: "font-family:var(--sans)", text: short(f.description, 160) }) : null));
  }));
}

// =========================================================================
// activity: tabs + filters
// =========================================================================
function setTab(tab) {
  if (!["calls", "events", "findings"].includes(tab)) tab = "calls";
  S.tab = tab;
  store.set("tab", tab);
  document.querySelectorAll(".tab").forEach((t) => {
    const on = t.dataset.tab === tab;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", on ? "true" : "false");
  });
  document.querySelectorAll(".pane").forEach((p) => { p.hidden = p.dataset.pane !== tab; });
  document.querySelector(".only-calls").hidden = tab !== "calls";
  $("sev-filter").hidden = tab !== "findings";
  for (const k of ["calls", "events", "findings", "sevchips"]) delete _sig[k];
  renderActive();
}
function renderActive() {
  renderCalls();
  renderEvents();
  renderFindings();
}
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => setTab(t.dataset.tab)));
$("act-filter").addEventListener("input", (e) => { S.filter = e.target.value; renderActive(); });
$("m-filter").addEventListener("input", (e) => { S.mFilter = e.target.value; renderMachines(); });
for (const [id, key] of [["f-errors", "fErrors"], ["f-destr", "fDestr"], ["f-mine", "fMine"]]) {
  $(id).addEventListener("change", (e) => { S[key] = e.target.checked; renderCalls(); });
}

document.addEventListener("keydown", (e) => {
  const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "");
  if (e.key === "Escape" && !menu.hidden) { closeMenu(); return; }
  if (e.key === "/" && !typing && !document.querySelector("dialog[open]")) {
    e.preventDefault();
    $("act-filter").focus();
  }
});

// =========================================================================
// header: live link + version
// =========================================================================
function renderLive() {
  const e = $("live");
  const views = S.machines.reduce((n, m) => n + (m.live ? m.live.length : (m.connected_views || []).length), 0);
  let cls = "off", text = "connecting…";
  if (S.apiDown) { cls = "down"; text = "orchestrator offline"; }
  else if (S.wsLive) { cls = "on"; text = views ? `live · ${plural(views, "view")}` : "live · no views"; }
  else if (S.loadedMachines) { text = "reconnecting…"; }
  e.className = `live ${cls}`;
  $("live-text").textContent = text;
}

async function loadHealth() {
  const r = await getJSON("/health");
  if (r.ok && r.data.server_version) $("ver-pill").textContent = "v" + r.data.server_version;
}

// =========================================================================
// websocket: live events + "a tool call happened" trigger
// =========================================================================
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  let ws;
  try { ws = new WebSocket(`${proto}://${location.host}/ws`); }
  catch (_) { setTimeout(connectWs, 3000); return; }
  ws.onopen = () => { S.wsLive = true; renderLive(); };
  ws.onmessage = (msg) => {
    let data;
    try { data = JSON.parse(msg.data); } catch (_) { return; }
    if (data.type !== "snapshot") return;
    if (!S.wsLive) { S.wsLive = true; renderLive(); }
    S.events = Array.isArray(data.events) ? data.events : [];
    renderEvents();
    const tl = data.toollog || [];
    const last = tl.length ? tl[tl.length - 1].ts : 0;
    if (last > S.lastToolTs) loadToollog();
  };
  ws.onclose = () => {
    S.wsLive = false;
    renderLive();
    setTimeout(connectWs, 2500);
  };
}

// =========================================================================
// polling (paused while the tab is hidden)
// =========================================================================
function every(ms, fn) {
  const tick = async () => {
    if (!document.hidden) { try { await fn(); } catch (err) { console.error(err); } }
    setTimeout(tick, ms);
  };
  setTimeout(tick, ms);
}
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) { loadMachines(); loadStatus(); loadToollog(); loadFindings(); }
});

// =========================================================================
// boot
// =========================================================================
setTab(S.tab);
renderMachines();
renderDetail();
renderLive();
loadHealth();
loadMachines().then(() => loadStatus());
loadToollog();
loadFindings();
connectWs();
every(4000, loadMachines);
every(5000, loadStatus);
every(10000, loadFindings);
every(10000, () => (S.wsLive ? null : loadToollog()));   // WS normally triggers this
every(60000, loadHealth);
