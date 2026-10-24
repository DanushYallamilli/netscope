/* NetScope dashboard - plain JavaScript, no build step. */
(() => {
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmt = (v, d = 1, unit = "") => (v === null || v === undefined || Number.isNaN(v)) ? "–" : (+v).toFixed(d) + unit;
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

const S = {
  data: null, tests: [], page: "dashboard", selected: null,
  sort: { key: "ip", desc: false }, live: null, hRange: "hour",
  cyMini: null, cyFull: null, layout: "star", charts: {},
};

const TYPE_LABEL = { router: "Router / gateway", pc: "Computer", phone: "Phone or tablet", printer: "Printer",
  camera: "Camera", iot: "Smart / IoT device", network: "Network equipment", unknown: "Unknown" };
const PORT_NAMES = { 22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 445: "SMB", 554: "RTSP", 631: "IPP", 8080: "HTTP-alt" };
const KIND_LABEL = { tcp: "TCP throughput", udp: "UDP test", lul: "Latency under load" };
const KIND_HELP = {
  tcp: ["Sends data over TCP as fast as possible and measures Mbps each second. TCP slows down when the link is congested.", "tcp"],
  udp: ["Sends numbered UDP datagrams at a fixed bitrate. The receiver counts lost and out-of-order packets and measures jitter.", "udp"],
  lul: ["Measures latency on an idle link, then again while a TCP upload fills the link. A big jump means bufferbloat.", "bufferbloat"],
};

// ---------------------------------------------------------------- utilities
async function api(path, opts = {}) {
  const o = { ...opts };
  if (o.body && typeof o.body !== "string") { o.body = JSON.stringify(o.body); o.headers = { "content-type": "application/json" }; }
  const r = await fetch(path, o);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.detail || r.statusText);
  return j;
}
function ago(ts) {
  if (!ts) return "never";
  const s = Date.now() / 1000 - ts;
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return Math.floor(s / 86400) + " d ago";
}
function toast(msg) {
  const t = document.createElement("div");
  t.className = "toast"; t.textContent = msg;
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 5000);
}
function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }
const devByKey = (k) => (S.data?.devices || []).find((d) => d.key === k);

// ---------------------------------------------------------------- theme
function applyTheme(t) {
  if (t) document.documentElement.dataset.theme = t; else delete document.documentElement.dataset.theme;
  const dark = t ? t === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
  $("#theme-btn").textContent = dark ? "Light mode" : "Dark mode";
  Chart.defaults.color = css("--muted");
  Chart.defaults.borderColor = css("--line");
  Chart.defaults.font.family = "Atkinson, system-ui, sans-serif";
  styleCy(S.cyMini); styleCy(S.cyFull);
  Object.values(S.charts).forEach((c) => { c.options.scales && Object.values(c.options.scales).forEach((sc) => { sc.grid = { color: css("--line") }; sc.ticks = { ...(sc.ticks || {}), color: css("--muted") }; }); c.update("none"); });
}
$("#theme-btn").addEventListener("click", () => {
  const dark = $("#theme-btn").textContent === "Light mode";
  const t = dark ? "light" : "dark";
  store("ns-theme", t); applyTheme(t);
});

// ---------------------------------------------------------------- learn dialog
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-learn]");
  if (!b) return;
  e.stopPropagation();
  e.preventDefault();
  const L = window.LEARN[b.dataset.learn];
  if (!L) return;
  $("#learn-title").textContent = L.title;
  $("#learn-body").innerHTML = L.body.map((p) => `<p>${esc(p)}</p>`).join("");
  $("#learn").showModal();
}, true);
$("#learn-close").addEventListener("click", () => $("#learn").close());

// ---------------------------------------------------------------- routing
function go(page) {
  S.page = page;
  $$(".page").forEach((p) => (p.hidden = p.id !== "page-" + page));
  $$(".rail a").forEach((a) => a.classList.toggle("on", a.dataset.page === page));
  if (page === "map") { ensureCy("full"); setTimeout(() => { S.cyFull.resize(); S.cyFull.fit(undefined, 40); }, 30); }
  if (page === "dashboard") { ensureCy("mini"); setTimeout(() => { S.cyMini.resize(); S.cyMini.fit(undefined, 24); }, 30); markAlertsRead(); }
  if (page === "history") loadHistory();
  if (page === "tests") loadTests();
  (window.NSPages || {})[page]?.();
}
window.addEventListener("hashchange", () => go(location.hash.slice(1) || "dashboard"));

// ---------------------------------------------------------------- data
let refreshTimer = null;
function refreshSoon() { clearTimeout(refreshTimer); refreshTimer = setTimeout(load, 300); }
async function load() {
  try { S.data = await api("/api/state"); }
  catch (e) { $("#netline").textContent = "Cannot reach the NetScope server: " + e.message; return; }
  render();
}
async function loadTests() {
  try { S.tests = await api("/api/tests?limit=60"); renderTestTable(); updateMaps(); } catch (e) { return; }
  const last = S.tests.find((t) => t.status === "done");
  if (!S.live && last && !S.tests.some((t) => t.status === "running")) showPast(last);
}

function render() {
  const d = S.data, n = d.network;
  $("#netline").innerHTML =
    `<span>Subnet <b>${esc(n.subnet)}</b></span>&ensp; <span>Gateway <b>${esc(n.gateway || "unknown")}</b></span>&ensp; <span>You <b>${esc(n.ip)}</b></span>`;
  renderScan(d.scan);
  renderDashboard();
  renderDevices();
  renderNodes();
  updateMaps();
  if (S.selected) renderSide(S.selected);
  const nw = d.summary.counts.new;
  $("#nav-new").hidden = !nw; $("#nav-new").textContent = nw;
  if (!S.settingsLoaded) { fillSettings(d.settings); S.settingsLoaded = true; }
  $("#agent-cmd").textContent = `python agent.py --server ${n.ip} --token ${d.settings.token}`;
  if (!d.devices.length && !d.scan.running) {
    $("#weakest").innerHTML = `<li><span class="grow">No devices yet. Press <b>Scan network</b> to find everything on ${esc(n.scan_subnet)}.</span></li>`;
  }
}

// ---------------------------------------------------------------- scanning
function renderScan(sc) {
  const p = $("#scan-progress"), btn = $("#scan-btn");
  btn.disabled = sc.running;
  btn.textContent = sc.running ? "Scanning…" : "Scan network";
  p.hidden = !sc.running && !sc.error;
  $("#scan-bar").style.width = (sc.running ? sc.pct : 0) + "%";
  $("#scan-msg").textContent = sc.error ? "Scan failed: " + sc.error : (sc.message || "");
}
$("#scan-btn").addEventListener("click", async () => {
  if (!S.data) return;
  if (!S.data.network.scan_allowed) { toast(S.data.network.scan_note); return; }
  if (!S.data.settings.consent) {
    $("#consent-net").textContent = S.data.network.scan_subnet;
    $("#consent").showModal();
    return;
  }
  startScan();
});
$("#consent-no").addEventListener("click", () => $("#consent").close());
$("#consent-yes").addEventListener("click", async () => {
  await api("/api/consent", { method: "POST" });
  S.data.settings.consent = true;
  $("#consent").close();
  startScan();
});
async function startScan() {
  try { await api("/api/scan", { method: "POST" }); } catch (e) { toast(e.message); }
}

// ---------------------------------------------------------------- dashboard
function renderDashboard() {
  const d = S.data, sm = d.summary, n = d.network;
  const h = sm.health;
  $("#health-num").textContent = h === null ? "–" : Math.round(h);
  const arc = $("#gauge-arc");
  arc.style.strokeDashoffset = 314.16 * (1 - (h || 0) / 100);
  arc.style.stroke = h === null ? css("--q-grey") : h >= 80 ? css("--q-green") : h >= 50 ? css("--q-amber") : css("--q-red");
  const c = sm.counts;
  $("#counts").innerHTML = [["online", "Online"], ["offline", "Offline"], ["new", "New"], ["agents", "Agents"]]
    .map(([k, l]) => `<div><b>${c[k]}</b><span>${l}</span></div>`).join("");

  const rows = [
    ["This machine", `${esc(n.hostname)}<br><span class="mono">${esc(n.ip)}</span>`],
    ["Interface", `${esc(n.interface || "–")}${n.link_speed_mbps ? `, ${n.link_speed_mbps} Mbps link` : ""}${n.mtu ? `, MTU ${n.mtu}` : ""}`],
    ["MAC", `<span class="mono">${esc(n.mac || "–")}</span>`],
    ["Subnet", `<span class="mono">${esc(n.subnet)}</span> <span class="sub">(${esc(n.netmask)})</span>${n.scan_note ? `<br><small>${esc(n.scan_note)}</small>` : ""}`],
    ["Gateway", `<span class="mono">${esc(n.gateway || "not found")}</span>`],
    ["DNS", `<span class="mono">${esc(n.dns.join(", ") || "–")}</span>`],
    ["Discovery", `${esc(d.scan.method || (n.is_admin ? "ARP scan" : "Ping sweep + ARP table"))} <button class="info" data-learn="arp" aria-label="About ARP">i</button>`],
    ["Ping engine", esc(d.ping_engine)],
    ["Last scan", esc(ago(d.scan.last_scan))],
  ];
  $("#netinfo").innerHTML = rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("");

  if (d.devices.length) {
    $("#weakest").innerHTML = sm.weakest.length ? sm.weakest.map((w) => `<li><span class="dot ${w.quality}"></span>
      <span class="grow"><button class="rowlink" data-dev="${esc(w.key)}">${esc(w.name)}</button><span class="sub mono">${esc(w.ip)}</span></span>
      <span class="num">${fmt(w.avg, 1)} ms<span class="sub">${fmt(w.loss_pct, 0)}% loss, ±${fmt(w.jitter, 1)} ms</span></span></li>`).join("")
      : `<li><span class="grow">Waiting for the first quality check…</span></li>`;
  }
  $("#alerts").innerHTML = d.alerts.length ? d.alerts.slice(0, 5).map((a) => `<li class="${a.read ? "" : "unread"}"><span class="lvl ${a.level}"></span>
      <span class="grow">${esc(a.message)}<span class="sub">${ago(a.ts)}</span></span></li>`).join("")
    : `<li><span class="grow">No alerts. NetScope reports new devices, devices going offline, poor link quality and throughput drops here.</span></li>`;
  $("#notif-btn").hidden = !("Notification" in window) || Notification.permission !== "default";
}
document.addEventListener("click", (e) => {
  const b = e.target.closest("[data-dev]");
  if (b) { S.selected = b.dataset.dev; location.hash = "map"; renderSide(S.selected); selectOnMap(S.selected); }
});
$("#notif-btn").addEventListener("click", async () => { await Notification.requestPermission(); $("#notif-btn").hidden = true; });
let readTimer = null;
function markAlertsRead() {
  clearTimeout(readTimer);
  readTimer = setTimeout(() => { if (S.page === "dashboard" && S.data?.alerts.some((a) => !a.read)) api("/api/alerts/read", { method: "POST" }); }, 4000);
}

// ---------------------------------------------------------------- network map
const ICON_PATHS = {
  router: '<rect x="4" y="14" width="24" height="9" rx="2"/><path d="M9 14V9M23 14V9M8 18.5h.01M12 18.5h.01"/><path d="M5.5 7.5a7 7 0 0 1 6 0M20.5 7.5a7 7 0 0 1 6 0"/>',
  pc: '<rect x="4" y="5" width="24" height="16" rx="2"/><path d="M12 27h8M16 21v6"/>',
  phone: '<rect x="10" y="3" width="12" height="26" rx="2.5"/><path d="M15 25h2"/>',
  printer: '<path d="M9 12V4h14v8"/><rect x="4" y="12" width="24" height="10" rx="2"/><rect x="9" y="19" width="14" height="9"/>',
  camera: '<rect x="3" y="9" width="18" height="14" rx="2"/><path d="M21 14l8-4v12l-8-4"/><circle cx="12" cy="16" r="3"/>',
  iot: '<rect x="8" y="8" width="16" height="16" rx="2"/><path d="M12 4v4M16 4v4M20 4v4M12 24v4M16 24v4M20 24v4M4 12h4M4 16h4M4 20h4M24 12h4M24 16h4M24 20h4"/>',
  network: '<rect x="3" y="11" width="26" height="10" rx="2"/><path d="M8 16h.01M12 16h.01M16 16h.01M20 16h.01M24 16h.01"/>',
  unknown: '<circle cx="16" cy="16" r="12"/><path d="M12.5 12.5a3.5 3.5 0 1 1 4.5 3.4c-.6.2-1 .8-1 1.5V19M16 23h.01"/>',
};
function iconURI(type, color) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${ICON_PATHS[type] || ICON_PATHS.unknown}</svg>`;
  return "data:image/svg+xml;utf8," + encodeURIComponent(svg);
}
function throughputByDevice() {
  const map = {}, nodes = S.data?.nodes || [];
  const devOf = (id) => id === "server" ? (S.data.devices.find((d) => d.is_self) || {}).key : (nodes.find((n) => n.id === id) || {}).device_key;
  [...S.tests].reverse().forEach((t) => {
    if (t.kind !== "tcp" || t.status !== "done" || !t.result) return;
    [devOf(t.source), devOf(t.target)].forEach((k) => { if (k) map[k] = t.result.avg_mbps; });
  });
  return map;
}
function styleCy(cy) {
  if (!cy) return;
  const qc = { green: css("--q-green"), amber: css("--q-amber"), red: css("--q-red"), grey: css("--q-grey") };
  cy.style([
    { selector: "node", style: {
      "shape": "round-rectangle", "width": 46, "height": 46, "background-color": css("--panel"),
      "border-width": 1.5, "border-color": css("--line-strong"),
      "background-image": "data(icon)", "background-width": "62%", "background-height": "62%",
      "label": "data(label)", "font-family": "Atkinson, system-ui, sans-serif", "font-size": 12, "color": css("--ink"),
      "text-valign": "bottom", "text-margin-y": 6, "text-wrap": "wrap", "text-max-width": 120,
      "text-background-color": css("--panel"), "text-background-opacity": 0.85, "text-background-padding": 2 } },
    { selector: "node.gw", style: { "width": 64, "height": 64, "border-width": 2.5, "border-color": css("--ink"), "font-weight": 700 } },
    { selector: "node.self", style: { "border-color": css("--accent"), "border-width": 3, "background-color": css("--accent-soft") } },
    { selector: "node.agent", style: { "border-color": css("--accent"), "border-width": 2.5, "border-style": "double" } },
    { selector: "node.offline", style: { "opacity": 0.45 } },
    { selector: "node.new", style: { "border-style": "dashed", "border-color": css("--accent") } },
    { selector: "node:selected", style: { "overlay-color": css("--accent"), "overlay-opacity": 0.14, "overlay-padding": 7 } },
    { selector: "edge", style: { "curve-style": "straight", "width": "data(w)", "line-color": qc.grey, "line-style": "dashed", "line-dash-pattern": [6, 5] } },
    ...["green", "amber", "red"].map((q) => ({ selector: "edge." + q, style: { "line-color": qc[q], "line-style": "solid" } })),
  ]);
  cy.nodes().forEach((n) => n.data("icon", iconURI(n.data("type"), n.hasClass("self") ? css("--accent") : css("--ink"))));
}
function ensureCy(which) {
  const k = which === "mini" ? "cyMini" : "cyFull";
  if (S[k]) return S[k];
  const cy = cytoscape({ container: $(which === "mini" ? "#cy-mini" : "#cy-full"), minZoom: 0.2, maxZoom: 3,
    userZoomingEnabled: which !== "mini", boxSelectionEnabled: false });
  S[k] = cy;
  cy.on("tap", "node", (e) => {
    const key = e.target.id();
    if (key === "__gw") return;
    S.selected = key;
    if (which === "mini") location.hash = "map";
    renderSide(key); selectOnMap(key);
  });
  styleCy(cy);
  syncCy(cy, true);
  return cy;
}
function graphElements() {
  const d = S.data;
  if (!d) return [];
  const tp = throughputByDevice();
  const devs = d.devices;
  let gw = devs.find((x) => x.is_gateway);
  const els = [];
  const gwId = gw ? gw.key : "__gw";
  if (!gw && devs.length) els.push({ group: "nodes", data: { id: "__gw", label: "Gateway\n" + (d.network.gateway || "?"), type: "router" }, classes: "gw" });
  devs.forEach((x) => {
    const cls = [x.is_gateway ? "gw" : "", x.is_self ? "self" : "", x.is_agent ? "agent" : "", x.online ? "" : "offline", x.new ? "new" : ""].join(" ");
    const name = x.is_self ? "You (" + x.name + ")" : x.name;
    els.push({ group: "nodes", data: { id: x.key, label: name === x.ip ? x.ip : name + "\n" + x.ip, type: x.type || "unknown" }, classes: cls });
    if (x.key !== gwId) {
      const mbps = tp[x.key];
      const w = mbps ? Math.min(12, 2.5 + Math.log2(1 + mbps) * 1.1) : 2.5;
      const q = x.is_self ? "green" : x.quality;
      els.push({ group: "edges", data: { id: "e:" + x.key, source: gwId, target: x.key, w }, classes: x.online ? q : "grey" });
    }
  });
  return els.filter((e) => e.group === "nodes").concat(els.filter((e) => e.group === "edges"));
}
function syncCy(cy, force) {
  if (!cy) return;
  const els = graphElements();
  const ids = new Set(els.map((e) => e.data.id));
  const before = new Set(cy.elements().map((e) => e.id()));
  let changed = force;
  cy.batch(() => {
    cy.elements().forEach((e) => { if (!ids.has(e.id())) { e.remove(); changed = true; } });
    els.forEach((e) => {
      const ex = cy.getElementById(e.data.id);
      if (ex.nonempty()) { ex.data(e.data); ex.classes(e.classes); }
      else { cy.add(e); changed = true; }
    });
  });
  cy.nodes().forEach((n) => n.data("icon", iconURI(n.data("type"), n.hasClass("self") ? css("--accent") : css("--ink"))));
  if (changed || before.size !== ids.size) runLayout(cy);
}
function runLayout(cy) {
  if (!cy || !cy.nodes().length) return;
  const name = S.layout;
  const opts = name === "grid" ? { name: "grid", avoidOverlap: true, padding: 30 }
    : name === "force" ? { name: "cose", animate: false, padding: 30, nodeRepulsion: 9000, idealEdgeLength: 110 }
    : { name: "concentric", concentric: (n) => (n.hasClass("gw") ? 2 : 1), levelWidth: () => 1, minNodeSpacing: 46, padding: 30, animate: false };
  cy.layout(opts).run();
  cy.fit(undefined, cy === S.cyMini ? 24 : 40);
}
function updateMaps() { syncCy(S.cyMini); syncCy(S.cyFull); }
function selectOnMap(key) {
  [S.cyFull, S.cyMini].forEach((cy) => { if (!cy) return; cy.$(":selected").unselect(); cy.getElementById(key).select(); });
}
$$("[data-layout]").forEach((b) => b.addEventListener("click", () => {
  $$("[data-layout]").forEach((x) => x.classList.toggle("on", x === b));
  S.layout = b.dataset.layout; runLayout(S.cyFull);
}));
$("#map-png").addEventListener("click", () => {
  const a = document.createElement("a");
  a.href = S.cyFull.png({ full: true, scale: 2, bg: css("--panel") });
  a.download = "netscope-map.png"; a.click();
});

// ---------------------------------------------------------------- device side panel
async function renderSide(key) {
  const x = devByKey(key);
  const el = $("#side");
  if (!x) { el.innerHTML = `<p class="empty">Select a device on the map to see its details and test it.</p>`; return; }
  const p = x.ping;
  const qText = { green: "Good", amber: "Fair", red: "Poor", grey: x.online ? (x.no_icmp ? "No ping reply" : "Not tested yet") : "Offline" }[x.quality];
  const ports = x.ports.length ? x.ports.map((n) => `${n} ${PORT_NAMES[n] || ""}`).join(", ") : "none of the common ports";
  el.innerHTML = `
    <h3>${esc(x.name)}</h3>
    <p class="ipline mono">${esc(x.ip)}${x.mac ? "&ensp;" + esc(x.mac) : ""}</p>
    <div class="badges">
      <span class="badge"><span class="dot ${x.is_self ? "green" : x.quality}"></span> ${x.is_self ? "This computer" : qText}</span>
      <span class="badge">${esc(TYPE_LABEL[x.type] || "Unknown")}</span>
      ${x.is_gateway ? '<span class="badge">Default gateway</span>' : ""}
      ${x.is_agent ? '<span class="badge agent">Agent</span>' : ""}
      ${x.new ? '<span class="badge new">New</span>' : ""}
    </div>
    ${x.is_self ? "" : `<div class="stats">
      <div><b>${fmt(p?.avg, 1)}</b><span>avg ms <button class="info" data-learn="rtt" aria-label="About latency">i</button></span></div>
      <div><b>${fmt(p?.jitter, 1)}</b><span>jitter ms <button class="info" data-learn="jitter" aria-label="About jitter">i</button></span></div>
      <div><b>${fmt(p?.loss_pct, 0)}%</b><span>loss <button class="info" data-learn="loss" aria-label="About packet loss">i</button></span></div>
      <div><b>${fmt(p?.min, 1)}</b><span>min ms</span></div>
      <div><b>${fmt(p?.max, 1)}</b><span>max ms</span></div>
      <div><b>${fmt(p?.jitter_rfc, 2)}</b><span>RFC 3550 jitter</span></div>
    </div>
    <p class="small">${p ? `${p.received}/${p.sent} replies, ${p.kind === "manual" ? "manual test" : "background check"} ${ago(p.ts)}` : "No ping results yet."}</p>
    <div class="actions">
      <button class="primary" id="side-ping" type="button">Run ping test</button>
      ${x.is_agent ? `<button class="ghost" id="side-tput" type="button">Throughput test</button>` : ""}
    </div>`}
    <dl class="kv">
      <dt>Vendor</dt><dd>${esc(x.vendor || "unknown")}${x.randomized_mac ? ` <button class="info" data-learn="mac" aria-label="About private MACs">i</button>` : ""}</dd>
      <dt>Hostname</dt><dd>${esc(x.hostname || "–")}</dd>
      <dt>Open ports</dt><dd>${esc(ports)} <button class="info" data-learn="ports" aria-label="About ports">i</button></dd>
      <dt>First seen</dt><dd>${esc(ago(x.first_seen))}</dd>
      <dt>Last seen</dt><dd>${x.online ? "online now" : esc(ago(x.last_seen))}</dd>
    </dl>
    ${x.is_self ? "" : `<h4>Latency, last hour</h4><div class="chartbox"><canvas id="side-chart"></canvas></div>`}
    <form class="rename" id="rename"><input name="label" placeholder="Give this device a name" value="${esc(x.label || "")}" aria-label="Device name"><button class="ghost" type="submit">Save</button></form>
    ${x.online ? "" : `<p><button class="ghost small" id="side-forget" type="button">Forget this device</button></p>`}`;
  $("#side-ping")?.addEventListener("click", async (e) => {
    const b = e.currentTarget; b.disabled = true; b.textContent = `Pinging ${S.data.settings.ping_count}×…`;
    try { const r = await api("/api/device/ping?key=" + encodeURIComponent(key), { method: "POST" }); toast(`${x.name}: ${fmt(r.stats.avg, 1)} ms avg, ${fmt(r.stats.loss_pct, 0)}% loss, ${fmt(r.stats.jitter, 1)} ms jitter`); }
    catch (err) { toast(err.message); }
    await load();
  });
  $("#side-tput")?.addEventListener("click", () => {
    const node = S.data.nodes.find((n) => n.device_key === key);
    location.hash = "tests";
    if (node) { setTimeout(() => { $("#test-form").elements.target.value = node.id; }, 50); }
  });
  $("#side-forget")?.addEventListener("click", async () => { await api("/api/device/forget?key=" + encodeURIComponent(key), { method: "POST" }); S.selected = null; load(); });
  $("#rename").addEventListener("submit", async (e) => {
    e.preventDefault();
    await api("/api/device/update", { method: "POST", body: { key, label: e.target.label.value.trim(), seen: true } });
    load();
  });
  if (x.new) api("/api/device/update", { method: "POST", body: { key, seen: true } });
  if (!x.is_self) {
    const h = await api("/api/history?range=hour&device=" + encodeURIComponent(key));
    const cv = $("#side-chart");
    if (!cv) return;
    lineChart("side", cv, [{ label: "avg ms", data: h.pings.map((r) => ({ x: r.ts * 1000, y: r.avg })), color: css("--accent") }], { legend: false });
  }
}

// ---------------------------------------------------------------- devices table
function renderDevices() {
  const f = $("#dev-filter").value.toLowerCase(), st = $("#dev-status").value;
  const sortVal = (d, k) => ({
    lat: d.ping?.avg ?? 1e9, jit: d.ping?.jitter ?? 1e9, loss: d.ping?.loss_pct ?? 1e9,
    quality: ["green", "amber", "red", "grey"].indexOf(d.quality),
    ip: d.ip.split(".").map((n) => n.padStart(3, "0")).join("."),
  }[k] ?? (typeof d[k] === "boolean" ? +d[k] : (d[k] ?? "")));
  let rows = S.data.devices.filter((d) => {
    if (st === "online" && !d.online) return false;
    if (st === "offline" && d.online) return false;
    if (st === "new" && !d.new) return false;
    if (st === "agent" && !d.is_agent) return false;
    return !f || [d.name, d.ip, d.mac, d.vendor, d.hostname].some((v) => (v || "").toLowerCase().includes(f));
  });
  const { key, desc } = S.sort;
  rows.sort((a, b) => { const x = sortVal(a, key), y = sortVal(b, key); return (x > y ? 1 : x < y ? -1 : 0) * (desc ? -1 : 1); });
  $$("#dev-table th").forEach((th) => { th.classList.toggle("sorted", th.dataset.sort === key); th.classList.toggle("desc", th.dataset.sort === key && desc); });
  $("#dev-table tbody").innerHTML = rows.map((d) => `<tr data-dev="${esc(d.key)}" class="${d.online ? "" : "offline"}">
    <td><span class="dot ${d.is_self ? "green" : d.quality}" title="${d.quality}"></span></td>
    <td><b>${esc(d.name)}</b>${d.new ? ' <span class="badge new">New</span>' : ""}${d.is_agent ? ' <span class="badge agent">Agent</span>' : ""}${d.is_self ? ' <span class="badge">You</span>' : ""}</td>
    <td class="mono">${esc(d.ip)}</td><td class="mono">${esc(d.mac || "–")}</td>
    <td>${esc(d.vendor || "–")}</td><td>${esc(TYPE_LABEL[d.type] || "Unknown")}</td>
    <td>${d.online ? (d.no_icmp ? "Online, no ping reply" : "Online") : "Offline"}</td>
    <td class="num">${d.is_self ? "–" : fmt(d.ping?.avg, 1, " ms")}</td>
    <td class="num">${d.is_self ? "–" : fmt(d.ping?.jitter, 1, " ms")}</td>
    <td class="num">${d.is_self ? "–" : fmt(d.ping?.loss_pct, 0, "%")}</td>
    <td>${d.online ? "now" : esc(ago(d.last_seen))}</td></tr>`).join("")
    || `<tr><td colspan="11" class="empty">${S.data.devices.length ? "No devices match this filter." : "No devices yet. Press Scan network to start."}</td></tr>`;
}
$("#dev-filter").addEventListener("input", renderDevices);
$("#dev-status").addEventListener("change", renderDevices);
$$("#dev-table th[data-sort]").forEach((th) => th.addEventListener("click", (e) => {
  if (e.target.closest(".info")) return;
  const k = th.dataset.sort;
  S.sort = { key: k, desc: S.sort.key === k ? !S.sort.desc : false };
  renderDevices();
}));
$("#dev-seen").addEventListener("click", async () => { await api("/api/device/update", { method: "POST", body: { seen: true } }); load(); });

// ---------------------------------------------------------------- charts
function lineChart(id, canvas, sets, o = {}) {
  S.charts[id]?.destroy();
  if (id === "live") $("#live-box").hidden = false;
  const timeAxis = o.timeAxis !== false;
  S.charts[id] = new Chart(canvas, {
    type: o.type || "line",
    data: { labels: o.labels, datasets: sets.map((s) => ({
      label: s.label, data: s.data, borderColor: s.color, backgroundColor: s.fill || s.color,
      borderWidth: 2, pointRadius: s.points ?? 0, pointHoverRadius: 4, tension: 0.25, spanGaps: s.spanGaps ?? true,
      yAxisID: s.axis || "y", borderDash: s.dash, fill: !!s.fill })) },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false, interaction: { mode: "nearest", intersect: false },
      plugins: { legend: { display: o.legend !== false, labels: { boxWidth: 14 } },
        tooltip: { callbacks: timeAxis ? { title: (it) => new Date(it[0].parsed.x).toLocaleString() } : {} } },
      scales: {
        x: timeAxis ? { type: "linear", ticks: { maxTicksLimit: 6, callback: (v) => new Date(v).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) }, grid: { color: css("--line") } }
          : { type: o.type === "bar" ? "category" : "linear", title: { display: !!o.xTitle, text: o.xTitle }, grid: { color: css("--line") }, ticks: o.type === "bar" ? {} : { stepSize: 1 } },
        y: { beginAtZero: true, title: { display: !!o.yTitle, text: o.yTitle }, grid: { color: css("--line") } },
        ...(o.y1 ? { y1: { position: "right", beginAtZero: true, title: { display: true, text: o.y1 }, grid: { display: false } } } : {}),
      },
    },
  });
  return S.charts[id];
}

// ---------------------------------------------------------------- tests
function renderNodes() {
  const nodes = S.data.nodes, f = $("#test-form");
  const opts = nodes.map((n) => `<option value="${esc(n.id)}">${esc(n.is_server ? "Server" : n.name)} – ${esc(n.ip)}${n.busy ? " (busy)" : ""}</option>`).join("");
  const sv = f.source.value, tv = f.elements.target.value;
  f.source.innerHTML = opts; f.elements.target.innerHTML = opts;
  f.source.value = nodes.some((n) => n.id === sv) ? sv : "server";
  f.elements.target.value = nodes.some((n) => n.id === tv) ? tv : (nodes.find((n) => n.id !== f.source.value)?.id || "");
  $("#test-run").disabled = nodes.length < 2 || !!S.live?.running;
  $("#agent-list").innerHTML = nodes.length > 1 ? nodes.filter((n) => !n.is_server).map((n) =>
    `<li><span class="dot ${n.busy ? "amber" : "green"}"></span><span class="grow"><b>${esc(n.name)}</b><span class="sub mono">${esc(n.ip)}</span><span class="sub">${esc(n.os || "")}</span></span><span class="num">${n.busy ? "in a test" : "ready"}</span></li>`).join("")
    : `<li><span class="grow">No agents connected yet. Start one on a second machine to run throughput tests.</span></li>`;
  if (nodes.length < 2) $("#test-err").textContent = "Connect at least one agent to run a throughput test.";
  else if ($("#test-err").textContent.startsWith("Connect")) $("#test-err").textContent = "";
  if (!S.live && S.data.running_tests.length) resumeLive(S.data.running_tests[0]);
}
function setKind() {
  const f = $("#test-form"), k = f.kind.value;
  $$(".opt", f).forEach((o) => (o.hidden = !o.classList.contains("opt-" + k)));
  const [txt, learn] = KIND_HELP[k];
  $("#kind-help").innerHTML = `<button class="info" type="button" data-learn="${learn}" aria-label="Learn more">i</button><span>${esc(txt)}${k === "tcp" ? ` <a href="#" data-learn="congestion">Why TCP backs off</a>` : ""}</span>`;
}
$("#test-form").kind.addEventListener("change", setKind);
$("#test-form").duration.addEventListener("input", (e) => (e.target.form.dur_out.value = e.target.value + " s"));
$("#test-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target;
  $("#test-err").textContent = "";
  const params = { duration: +f.duration.value, streams: +f.streams.value, direction: f.direction.value, rate_mbps: +f.rate_mbps.value, idle_seconds: 5 };
  try {
    const t = await api("/api/tests", { method: "POST", body: { kind: f.kind.value, source: f.source.value, target: f.elements.target.value, params } });
    resumeLive(t);
  } catch (err) { $("#test-err").textContent = err.message; }
});
function nodeName(id) {
  if (id === "server") return "Server";
  const n = S.data?.nodes.find((x) => x.id === id);
  return n ? n.name : id.split("@")[0];
}
function resumeLive(t) {
  S.live = { id: t.id, kind: t.kind, params: t.params, running: true, mbps: [...(t.series || [])], rtt: [], source: t.source, target: t.target };
  $("#test-run").disabled = true;
  $("#live-title").textContent = `${KIND_LABEL[t.kind]}: ${nodeName(t.source)} to ${nodeName(t.target)}`;
  $("#live-result").innerHTML = `<p class="empty">${t.kind === "lul" ? `Measuring idle latency for ${t.params.idle_seconds} s, then loading the link for ${t.params.duration} s…` : `Running for ${t.params.duration} s…`}</p>`;
  drawLive();
}
function drawLive() {
  const L = S.live;
  const sets = [{ label: "Mbps", data: L.mbps.map((v, i) => ({ x: i + 1, y: v })), color: css("--accent"), points: 3 }];
  if (L.kind === "lul") {
    // one measure per chart: while the link is loaded, plot the latency (the throughput is shown in the result)
    lineChart("live", $("#live-chart"), [{ label: "RTT under load (ms)", data: L.rtt.map((v, i) => ({ x: i + 1, y: v })), color: css("--q-amber"), points: 3 }],
      { timeAxis: false, xTitle: "second", yTitle: "ms", legend: false });
    return;
  }
  lineChart("live", $("#live-chart"), sets, { timeAxis: false, xTitle: "second", yTitle: "Mbps", legend: false });
}
function finishLive(id, result, error) {
  const L = S.live;
  if (!L || L.id !== id) { loadTests(); return; }
  L.running = false;
  if (error) { $("#live-result").innerHTML = `<p class="formerr">Test failed: ${esc(error)}</p>`; }
  else showResult(L.kind, result, L.params);
  $("#test-run").disabled = (S.data?.nodes.length || 0) < 2;
  loadTests(); refreshSoon();
}
function showResult(kind, r, p) {
  const big = (v, l) => `<div class="big"><b>${v}</b><span>${l}</span></div>`;
  let html = "", verdict = "";
  if (kind === "tcp") {
    html = big(fmt(r.avg_mbps, 1), "average Mbps") + big(fmt(Math.max(...r.series_mbps), 1), "peak Mbps") +
      big(fmt(r.bytes / 1e6, 1), "MB transferred") + big(`${r.streams} × ${r.direction === "up" ? "up" : "down"}`, "streams, direction");
    const s = r.series_mbps.filter((v) => v > 0);
    const cv = s.length > 1 ? Math.sqrt(s.reduce((a, v) => a + (v - r.avg_mbps) ** 2, 0) / s.length) / (r.avg_mbps || 1) : 0;
    verdict = cv > 0.3 ? "Throughput varied a lot from second to second. That's typical of Wi-Fi or a shared, busy link where TCP keeps backing off and ramping up again."
      : "Throughput was steady, so TCP found a stable share of the bottleneck link.";
    drawSeries([{ label: "Mbps", data: r.series_mbps, color: css("--accent") }]);
  } else if (kind === "udp") {
    html = big(fmt(r.throughput_mbps, 1), "received Mbps") + big(fmt(r.send_rate_mbps, 1), "sent Mbps") +
      big(fmt(r.loss_pct, 2) + "%", `loss (${r.lost} of ${r.sent})`) + big(fmt(r.jitter_ms, 2), "jitter ms (RFC 3550)") + big(r.out_of_order, "out of order");
    verdict = r.loss_pct > 2 ? `${fmt(r.loss_pct, 1)}% of datagrams were lost: the path couldn't carry ${r.target_rate_mbps} Mbps. UDP doesn't slow down, so the excess is simply dropped at the bottleneck queue.`
      : `The path carried ${r.target_rate_mbps} Mbps of UDP with little loss. Try a higher bitrate to find the point where loss starts.`;
    drawSeries([{ label: "Sent Mbps", data: r.series_mbps, color: css("--accent") }]);
  } else {
    const inc = r.latency_increase_ms;
    html = big(fmt(r.idle.avg, 1), "idle RTT ms") + big(fmt(r.loaded.avg, 1), "loaded RTT ms") +
      big((inc >= 0 ? "+" : "") + fmt(inc, 1), "ms added by load") + big(fmt(r.tcp?.avg_mbps, 1), "Mbps during load") +
      big(fmt(r.loaded.loss_pct, 0) + "%", "probes lost under load");
    verdict = inc === null ? "" : inc < 10 ? "Latency barely changed under load, so the queues on this path are well managed. No bufferbloat."
      : inc < 60 ? "Latency rose noticeably under load. Some buffering on the path, so video calls would degrade during big uploads."
      : "Latency rose sharply under load. This is bufferbloat: packets wait in an oversized queue. Smart queue management (fq_codel or CAKE) on the router fixes it.";
    const idle = r.rtt_series.map((s) => ({ x: s.t, y: s.phase === "idle" ? s.rtt_ms : null }));
    const load = r.rtt_series.map((s) => ({ x: s.t, y: s.phase === "loaded" ? s.rtt_ms : null }));
    lineChart("live", $("#live-chart"), [
      { label: "RTT idle (ms)", data: idle, color: css("--q-green"), points: 2, spanGaps: false },
      { label: "RTT under load (ms)", data: load, color: css("--q-amber"), points: 2, spanGaps: false }],
      { timeAxis: false, xTitle: "seconds since start", yTitle: "ms" });
  }
  $("#live-result").innerHTML = `<div class="bigrow">${html}</div><p class="verdict">${esc(verdict)}</p>`;
}
function drawSeries(sets) {
  lineChart("live", $("#live-chart"), sets.map((s) => ({ ...s, data: s.data.map((v, i) => ({ x: i + 1, y: v })), points: 3 })), { timeAxis: false, xTitle: "second", yTitle: "Mbps" });
}
function summarizeTest(t) {
  const r = t.result || {};
  if (t.status === "running") return "running…";
  if (t.status !== "done") return "failed: " + (t.error || "");
  if (t.kind === "tcp") return `${fmt(r.avg_mbps, 1)} Mbps, ${t.params.streams} stream${t.params.streams > 1 ? "s" : ""} ${t.params.direction}`;
  if (t.kind === "udp") return `${fmt(r.throughput_mbps, 1)} of ${t.params.rate_mbps} Mbps, ${fmt(r.loss_pct, 2)}% loss, ${fmt(r.jitter_ms, 2)} ms jitter, ${r.out_of_order} out of order`;
  return `idle ${fmt(r.idle?.avg, 1)} ms, loaded ${fmt(r.loaded?.avg, 1)} ms (+${fmt(r.latency_increase_ms, 1)} ms)`;
}
function renderTestTable() {
  $("#test-table tbody").innerHTML = S.tests.map((t) => `<tr data-test="${esc(t.id)}"><td>${new Date(t.ts * 1000).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}</td>
    <td>${esc(KIND_LABEL[t.kind])}</td><td>${esc(nodeName(t.source))} to ${esc(nodeName(t.target))}</td><td>${esc(summarizeTest(t))}</td></tr>`).join("")
    || `<tr><td colspan="4" class="empty">No tests yet.</td></tr>`;
}
$("#test-table").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-test]");
  if (!tr) return;
  const t = S.tests.find((x) => x.id === tr.dataset.test);
  if (!t || t.status !== "done" || (S.live && S.live.running)) return;
  showPast(t);
});
function showPast(t) {
  S.live = { id: t.id, kind: t.kind, params: t.params, running: false, mbps: [], rtt: [] };
  $("#live-title").textContent = `${KIND_LABEL[t.kind]}: ${nodeName(t.source)} to ${nodeName(t.target)}, ${new Date(t.ts * 1000).toLocaleString()}`;
  showResult(t.kind, t.result, t.params);
}

// ---------------------------------------------------------------- history
function fillHistoryDevices() {
  const sel = $("#h-device"), cur = sel.value;
  sel.innerHTML = `<option value="">All devices</option>` + (S.data?.devices || []).filter((d) => !d.is_self)
    .map((d) => `<option value="${esc(d.key)}">${esc(d.name)} (${esc(d.ip)})</option>`).join("");
  sel.value = cur;
}
async function loadHistory() {
  if (!S.data) return;
  fillHistoryDevices();
  const dev = $("#h-device").value, metric = $("#h-metric").value, mLabel = $("#h-metric").selectedOptions[0].textContent;
  const h = await api(`/api/history?range=${S.hRange}&device=${encodeURIComponent(dev)}`);
  const palette = [css("--accent"), css("--q-green"), css("--q-amber"), css("--q-red"), "#8b5cf6", "#0891b2", "#db2777", "#65a30d"];
  if (dev) {
    const sets = [{ label: mLabel, data: h.pings.map((r) => ({ x: r.ts * 1000, y: r[metric] })), color: palette[0] }];
    if (metric === "avg") {
      sets.push({ label: "min", data: h.pings.map((r) => ({ x: r.ts * 1000, y: r.min })), color: css("--line-strong"), dash: [4, 4] });
      sets.push({ label: "max", data: h.pings.map((r) => ({ x: r.ts * 1000, y: r.max })), color: css("--line-strong"), dash: [4, 4] });
    }
    lineChart("hist", $("#h-chart"), sets, { yTitle: mLabel });
    $("#h-note").textContent = h.pings.length ? `${h.pings.length} data points. Background checks run every ${S.data.settings.ping_interval_s} s.` : "No measurements in this period yet.";
    const tcp = h.tests.filter((t) => t.kind === "tcp" && t.status === "done");
    $("#h-tests-panel").hidden = !tcp.length;
    if (tcp.length) {
      const rows = [...tcp].reverse();
      lineChart("htput", $("#h-tput"), [{ label: "TCP Mbps", data: rows.map((t) => t.result.avg_mbps), color: css("--accent") }],
        { type: "bar", timeAxis: false, labels: rows.map((t) => new Date(t.ts * 1000).toLocaleString([], { dateStyle: "short", timeStyle: "short" })), yTitle: "Mbps", legend: false });
    }
  } else {
    const series = h.series.slice(0, 8);
    lineChart("hist", $("#h-chart"), series.map((s, i) => ({ label: s.name, data: s.pings.map((r) => ({ x: r.ts * 1000, y: r[metric] })), color: palette[i % palette.length] })), { yTitle: mLabel });
    $("#h-note").textContent = h.series.length > 8 ? `Showing 8 of ${h.series.length} devices. Pick one device to see its full history.` : (h.series.length ? "" : "No measurements in this period yet.");
    $("#h-tests-panel").hidden = true;
  }
}
$("#h-device").addEventListener("change", loadHistory);
$("#h-metric").addEventListener("change", loadHistory);
$$("[data-range]").forEach((b) => b.addEventListener("click", () => {
  $$("[data-range]").forEach((x) => x.classList.toggle("on", x === b));
  S.hRange = b.dataset.range; loadHistory();
}));

// ---------------------------------------------------------------- settings
function fillSettings(s) {
  const f = $("#settings-form");
  Object.entries(s).forEach(([k, v]) => { const i = f.elements[k]; if (!i) return; if (i.type === "checkbox") i.checked = !!v; else i.value = v; });
}
$("#settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, body = {};
  [...f.elements].forEach((i) => { if (!i.name) return; body[i.name] = i.type === "checkbox" ? i.checked : i.value; });
  try {
    const r = await api("/api/settings", { method: "POST", body });
    fillSettings(r.settings);
    $("#settings-msg").textContent = r.restart_needed ? "Saved. Restart NetScope for the new ports to take effect." : "Saved.";
    if (body.token !== S.data.settings.token) toast("Agent token changed. Restart each agent with the new token.");
    load();
  } catch (err) { $("#settings-msg").textContent = err.message; }
});

// ---------------------------------------------------------------- live events
function connect() {
  const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
  ws.onopen = () => { $("#conn").textContent = "live"; $("#conn").classList.add("live"); load(); loadTests(); };
  ws.onclose = () => { $("#conn").textContent = "reconnecting"; $("#conn").classList.remove("live"); setTimeout(connect, 2000); };
  ws.onmessage = (m) => {
    const e = JSON.parse(m.data);
    switch (e.type) {
      case "scan_progress": if (S.data) { S.data.scan = e; renderScan(e); } if (!e.running) refreshSoon(); break;
      case "devices_changed": refreshSoon(); if (S.page === "history") loadHistory(); break;
      case "agents": if (S.data) { S.data.nodes = e.agents; renderNodes(); } break;
      case "test_started": loadTests(); break;
      case "test_tick":
        if (S.live && S.live.id === e.test_id && S.live.running) {
          S.live.mbps.push(e.mbps); if (S.live.kind === "lul") S.live.rtt.push(e.rtt_ms);
          drawLive();
        }
        break;
      case "test_done": finishLive(e.test_id, e.result); break;
      case "test_error": finishLive(e.test_id, null, e.error); break;
      default:
        (window.NSHandlers || []).forEach((h) => { try { h(e); } catch (err) { console.warn(err); } });
        break;
      case "alert":
        toast(e.alert.message);
        if ("Notification" in window && Notification.permission === "granted" && document.hidden) new Notification("NetScope", { body: e.alert.message });
        refreshSoon();
        break;
    }
  };
  setInterval(() => { if (ws.readyState === 1) ws.send("ping"); }, 25000);
}

// ---------------------------------------------------------------- start
window.NS = { $, $$, api, esc, fmt, css, toast, ago, store, state: S, lineChart, go };
applyTheme(store("ns-theme"));
matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => applyTheme(store("ns-theme")));
setKind();
go(location.hash.slice(1) || "dashboard");
load(); loadTests();
connect();
setInterval(() => { if (S.page === "dashboard" && S.data) renderDashboard(); }, 30000);
})();
