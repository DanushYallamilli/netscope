/* NetScope: Paths (traceroute), DNS, Traffic and Connections pages. */
(() => {
"use strict";
const { $, $$, api, esc, fmt, css, toast, ago, state } = window.NS;
window.NSPages = window.NSPages || {};
window.NSHandlers = window.NSHandlers || [];
const on = (fn) => window.NSHandlers.push(fn);
const charts = {};

// Categorical slots in fixed order (validated palette); text never wears these colours.
const SLOT = (i) => css("--s" + (i + 1));
function fmtBytes(b) {
  if (b === null || b === undefined) return "–";
  if (b < 1024) return b + " B";
  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";
  if (b < 1073741824) return (b / 1048576).toFixed(1) + " MB";
  return (b / 1073741824).toFixed(2) + " GB";
}
function mbps(v) { return v === null || v === undefined ? "–" : v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2); }
function baseOpts(extra = {}) {
  return {
    responsive: true, maintainAspectRatio: false, animation: false,
    interaction: { mode: "index", intersect: false },
    plugins: { legend: { display: false, labels: { boxWidth: 12, color: css("--muted") } }, tooltip: {} },
    ...extra,
  };
}
function grid() { return { color: css("--line") }; }
function bounds(labels) { return labels.length ? { min: labels[0], max: Math.max(labels[labels.length - 1], labels[0] + 10000) } : { min: undefined, max: undefined }; }
function timeAxis(labels) {
  return { type: "linear", ...bounds(labels), grid: grid(),
    ticks: { color: css("--muted"), maxTicksLimit: 6, includeBounds: false, callback: (v) => new Date(v).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) } };
}
function chart(id, canvas, cfg) {
  charts[id]?.destroy();
  charts[id] = new Chart(canvas, cfg);
  return charts[id];
}
// Re-colour our charts when the theme changes
new MutationObserver(() => setTimeout(() => {
  Object.values(charts).forEach((c) => {
    Object.values(c.options.scales || {}).forEach((sc) => { sc.grid = grid(); sc.ticks = { ...(sc.ticks || {}), color: css("--muted") }; });
    c.update("none");
  });
  if (state.page === "connections" && CN.data) drawFSM(CN.data);
}, 30)).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

// =====================================================================
// Live bandwidth in the top bar (every page)
// =====================================================================
const BW = { hist: [], last: null };
on((e) => {
  if (e.type !== "traffic") return;
  BW.last = e.bw;
  BW.hist.push(e.bw); if (BW.hist.length > 300) BW.hist.shift();
  $("#bwline").innerHTML =
    `<span title="Download"><svg viewBox="0 0 12 12" aria-hidden="true"><path d="M6 1v9M2 6l4 4 4-4"/></svg><b>${mbps(e.bw.rx_mbps)}</b> Mbps</span>` +
    `<span title="Upload"><svg viewBox="0 0 12 12" aria-hidden="true"><path d="M6 11V2M2 6l4-4 4 4"/></svg><b>${mbps(e.bw.tx_mbps)}</b> Mbps</span>`;
  if (state.page === "traffic") trafficTick(e);
  if (e.capture) { TF.summary = e.capture; if (state.page === "traffic") renderCapture(); }
  $("#nav-rec").hidden = !(e.capture && e.capture.capture.running);
});

// =====================================================================
// PATHS - traceroute
// =====================================================================
const TR = { cur: null, recent: [], engine: null };

window.NSPages.paths = async () => {
  try {
    const r = await api("/api/traces");
    TR.recent = r.recent; TR.engine = r.engine;
    if (r.running) TR.cur = r.running;
    else if (!TR.cur && r.recent.length) TR.cur = r.recent[0];
    renderTrace(); renderRecent();
  } catch (e) { $("#trace-err").textContent = e.message; }
};
$("#trace-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#trace-err").textContent = "";
  try {
    TR.cur = await api("/api/trace", { method: "POST", body: { target: e.target.target.value } });
    renderTrace();
  } catch (err) { $("#trace-err").textContent = err.message; }
});
$$("#trace-form .chip").forEach((b) => b.addEventListener("click", () => {
  $("#trace-form").target.value = b.dataset.target;
  $("#trace-form").requestSubmit();
}));
$("#trace-stop").addEventListener("click", () => api("/api/trace/stop", { method: "POST" }));
on((e) => {
  if (e.type === "trace_started") { TR.cur = e.trace; renderTrace(); }
  else if (e.type === "trace_hop" && TR.cur && TR.cur.id === e.id) {
    TR.cur.hops = TR.cur.hops.filter((h) => h.hop !== e.hop.hop).concat([e.hop]).sort((a, b) => a.hop - b.hop);
    renderTrace();
  } else if (e.type === "trace_done") {
    if (!TR.cur || TR.cur.id === e.trace.id) TR.cur = e.trace;
    TR.recent = [e.trace, ...TR.recent.filter((t) => t.id !== e.trace.id)].slice(0, 15);
    renderTrace(); renderRecent();
  }
});

function networkColors(hops) {
  // Colour follows the network (AS): slots assigned in order of first appearance on this path
  const map = {}; let n = 0;
  hops.forEach((h) => {
    if (h.asn && !(h.asn in map)) map[h.asn] = n < 8 ? SLOT(n++) : css("--s-other");
  });
  return map;
}
function hopColor(h, asColors) {
  if (!h.ip) return "transparent";
  if (h.label === "Your router" || h.kind === "loopback") return css("--accent");
  if (h.asn && asColors[h.asn]) return asColors[h.asn];
  if (h.kind === "private" || h.kind === "cgnat") return css("--line-strong");
  return css("--s-other");
}
function renderTrace() {
  const t = TR.cur;
  const running = t && t.status === "running";
  $("#trace-btn").disabled = running;
  $("#trace-stop").hidden = !running;
  if (!t) {
    $("#trace-title").textContent = "Route";
    $("#trace-status").textContent = TR.engine ? "Method: " + TR.engine : "";
    $("#hops").innerHTML = `<li class="empty">Enter a website above to see every router between you and it.</li>`;
    return;
  }
  $("#trace-title").textContent = `Route to ${t.target}${t.target !== t.ip ? " (" + t.ip + ")" : ""}`;
  const last = t.hops[t.hops.length - 1];
  $("#trace-status").textContent = running
    ? `Tracing… hop ${last ? last.hop + 1 : 1} of up to 30. Method: ${t.engine}`
    : t.status === "error" ? "Trace failed: " + (t.error || "")
    : `${t.status === "stopped" ? "Stopped" : "Finished"} ${ago(t.ts)}. Method: ${t.engine}`;
  const asColors = networkColors(t.hops);
  const maxRtt = Math.max(1, ...t.hops.map((h) => h.max || 0));
  $("#hops").innerHTML = t.hops.map((h) => {
    const probes = h.rtts.map((r) => r === null ? `<span class="star" title="No reply">*</span>` : `<span>${r < 1 ? r.toFixed(2) : r.toFixed(r < 10 ? 1 : 0)}</span>`).join("");
    return `<li class="hop ${h.ip ? "" : "silent"} ${h.ip === t.ip ? "dest" : ""}" style="--seg:${hopColor(h, asColors)}">
      <span class="hopnum ${h.hop > 9 ? "two" : ""}">${h.hop}</span>
      <div class="hopmain">
        <div class="hopip">${h.ip ? `<b class="mono">${esc(h.ip)}</b>` : `<b>No reply</b>`}${h.hostname && h.hostname !== h.ip ? ` <span class="host">${esc(h.hostname)}</span>` : ""}</div>
        <div class="hopnet">${!h.ip ? `<span class="muted">This router didn't answer. It still forwarded the packets.</span>` : esc(h.label || "")}${h.asn ? ` <span class="muted">${h.label !== h.as_name && h.as_name ? esc(h.as_name) + ", " : ""}AS${h.asn}</span>` : ""}</div>
      </div>
      <div class="hoprtt">
        <div class="probes">${probes}<span class="unit">ms</span></div>
        <div class="rttbar"><i style="width:${h.avg ? Math.max(2, 100 * h.avg / maxRtt) : 0}%"></i></div>
      </div></li>`;
  }).join("") + (running ? `<li class="hop pending"><span class="hopnum">${last ? last.hop + 1 : 1}</span><div class="hopmain"><div class="hopnet muted">Waiting for replies…</div></div></li>` : "");

  const sm = t.summary;
  if (sm) {
    const path = sm.as_path.map((a, i) => `<li><span class="sw" style="background:${asColors[a.asn] || css("--s-other")}"></span><span><b>${esc(a.name || "AS" + a.asn)}</b><span class="sub">AS${a.asn}, from hop ${a.first_hop}</span></span></li>`).join("");
    $("#trace-summary").innerHTML = `
      <div class="bigrow">
        <div class="big"><b>${sm.hops}</b><span>hops</span></div>
        <div class="big"><b>${sm.rtt_ms !== null ? fmt(sm.rtt_ms, 1) : "–"}</b><span>ms round trip</span></div>
        <div class="big"><b>${sm.as_path.length || "–"}</b><span>networks crossed</span></div>
      </div>
      <p class="verdict">${sm.reached ? `Reached ${esc(t.target)} in ${sm.hops} hops.` : `The destination didn't answer. Some servers ignore ping, so the last router that replied is as close as traceroute can see.`}
      ${sm.silent_hops ? ` ${sm.silent_hops} router${sm.silent_hops > 1 ? "s" : ""} didn't reply (shown as *), which is normal.` : ""}</p>
      ${sm.jump ? `<p class="verdict">The biggest jump is between hop ${sm.jump.from} and hop ${sm.jump.to} (+${fmt(sm.jump.ms, 0)} ms). That's usually a long-distance link, such as a connection to another city or a submarine cable.</p>` : ""}
      ${path ? `<h4 class="subhead">Networks on the path</h4><ol class="aspath">${path}</ol>` : `<p class="small muted">${running ? "" : "Network names appear for public routers when the AS lookup succeeds."}</p>`}`;
  } else if (running) {
    $("#trace-summary").innerHTML = `<p class="empty">Waiting for the trace to finish…</p>`;
  }
  const answered = t.hops;
  chart("trace", $("#trace-chart"), {
    type: "line",
    data: { labels: answered.map((h) => h.hop), datasets: [{
      label: "Average RTT (ms)", data: answered.map((h) => h.avg), borderColor: SLOT(0), backgroundColor: SLOT(0),
      borderWidth: 2, pointRadius: 4, pointHoverRadius: 6, spanGaps: true, tension: 0 }] },
    options: baseOpts({ scales: {
      x: { title: { display: true, text: "hop", color: css("--muted") }, grid: grid(), ticks: { color: css("--muted") } },
      y: { beginAtZero: true, title: { display: true, text: "ms", color: css("--muted") }, grid: grid(), ticks: { color: css("--muted") } } },
      plugins: { legend: { display: false }, tooltip: { callbacks: { title: (it) => "Hop " + it[0].label, label: (it) => {
        const h = answered[it.dataIndex]; return `${h.ip || "no reply"}: ${it.parsed.y === null ? "–" : it.parsed.y.toFixed(1) + " ms"}`; } } } } }),
  });
}
function renderRecent() {
  $("#trace-recent").innerHTML = TR.recent.length ? TR.recent.map((t) => `<li>
    <span class="grow"><button class="rowlink" data-trace="${esc(t.id)}">${esc(t.target)}</button><span class="sub">${ago(t.ts)}${t.summary ? `, ${t.summary.hops} hops${t.summary.reached ? "" : ", not reached"}` : ""}</span></span>
    <span class="num">${t.summary && t.summary.rtt_ms !== null ? fmt(t.summary.rtt_ms, 1) + " ms" : "–"}</span></li>`).join("")
    : `<li><span class="grow muted">No traces yet.</span></li>`;
}
$("#trace-recent").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-trace]");
  if (!b) return;
  if (TR.cur && TR.cur.status === "running") return toast("Wait for the running trace to finish");
  TR.cur = await api("/api/trace/" + b.dataset.trace);
  renderTrace();
});

// =====================================================================
// DNS
// =====================================================================
const DN = { resolvers: [], skip: new Set(), custom: [], running: false, progress: {}, last: null };

window.NSPages.dns = async () => {
  try {
    const r = await api("/api/dns");
    DN.resolvers = r.resolvers; DN.running = r.running; DN.progress = r.progress;
    if (!DN.last && r.recent.length) DN.last = r.recent[0];
    renderResolvers(); renderBench();
    $("#dns-server").innerHTML = r.resolvers.map((x) => `<option value="${esc(x.ip)}">${esc(x.name)} (${esc(x.ip)})</option>`).join("");
  } catch (e) { $("#dns-err").textContent = e.message; }
};
function allResolvers() {
  return DN.resolvers.concat(DN.custom.filter((ip) => !DN.resolvers.some((r) => r.ip === ip)).map((ip) => ({ name: "Custom", ip, kind: "custom" })));
}
function renderResolvers() {
  $("#dns-resolvers").innerHTML = allResolvers().map((r) => {
    const p = DN.progress[r.ip];
    return `<label class="reschip ${DN.skip.has(r.ip) ? "off" : ""}">
      <input type="checkbox" data-ip="${esc(r.ip)}" ${DN.skip.has(r.ip) ? "" : "checked"} ${DN.running ? "disabled" : ""}>
      <span><b>${esc(r.name)}</b><span class="sub mono">${esc(r.ip)}</span></span>
      ${DN.running && p !== undefined ? `<span class="minibar"><i style="width:${p}%"></i></span>` : ""}</label>`;
  }).join("");
  $("#dns-run").disabled = DN.running;
  $("#dns-run").textContent = DN.running ? "Running…" : "Run benchmark";
}
$("#dns-resolvers").addEventListener("change", (e) => {
  const ip = e.target.dataset.ip; if (!ip) return;
  e.target.checked ? DN.skip.delete(ip) : DN.skip.add(ip);
  renderResolvers();
});
$("#dns-add").addEventListener("click", () => {
  const ip = $("#dns-custom").value.trim();
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) { $("#dns-err").textContent = "Enter an IPv4 address like 94.140.14.14"; return; }
  $("#dns-err").textContent = "";
  if (!DN.custom.includes(ip)) DN.custom.push(ip);
  $("#dns-custom").value = "";
  renderResolvers();
});
$("#dns-run").addEventListener("click", async () => {
  $("#dns-err").textContent = "";
  try {
    await api("/api/dns/bench", { method: "POST", body: { skip: [...DN.skip], custom: DN.custom } });
    DN.running = true; renderResolvers();
  } catch (e) { $("#dns-err").textContent = e.message; }
});
on((e) => {
  if (e.type === "dns_progress") { DN.progress = e.progress; DN.running = e.running; if (state.page === "dns") renderResolvers(); }
  if (e.type === "dns_done") {
    DN.running = false; DN.progress = {};
    if (e.error) $("#dns-err").textContent = "Benchmark failed: " + e.error; else DN.last = e.result;
    if (state.page === "dns") { renderResolvers(); renderBench(); }
  }
});
function renderBench() {
  const b = DN.last;
  if (!b) return;
  const rows = b.results.slice().sort((x, y) => (x.cached_ms ?? 1e9) - (y.cached_ms ?? 1e9));
  const ok = rows.filter((r) => r.reachable);
  const router = rows.find((r) => r.kind === "router");
  const fast = rows.find((r) => r.name === b.fastest);
  let verdict = "";
  if (fast) {
    verdict = `For cached lookups, ${esc(fast.name)} answered fastest from your network (median ${fmt(fast.cached_ms, 1)} ms).`;
    if (b.fastest_uncached && b.fastest_uncached !== b.fastest) verdict += ` For names nobody has looked up recently, ${esc(b.fastest_uncached)} was fastest.`;
    if (router && router.reachable && router.cached_ms !== null && fast !== router)
      verdict += ` Your router took ${fmt(router.cached_ms, 1)} ms: it forwards your lookups to your ISP's servers and caches the answers.`;
  }
  const unreachable = rows.filter((r) => !r.reachable);
  if (unreachable.length) verdict += ` ${unreachable.map((r) => esc(r.name)).join(", ")} didn't answer. Some networks (colleges, offices) block outside DNS servers.`;
  $("#dns-results").innerHTML = `
    <div class="dnscharts">
      <div><h4 class="subhead">Cached lookups, median ms</h4><div class="chartbox short"><canvas id="dns-c1"></canvas></div></div>
      <div><h4 class="subhead">Uncached lookups (full recursion), median ms</h4><div class="chartbox short"><canvas id="dns-c2"></canvas></div></div>
    </div>
    <p class="verdict">${verdict}</p>
    <div class="tablescroll"><table class="grid"><thead><tr><th>DNS server</th><th>IP</th><th class="num">Cached</th><th class="num">90th pct</th><th class="num">Uncached</th><th class="num">Answered</th><th>google.com</th></tr></thead>
    <tbody>${rows.map((r) => `<tr><td><b>${esc(r.name)}</b></td><td class="mono">${esc(r.ip)}</td>
      <td class="num">${fmt(r.cached_ms, 1, " ms")}</td><td class="num">${fmt(r.cached_p90, 1, " ms")}</td><td class="num">${fmt(r.uncached_ms, 1, " ms")}</td>
      <td class="num">${r.answered_pct === null ? "–" : fmt(r.answered_pct, 0, "%")}</td>
      <td class="mono small">${r.google && r.google.ips.length ? esc(r.google.ips.join(", ")) + ` <span class="muted">TTL ${r.google.ttl}s</span>` : "–"}</td></tr>`).join("")}</tbody></table></div>
    <p class="small muted">Ran ${ago(b.ts)}. Different servers often return different google.com addresses: big sites use DNS to send each user to a nearby data centre.</p>`;
  const hbar = (id, key) => {
    const rs = ok.filter((r) => r[key] !== null).sort((x, y) => x[key] - y[key]);
    chart(id, $("#" + id), {
      type: "bar",
      data: { labels: rs.map((r) => r.name), datasets: [{ data: rs.map((r) => r[key]), backgroundColor: SLOT(0), borderRadius: 4, borderSkipped: "start", barThickness: 14 }] },
      options: baseOpts({ indexAxis: "y", interaction: { mode: "nearest", axis: "y", intersect: false },
        scales: { x: { beginAtZero: true, grid: grid(), ticks: { color: css("--muted") } }, y: { grid: { display: false }, ticks: { color: css("--ink") } } },
        plugins: { legend: { display: false }, tooltip: { callbacks: { label: (it) => `${it.parsed.x.toFixed(1)} ms median` } } } }),
    });
  };
  hbar("dns-c1", "cached_ms"); hbar("dns-c2", "uncached_ms");
}

// Lookup inspector
$("#dns-lookup").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, out = $("#dns-lookup-out");
  out.innerHTML = `<p class="empty">Asking ${esc(f.server.value)}…</p>`;
  try {
    const r = await api(`/api/dns/lookup?name=${encodeURIComponent(f.name.value)}&type=${f.type.value}&server=${encodeURIComponent(f.server.value)}`);
    out.innerHTML = renderLookup(r);
  } catch (err) { out.innerHTML = `<p class="formerr">${esc(err.message)}</p>`; }
});
function renderLookup(r) {
  const h = r.header;
  const flag = (on, label, title) => `<span class="flag ${on ? "on" : ""}" title="${esc(title)}">${label}</span>`;
  const answers = r.records.filter((x) => x.section === "answer");
  const other = r.records.filter((x) => x.section !== "answer");
  const recRows = (list) => list.map((x) => `<tr><td class="mono">${esc(x.name)}</td><td>${esc(x.type)}</td><td class="num">${x.ttl}s</td><td class="mono wrap">${esc(x.value)}</td></tr>`).join("");
  return `
    <div class="bigrow">
      <div class="big"><b>${fmt(r.ms, 1)}</b><span>ms</span></div>
      <div class="big"><b>${esc(h.rcode_name)}</b><span>response code</span></div>
      <div class="big"><b>${r.query_bytes} / ${r.response_bytes}</b><span>bytes sent / received</span></div>
    </div>
    <p class="small">Over ${esc(r.transport)} to ${esc(r.server)} port 53.</p>
    <div class="flags">${flag(h.qr, "QR response", "This packet is a response")}${flag(h.rd, "RD recursion desired", "We asked the server to do the full lookup for us")}${flag(h.ra, "RA recursion available", "The server offers recursive lookups")}${flag(h.aa, "AA authoritative", "Set only when the answer comes from the domain's own name servers")}${flag(h.tc, "TC truncated", "The answer didn't fit in one UDP datagram")}</div>
    <h4 class="subhead">Answer section (${h.ancount})</h4>
    ${answers.length ? `<div class="tablescroll"><table class="grid"><thead><tr><th>Name</th><th>Type</th><th class="num">TTL</th><th>Value</th></tr></thead><tbody>${recRows(answers)}</tbody></table></div>` : `<p class="small muted">No answer records${h.rcode === 3 ? ": the name doesn't exist (NXDOMAIN)." : "."}</p>`}
    ${other.length ? `<h4 class="subhead">Authority and additional (${other.length})</h4><div class="tablescroll"><table class="grid"><tbody>${recRows(other)}</tbody></table></div>` : ""}
    <h4 class="subhead">The query packet NetScope sent</h4>
    ${hexDump(r.query_hex, r.segments)}`;
}
function hexDump(hex, segs) {
  const bytes = hex.match(/../g) || [];
  const segOf = (i) => (segs.find((s) => i >= s.start && i < s.end) || {}).part || "";
  let rows = "";
  for (let o = 0; o < bytes.length; o += 16) {
    const chunk = bytes.slice(o, o + 16);
    const hx = chunk.map((b, j) => `<span class="b seg-${segOf(o + j)}">${b}</span>`).join("");
    const asc = chunk.map((b, j) => { const c = parseInt(b, 16); return `<span class="seg-${segOf(o + j)}">${c >= 33 && c < 127 ? esc(String.fromCharCode(c)) : "."}</span>`; }).join("");
    rows += `<div class="hexrow"><span class="off">${o.toString(16).padStart(4, "0")}</span><span class="hx">${hx}</span><span class="asc">${asc}</span></div>`;
  }
  const n = (i) => parseInt(bytes[i] + bytes[i + 1], 16);
  const flags = n(2);
  const qtype = n(bytes.length - 4);
  return `<div class="hexdump" role="img" aria-label="Hex dump of the DNS query">${rows}</div>
    <ul class="hexlegend">
      <li><span class="sw seg-header"></span><span><b>Header, 12 bytes.</b> ID 0x${bytes[0]}${bytes[1]} (random), flags 0x${bytes[2]}${bytes[3]} (RD=${flags >> 8 & 1}), questions ${n(4)}, answers ${n(6)}, authority ${n(8)}, additional ${n(10)}</span></li>
      <li><span class="sw seg-qname"></span><span><b>Question name.</b> Each label is preceded by its length and the name ends with 00.</span></li>
      <li><span class="sw seg-qtype_qclass"></span><span><b>Type and class.</b> Type ${qtype} (${esc(Object.entries({ A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 }).find(([, v]) => v === qtype)?.[0] || "?")}), class ${n(bytes.length - 2)} (IN, the internet)</span></li>
    </ul>`;
}

// =====================================================================
// TRAFFIC
// =====================================================================
const TF = { summary: null, hist: [], groups: [] };
const GROUP_ORDER = ["HTTPS", "QUIC", "DNS", "HTTP", "Local discovery", "NetScope", "Other TCP", "Other UDP", "Other"];
const groupColor = (g) => { const i = GROUP_ORDER.indexOf(g); return i >= 0 && i < 8 ? SLOT(i) : css("--s-other"); };
const LAYER = { 2: "2 Data link", 3: "3 Network", 4: "4 Transport", 7: "7 Application" };

window.NSPages.traffic = async () => {
  try {
    const s = await api("/api/traffic");
    TF.summary = s; TF.hist = s.proto_hist || [];
    if (s.bandwidth?.length) BW.hist = s.bandwidth.slice();
    drawBw(); drawProto(); renderCapture();
  } catch (e) { $("#cap-err").textContent = e.message; }
};
function drawBw() {
  const h = BW.hist.slice(-120);
  const last = BW.last || h[h.length - 1];
  $("#bw-now").innerHTML = last ? `
    <div class="big"><b>${mbps(last.rx_mbps)}</b><span>Mbps download</span></div>
    <div class="big"><b>${mbps(last.tx_mbps)}</b><span>Mbps upload</span></div>
    <div class="big"><b>${fmt(last.rx_pps, 0)}</b><span>packets/s in</span></div>
    <div class="big"><b>${fmt(last.tx_pps, 0)}</b><span>packets/s out</span></div>` : "";
  const c = charts.bw;
  const labels = h.map((s) => s.ts * 1000);
  if (c) {
    c.data.labels = labels;
    c.data.datasets[0].data = h.map((s) => s.rx_mbps);
    c.data.datasets[1].data = h.map((s) => s.tx_mbps);
    Object.assign(c.options.scales.x, bounds(labels));
    c.update("none");
    return;
  }
  chart("bw", $("#bw-chart"), {
    type: "line",
    data: { labels, datasets: [
      { label: "Download", data: h.map((s) => s.rx_mbps), borderColor: SLOT(0), backgroundColor: SLOT(0), borderWidth: 2, pointRadius: 0, tension: 0.2 },
      { label: "Upload", data: h.map((s) => s.tx_mbps), borderColor: SLOT(1), backgroundColor: SLOT(1), borderWidth: 2, pointRadius: 0, tension: 0.2 }] },
    options: baseOpts({ scales: {
      x: timeAxis(labels),
      y: { beginAtZero: true, title: { display: true, text: "Mbps", color: css("--muted") }, grid: grid(), ticks: { color: css("--muted") } } },
      plugins: { legend: { display: true, labels: { boxWidth: 12, color: css("--muted") } },
        tooltip: { callbacks: { title: (it) => new Date(it[0].parsed.x).toLocaleTimeString(), label: (it) => `${it.dataset.label}: ${mbps(it.parsed.y)} Mbps` } } } }),
  });
}
function trafficTick(e) {
  drawBw();
  if (e.proto) { TF.hist.push(e.proto); if (TF.hist.length > 120) TF.hist.shift(); drawProto(); }
}
function drawProto() {
  const h = TF.hist;
  const seen = GROUP_ORDER.filter((g) => h.some((s) => s.groups[g]));
  const labels = h.map((s) => s.ts * 1000);
  const sets = seen.map((g) => ({ label: g, data: h.map((s) => s.groups[g] || 0), borderColor: css("--panel"), borderWidth: 1,
    backgroundColor: groupColor(g), fill: true, pointRadius: 0, tension: 0.2, stack: "s" }));
  const c = charts.proto;
  if (c && c.data.datasets.length === sets.length && c.data.datasets.every((d, i) => d.label === sets[i].label)) {
    c.data.labels = labels; c.data.datasets.forEach((d, i) => (d.data = sets[i].data));
    Object.assign(c.options.scales.x, bounds(labels)); c.update("none"); return;
  }
  chart("proto", $("#proto-chart"), {
    type: "line", data: { labels, datasets: sets },
    options: baseOpts({ scales: {
      x: timeAxis(labels),
      y: { stacked: true, beginAtZero: true, title: { display: true, text: "Mbps", color: css("--muted") }, grid: grid(), ticks: { color: css("--muted") } } },
      plugins: { legend: { display: sets.length > 0, position: "bottom", labels: { boxWidth: 12, color: css("--muted") } },
        tooltip: { callbacks: { title: (it) => new Date(it[0].parsed.x).toLocaleTimeString(), label: (it) => `${it.dataset.label}: ${mbps(it.parsed.y)} Mbps` } } } }),
  });
}
function renderCapture() {
  const s = TF.summary;
  if (!s) return;
  const cap = s.capture, running = cap.running;
  $("#cap-btn").textContent = running ? "Stop capture" : "Start capture";
  $("#cap-btn").className = running ? "ghost" : "primary";
  $("#cap-status").innerHTML = running
    ? `<span class="recdot"></span> Capturing for ${fmtTime(cap.seconds)}: ${s.total.packets.toLocaleString()} packets, ${fmtBytes(s.total.bytes)}`
    : cap.started ? `Last capture: ${s.total.packets.toLocaleString()} packets, ${fmtBytes(s.total.bytes)} over ${fmtTime(cap.seconds)}${cap.error ? ". " + esc(cap.error) : ""}`
    : (s.admin === false ? "Capture needs NetScope running as administrator." : "Not capturing.");
  const total = s.total.bytes || 1;
  $("#proto-table tbody").innerHTML = s.categories.length ? s.categories.map((c) => `<tr title="${esc(c.about)}">
    <td><span class="sw" style="background:${groupColor(c.group)}"></span> ${esc(c.name)}</td>
    <td>${LAYER[c.layer] || "–"}</td><td class="num">${c.packets.toLocaleString()}</td><td class="num">${fmtBytes(c.bytes)}</td>
    <td class="sharecell"><span class="share"><i style="width:${(100 * c.bytes / total).toFixed(1)}%"></i></span><span class="small">${(100 * c.bytes / total).toFixed(1)}%</span></td></tr>`).join("")
    : `<tr><td colspan="5" class="empty">${running ? "Waiting for packets…" : "Start a capture, then browse a website or play a video to see which protocols your computer uses."}</td></tr>`;
  $("#conv-table tbody").innerHTML = s.conversations.length ? s.conversations.map((c) => `<tr>
    <td>${c.name ? `<b>${esc(c.name)}</b>` : `<span class="muted">unknown</span>`}</td><td class="mono">${esc(c.ip)}</td><td>${esc(c.scope)}</td>
    <td class="small">${esc(c.protocols.join(", "))}</td><td class="num">${fmtBytes(c.in)}</td><td class="num">${fmtBytes(c.out)}</td></tr>`).join("")
    : `<tr><td colspan="6" class="empty">Hosts appear here during a capture. Names come from the DNS answers your computer receives.</td></tr>`;
}
function fmtTime(s) { s = Math.round(s || 0); return s < 60 ? s + " s" : Math.floor(s / 60) + " min " + (s % 60) + " s"; }
$("#cap-btn").addEventListener("click", async () => {
  $("#cap-err").textContent = "";
  const running = TF.summary?.capture.running;
  $("#cap-btn").disabled = true;
  try {
    const st = await api("/api/traffic/capture", { method: "POST", body: { action: running ? "stop" : "start" } });
    if (!running) TF.hist = [];
    TF.summary = st; renderCapture(); if (!running) drawProto();
  } catch (e) { $("#cap-err").textContent = e.message; }
  $("#cap-btn").disabled = false;
});
on((e) => { if (e.type === "capture_state") { TF.summary = e.state; $("#nav-rec").hidden = !e.state.capture.running; if (state.page === "traffic") renderCapture(); } });

// =====================================================================
// CONNECTIONS
// =====================================================================
const CN = { data: null, timer: null, stateFilter: "" };
const FSM_NODES = {
  CLOSED: [380, 46], LISTEN: [380, 140], SYN_RECV: [150, 236], SYN_SENT: [610, 236], ESTABLISHED: [380, 330],
  FIN_WAIT1: [150, 426], CLOSE_WAIT: [610, 426], FIN_WAIT2: [150, 520], CLOSING: [380, 520], LAST_ACK: [610, 520],
  TIME_WAIT: [265, 614], CLOSED_END: [610, 614],
};
const FSM_LABEL = { CLOSED_END: "CLOSED", FIN_WAIT1: "FIN_WAIT_1", FIN_WAIT2: "FIN_WAIT_2", SYN_RECV: "SYN_RECEIVED" };
const FSM_EDGES = [
  ["CLOSED", "LISTEN", "server: listen()", 8, 0, "start"],
  ["CLOSED", "SYN_SENT", "client: connect(), send SYN", 12, -8, "start"],
  ["LISTEN", "SYN_RECV", "receive SYN, send SYN+ACK", -10, -6, "end"],
  ["SYN_SENT", "ESTABLISHED", "receive SYN+ACK, send ACK", 10, 12, "start"],
  ["SYN_RECV", "ESTABLISHED", "receive ACK", -6, 14, "end"],
  ["ESTABLISHED", "FIN_WAIT1", "close(), send FIN", -10, -6, "end"],
  ["ESTABLISHED", "CLOSE_WAIT", "receive FIN, send ACK", 10, -6, "start"],
  ["FIN_WAIT1", "FIN_WAIT2", "receive ACK", -8, 0, "end"],
  ["FIN_WAIT1", "CLOSING", "receive FIN, send ACK", 12, -4, "start"],
  ["CLOSE_WAIT", "LAST_ACK", "close(), send FIN", 8, 0, "start"],
  ["FIN_WAIT2", "TIME_WAIT", "receive FIN, send ACK", -12, 4, "end"],
  ["CLOSING", "TIME_WAIT", "receive ACK", 12, 4, "start"],
  ["LAST_ACK", "CLOSED_END", "receive ACK", 8, 0, "start"],
  ["TIME_WAIT", "CLOSED_END", "wait 2 × MSL", 0, -8, "middle"],
];
const NW = 150, NH = 50;
function clip(x1, y1, x2, y2) {
  const dx = x2 - x1, dy = y2 - y1;
  const t = Math.min(dx ? (NW / 2 + 3) / Math.abs(dx) : Infinity, dy ? (NH / 2 + 3) / Math.abs(dy) : Infinity);
  return [x1 + dx * t, y1 + dy * t];
}
function drawFSM(d) {
  const counts = d.counts || {};
  const max = Math.max(1, ...Object.values(counts));
  let s = `<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="${css("--line-strong")}"/></marker></defs>`;
  s += `<line x1="-96" y1="70" x2="-96" y2="350" class="fsm-bracket"/><text x="-84" y="200" class="fsm-phase">Opening</text><text x="-84" y="216" class="fsm-phase sub">3-way</text><text x="-84" y="231" class="fsm-phase sub">handshake</text>`;
  s += `<line x1="-96" y1="400" x2="-96" y2="640" class="fsm-bracket"/><text x="-84" y="510" class="fsm-phase">Closing</text><text x="-84" y="526" class="fsm-phase sub">FIN and</text><text x="-84" y="541" class="fsm-phase sub">ACK each way</text>`;
  FSM_EDGES.forEach(([a, b, label, dx, dy, anchor]) => {
    const [x1, y1] = FSM_NODES[a], [x2, y2] = FSM_NODES[b];
    let [sx, sy] = clip(x1, y1, x2, y2);
    const [ex, ey] = clip(x2, y2, x1, y1);
    if (a === "CLOSED" && b === "SYN_SENT") { sx = x1 + NW / 2 + 3; sy = y1; }
    s += `<line x1="${sx}" y1="${sy}" x2="${ex}" y2="${ey}" class="fsm-edge" marker-end="url(#arr)"/>`;
    const mx = (sx + ex) / 2 + dx, my = (sy + ey) / 2 + dy;
    s += `<text x="${mx}" y="${my}" text-anchor="${anchor}" class="fsm-label">${esc(label)}</text>`;
  });
  Object.entries(FSM_NODES).forEach(([k, [x, y]]) => {
    const isClosed = k === "CLOSED" || k === "CLOSED_END";
    const n = isClosed ? null : (counts[k] || 0);
    const live = n > 0;
    const strength = live ? 0.25 + 0.75 * Math.sqrt(n / max) : 0;
    const sel = CN.stateFilter === k;
    s += `<g class="fsm-node ${live ? "live" : ""} ${sel ? "sel" : ""} ${isClosed ? "closed" : ""}" data-state="${isClosed ? "" : k}" tabindex="${isClosed ? -1 : 0}" role="${isClosed ? "presentation" : "button"}" aria-label="${FSM_LABEL[k] || k}: ${n ?? 0} connections">
      <rect x="${x - NW / 2}" y="${y - NH / 2}" width="${NW}" height="${NH}" rx="9" style="${live ? `fill: color-mix(in srgb, var(--accent) ${Math.round(strength * 32)}%, var(--panel))` : ""}"/>
      <text x="${x}" y="${isClosed ? y + 5 : y - 4}" text-anchor="middle" class="fsm-name">${FSM_LABEL[k] || k}</text>
      ${isClosed ? "" : `<text x="${x}" y="${y + 15}" text-anchor="middle" class="fsm-count">${n}</text>`}</g>`;
  });
  $("#fsm").innerHTML = s;
}
$("#fsm").addEventListener("click", (e) => {
  const g = e.target.closest(".fsm-node[data-state]");
  if (!g || !g.dataset.state) return;
  CN.stateFilter = CN.stateFilter === g.dataset.state ? "" : g.dataset.state;
  $("#conn-state").value = CN.stateFilter;
  renderConnections();
});
$("#fsm").addEventListener("keydown", (e) => { if ((e.key === "Enter" || e.key === " ") && e.target.closest(".fsm-node")) { e.preventDefault(); e.target.dispatchEvent(new MouseEvent("click", { bubbles: true })); } });
$("#conn-state").addEventListener("change", (e) => { CN.stateFilter = e.target.value; renderConnections(); });
$("#conn-filter").addEventListener("input", () => renderConnections());
$("#conn-scope").addEventListener("change", () => renderConnections());

async function pollConnections() {
  if (state.page !== "connections") { clearInterval(CN.timer); CN.timer = null; return; }
  try { CN.data = await api("/api/connections"); renderConnections(); $("#conn-err").textContent = CN.data.error || ""; }
  catch (e) { $("#conn-err").textContent = e.message; }
}
window.NSPages.connections = () => {
  pollConnections();
  clearInterval(CN.timer);
  CN.timer = setInterval(pollConnections, 2000);
};
function renderConnections() {
  const d = CN.data; if (!d) return;
  drawFSM(d);
  const c = d.counts;
  $("#conn-counts").innerHTML = [["ESTABLISHED", "Established"], ["LISTEN", "Listening"], ["TIME_WAIT", "Time-wait"], ["CLOSE_WAIT", "Close-wait"]]
    .map(([k, l]) => `<div><b>${c[k] || 0}</b><span>${l}</span></div>`).join("") +
    `<div><b>${d.exposed}</b><span>ports open to the network</span></div><div><b>${d.udp_total}</b><span>UDP sockets</span></div>`;
  $("#conn-procs").innerHTML = d.top_processes.length ? d.top_processes.map((p) => `<li><span class="grow">${esc(p.process)}</span><span class="num">${p.connections}</span></li>`).join("")
    : `<li><span class="grow muted">No open connections.</span></li>`;
  const sel = $("#conn-state");
  if (sel.options.length <= 1) {
    sel.innerHTML = `<option value="">All states</option>` + Object.keys(c).filter((k) => k !== "LISTEN" && k !== "CLOSE").map((k) => `<option value="${k}">${FSM_LABEL[k] || k}</option>`).join("");
    sel.value = CN.stateFilter;
  }
  const f = $("#conn-filter").value.toLowerCase(), sc = $("#conn-scope").value;
  const rows = d.tcp.filter((r) => (!CN.stateFilter || r.state === CN.stateFilter) && (!sc || r.remote_scope === sc) &&
    (!f || [r.process, r.host, r.rip, String(r.rport), String(r.lport), r.service].some((v) => (v || "").toLowerCase().includes(f))));
  $("#conn-shown").textContent = `Showing ${rows.length} of ${d.tcp_total} TCP connections${CN.stateFilter ? " in " + (FSM_LABEL[CN.stateFilter] || CN.stateFilter) : ""}`;
  $("#conn-table tbody").innerHTML = rows.slice(0, 300).map((r) => `<tr>
    <td>${esc(r.process || "–")}</td><td>${r.host ? esc(r.host) : `<span class="muted">${esc(r.remote_scope)}</span>`}</td>
    <td class="mono">${esc(r.rip)}:${r.rport}</td><td>${esc(r.service || "–")}</td><td class="mono">${r.lport}</td>
    <td><span class="state st-${r.state}">${FSM_LABEL[r.state] || r.state}</span></td></tr>`).join("")
    || `<tr><td colspan="6" class="empty">No connections match.</td></tr>`;
  const L = d.listening.concat(d.udp.slice(0, 40));
  $("#listen-table tbody").innerHTML = L.map((r) => `<tr>
    <td class="mono">${r.port}</td><td>${r.proto}</td><td>${esc(r.service || "–")}</td><td>${esc(r.process || "–")}</td>
    <td><span class="scope ${r.scope === "all interfaces" ? "open" : ""}">${esc(r.scope)}</span> <span class="small muted">${esc(r.scope_note)}</span></td></tr>`).join("")
    || `<tr><td colspan="5" class="empty">Nothing is listening.</td></tr>`;
}

// Run the hook for the page we're already on (app.js navigated before this file loaded)
window.NSPages[state.page]?.();
})();
