// Whodunnet dashboard: vanilla JS, no build step, no external requests (spec §7.2).
"use strict";

const LAYER_LABELS = {
  ok: "OK",
  inconclusive: "Not enough targets",
  wifi: "WiFi",
  home_network: "Home network",
  isp_network: "ISP network",
  isp_upstream: "Beyond the ISP",
  video_path: "Video services",
};
const VERDICT_LABELS = {
  wifi: "Your WiFi",
  home_network: "Your home network",
  isp_network: "Your ISP's network",
  isp_upstream: "Beyond your ISP's network",
  video_path: "The route to the video services",
  bufferbloat: "Lag when the line is busy (bufferbloat)",
  device_or_app: "The device or app, not the network",
  no_problem_found: "No network problem found",
  insufficient_data: "Not enough data yet",
};
const QUALIFIER_LABELS = { evening: "in the evenings", all_day: "all day", at_lag_moments: "at the moments you marked" };
const LAYERS = ["wifi", "home_network", "isp_network", "isp_upstream", "video_path"];
const EVENT_LABELS = {
  router_change: "Router change",
  package_change: "Package change",
  isp_contact: "ISP contact",
  other: "Note",
  lag: "Lag",
  system: "System",
};
const USER_KINDS = new Set(["router_change", "package_change", "isp_contact", "other"]);
const HOUR = 3600 * 1000;
const DAY = 24 * HOUR;

// ---- helpers ------------------------------------------------------------------------------------

async function api(path, options = {}) {
  const init = { ...options };
  if (init.method && init.method !== "GET") {
    init.headers = { "X-Whodunnet": "1", "Content-Type": "application/json", ...(init.headers || {}) };
  }
  const response = await fetch(path, init);
  let body = null;
  try { body = await response.json(); } catch (e) { body = null; }
  if (!response.ok) {
    throw new Error((body && body.error) || `HTTP ${response.status}`);
  }
  return body;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child == null) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function svg(tag, attrs = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, value);
  return node;
}

function nice(word) { return String(word || "").replace(/_/g, " "); }
function pct(x) { return x == null ? "–" : `${Math.round(x * 100)}%`; }
function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
function layerColor(layer) { return css(`--${layer}`) || css("--inconclusive"); }
function fmtTime(ms) {
  return new Date(ms).toLocaleString([], { weekday: "short", hour: "2-digit", minute: "2-digit" });
}
function setStatus(id, text) { document.getElementById(id).textContent = text; }
function nowMinute() { return Math.floor(Date.now() / 60000) * 60000; }

// ---- views ----------------------------------------------------------------------------------------

async function showVerdict() {
  const card = document.getElementById("verdict-card");
  const coverage = document.getElementById("coverage-card");
  let v;
  try {
    v = await api("/api/verdict");
  } catch (e) {
    card.replaceChildren(el("p", { text: `No verdict yet: ${e.message}` }));
    coverage.replaceChildren();
    return;
  }
  const title = el("p", { class: "verdict-title" },
    el("strong", { text: VERDICT_LABELS[v.verdict] || nice(v.verdict) }),
    v.qualifier ? ` — ${QUALIFIER_LABELS[v.qualifier] || nice(v.qualifier)}` : "",
    el("span", { class: `badge ${v.confidence}`, text: `${v.confidence} confidence` }));
  const parts = [title, el("p", { text: v.summary })];
  if (v.evidence.length) {
    parts.push(el("h2", { text: "Evidence" }),
      el("ul", {}, ...v.evidence.map((e) => el("li", { text: e.claim }))));
  }
  if (v.not_measurable.length) {
    parts.push(el("p", { class: "muted",
      text: `Not measurable: ${v.not_measurable.map(nice).join(", ")} (your router doesn't answer).` }));
  }
  parts.push(el("h2", { text: "Next steps" }),
    el("ul", {}, ...v.next_steps.map((s) => el("li", { text: s }))));
  if (v.missing.length) {
    parts.push(el("h2", { text: "What would make this more certain" }),
      el("ul", {}, ...v.missing.map((m) => el("li", { text: m }))));
  }
  if (v.secondary.length) {
    parts.push(el("p", { class: "muted",
      text: "Also seen: " + v.secondary.map((s) => `${nice(s.finding)} (${s.detail})`).join("; ") }));
  }
  card.replaceChildren(...parts);
  const c = v.coverage;
  coverage.replaceChildren(
    el("h2", { text: "Coverage" }),
    el("p", { text: `${c.from} → ${c.to}: ${c.evenings_covered} evenings and ${c.daytimes_covered} daytimes with data; ${c.evening_coverage_pct}% of evening time covered. Address family: IPv${v.address_family}.` }),
    el("p", { class: "muted",
      text: `Lag moments: ${v.lag.known} with data (${v.lag.network_bad} network bad, ${v.lag.network_ok} network fine), ${v.lag.unknown} without data.` }));
}

async function markLag() {
  try {
    await api("/api/lag", { method: "POST", body: "{}" });
    setStatus("lag-status", `Recorded at ${new Date().toLocaleTimeString()} ✓`);
  } catch (e) {
    setStatus("lag-status", `Couldn't record: ${e.message}`);
  }
}

async function showTimeline() {
  const days = Number(document.getElementById("timeline-range").value);
  const kindFilter = document.getElementById("timeline-kind").value;
  const to = nowMinute();
  const from = to - days * DAY;
  const chart = document.getElementById("timeline-chart");
  chart.replaceChildren(el("p", { class: "muted", text: "Loading…" }));
  let t;
  try {
    t = await api(`/api/timeline?from=${from}&to=${to}`);
  } catch (e) {
    chart.replaceChildren(el("p", { text: e.message }));
    return;
  }
  const W = 1000, left = 40, right = 10, laneH = 18, plotH = 220, wifiH = 60;
  const top = 10, layerY = top, plotY = layerY + laneH + 10, wifiY = plotY + plotH + 20;
  const H = wifiY + wifiH + 24;
  const x = (ms) => left + ((ms - from) / (to - from)) * (W - left - right);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Timeline" });

  // gaps and excluded minutes
  for (const [a, b] of t.gaps) {
    const x1 = x(Math.max(a, from)), x2 = x(Math.min(b, to));
    if (x2 > x1) root.append(svg("rect", { x: x1, y: top, width: x2 - x1, height: H - top - 20, fill: css("--gap") }));
  }
  // layer strip
  const minuteW = Math.max(1, (W - left - right) / ((to - from) / t.step));
  for (const [minute, layer] of t.layers) {
    root.append(svg("rect", { x: x(minute), y: layerY, width: minuteW + 0.3, height: laneH, fill: layerColor(layer) }));
  }
  const label = (y, text) => { const n = svg("text", { x: 2, y }); n.textContent = text; root.append(n); };
  label(layerY + 13, "layer");

  // p95 per target (log-ish scale up to 300 ms)
  const targets = t.targets.filter((tg) => kindFilter === "all" || tg.kind === kindFilter);
  const maxMs = 300;
  const y = (ms) => plotY + plotH - (Math.min(ms, maxMs) / maxMs) * plotH;
  root.append(svg("line", { x1: left, x2: W - right, y1: plotY + plotH, y2: plotY + plotH, class: "axis" }));
  for (const ms of [0, 50, 100, 200, 300]) {
    label(y(ms) + 3, `${ms}`);
    root.append(svg("line", { x1: left, x2: W - right, y1: y(ms), y2: y(ms), class: "axis", "stroke-dasharray": "2 4" }));
  }
  const palette = ["#1a73e8", "#d93025", "#188038", "#e37400", "#9334e6", "#00897b", "#c5221f", "#5f6368"];
  const legend = [];
  targets.forEach((tg, i) => {
    const rows = t.rollups[String(tg.id)] || [];
    const color = palette[i % palette.length];
    let d = "", prev = null;
    for (const [minute, sent, lost, p50, p95] of rows) {
      if (p95 == null || (prev != null && minute - prev > 2 * t.step)) { prev = null; if (p95 == null) continue; }
      d += `${prev == null ? "M" : "L"}${x(minute).toFixed(1)},${y(p95).toFixed(1)}`;
      prev = minute;
      if (lost >= 2 * (t.step / 60000)) root.append(svg("circle", { cx: x(minute), cy: plotY + plotH - 2, r: 1.6, fill: color }));
    }
    if (d) root.append(svg("path", { d, fill: "none", stroke: color, "stroke-width": 1, opacity: 0.85 }));
    legend.push(el("span", { style: `--swatch:${color}`, text: `${tg.name} (IPv${tg.af})` }));
  });
  label(plotY + plotH + 14, "p95 ms ↑");

  // WiFi signal
  const ry = (rssi) => wifiY + wifiH - ((Math.max(-90, Math.min(-30, rssi)) + 90) / 60) * wifiH;
  let wd = "";
  for (const [ts, rssi] of t.wifi) if (rssi != null) wd += `${wd ? "L" : "M"}${x(ts).toFixed(1)},${ry(rssi).toFixed(1)}`;
  if (wd) root.append(svg("path", { d: wd, fill: "none", stroke: css("--wifi"), "stroke-width": 1.5 }));
  label(wifiY + 10, "WiFi dBm");

  // events and lag markers
  for (const e of t.events) {
    const color = e.kind === "lag" ? css("--lag") : css("--muted");
    root.append(svg("line", { x1: x(e.ts), x2: x(e.ts), y1: top, y2: H - 20, stroke: color, "stroke-width": e.kind === "lag" ? 1.5 : 1, "stroke-dasharray": e.kind === "lag" ? "" : "3 3" }));
  }
  // time axis
  const step = days > 1 ? DAY : 3 * HOUR;
  for (let ms = Math.ceil(from / step) * step; ms <= to; ms += step) {
    const n = svg("text", { x: x(ms), y: H - 6, "text-anchor": "middle" });
    n.textContent = days > 1 ? new Date(ms).toLocaleDateString([], { weekday: "short", day: "numeric" })
      : new Date(ms).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    root.append(n);
  }
  chart.replaceChildren(root);
  document.getElementById("timeline-legend").replaceChildren(
    ...["ok", ...LAYERS, "inconclusive"].map((l) => el("span", { style: `--swatch:${layerColor(l)}`, text: LAYER_LABELS[l] })),
    el("span", { style: `--swatch:${css("--lag")}`, text: "Lag moment" }),
    el("span", { style: `--swatch:${css("--gap")}`, text: "No data" }),
    ...legend);
}

async function showHeatmap() {
  const metric = document.getElementById("heatmap-metric").value;
  const days = Number(document.getElementById("heatmap-days").value);
  const to = nowMinute();
  const box = document.getElementById("heatmap-grid");
  let h;
  try {
    h = await api(`/api/heatmap?metric=${metric}&from=${to - days * DAY}&to=${to}`);
  } catch (e) {
    box.replaceChildren(el("p", { text: e.message }));
    return;
  }
  const all = h.values.flat().filter((v) => v != null);
  const max = metric === "layer_rate" || metric === "loss" ? Math.max(0.2, ...all) : Math.max(1, ...all);
  const good = metric === "download";
  const color = (v) => {
    if (v == null) return "transparent";
    const k = Math.min(1, v / max);
    const bad = good ? 1 - k : k;
    return `hsl(${Math.round(120 - 120 * bad)}, 70%, ${Math.round(50 + 10 * (1 - bad))}%)`;
  };
  const fmt = (v) => v == null ? "no data"
    : metric === "layer_rate" || metric === "loss" ? pct(v) : `${Math.round(v)}`;
  const head = el("tr", {}, el("th"), ...h.hours.map((hr) => el("th", { text: hr % 3 === 0 ? String(hr) : "" })));
  const rows = h.days.map((day, i) => el("tr", {},
    el("th", { text: day.slice(5) }),
    ...h.values[i].map((v, hr) => el("td", { style: `background:${color(v)}`, title: `${day} ${hr}:00 — ${fmt(v)}` }))));
  box.replaceChildren(h.days.length
    ? el("div", { class: "scroll" }, el("table", {}, el("thead", {}, head), el("tbody", {}, ...rows)))
    : el("p", { class: "muted", text: "No data in this range yet." }));
}

async function showCompare() {
  const box = document.getElementById("compare-tables");
  let c;
  try {
    c = await api("/api/compare");
  } catch (e) {
    box.replaceChildren(el("p", { text: e.message }));
    return;
  }
  const tables = Object.entries(c.families).map(([af, layers]) => {
    const rows = LAYERS.map((layer) => {
      const r = layers[layer];
      return el("tr", {},
        el("td", { text: LAYER_LABELS[layer] }),
        el("td", { class: "num", text: pct(r.evening_rate) }),
        el("td", { class: "num", text: pct(r.daytime_rate) }),
        el("td", { class: "num", text: `${r.evenings_shown} / ${r.evenings_covered}` }),
        el("td", { class: "num", text: `${r.daytimes_shown} / ${r.daytimes_covered}` }));
    });
    return el("div", {},
      el("h2", { text: `IPv${af}${Number(af) === c.address_family ? " (used for the verdict)" : ""}` }),
      el("table", { class: "compare" },
        el("thead", {}, el("tr", {}, el("th", { text: "Layer" }), el("th", { text: "Evening" }),
          el("th", { text: "Daytime" }), el("th", { text: "Evenings ≥ 5%" }), el("th", { text: "Daytimes ≥ 5%" }))),
        el("tbody", {}, ...rows)));
  });
  box.replaceChildren(...(tables.length ? tables : [el("p", { class: "muted", text: "No data yet." })]));
}

async function showEvents() {
  const list = document.getElementById("event-list");
  const to = Date.now() + DAY;
  let events;
  try {
    events = await api(`/api/events?from=${to - 365 * DAY}&to=${to}`);
  } catch (e) {
    list.replaceChildren(el("li", { text: e.message }));
    return;
  }
  events.sort((a, b) => b.ts - a.ts);
  list.replaceChildren(...events.map((e) => el("li", {},
    el("span", {}, el("strong", { text: EVENT_LABELS[e.kind] || e.kind }), ` · ${fmtTime(e.ts)}`, e.note ? ` — ${e.note}` : ""),
    USER_KINDS.has(e.kind)
      ? el("button", { class: "secondary", type: "button", text: "Delete", onclick: async () => {
          await api(`/api/events/${e.id}`, { method: "DELETE" });
          showEvents();
        } })
      : null)));
  if (!events.length) list.replaceChildren(el("li", { class: "muted", text: "No events yet." }));
}

async function addEvent(evt) {
  evt.preventDefault();
  const when = document.getElementById("event-when").value;
  const body = { kind: document.getElementById("event-kind").value, note: document.getElementById("event-note").value };
  if (when) body.ts = new Date(when).getTime();
  try {
    await api("/api/events", { method: "POST", body: JSON.stringify(body) });
    setStatus("event-status", "Added ✓");
    document.getElementById("event-note").value = "";
    showEvents();
  } catch (e) {
    setStatus("event-status", e.message);
  }
}

// The tab is opened before the fetch, while the click still counts as a user gesture (Safari
// blocks pop-ups opened after an await); the report then loads into it as a blob URL.
async function makeReport(evt) {
  evt.preventDefault();
  const from = document.getElementById("report-from").value;
  const to = document.getElementById("report-to").value;
  if (!from || !to) { setStatus("report-status", "Choose both dates."); return; }
  const tab = window.open("", "_blank");
  setStatus("report-status", "Creating the report…");
  let response;
  try {
    response = await fetch(`/api/report?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
  } catch (e) {
    if (tab) tab.close();
    setStatus("report-status", "Couldn't reach the collector.");
    return;
  }
  if (!response.ok) {
    if (tab) tab.close();
    let message = `HTTP ${response.status}`;
    try { message = (await response.json()).error; } catch (e) { /* keep status */ }
    setStatus("report-status", message);
    return;
  }
  const url = URL.createObjectURL(new Blob([await response.text()], { type: "text/html" }));
  if (tab) {
    tab.location.href = url;
    setStatus("report-status", "Opened in a new tab — use Print → Save as PDF to keep a copy.");
  } else {
    const link = el("a", { href: url, target: "_blank", text: "Open the report" });
    document.getElementById("report-status").replaceChildren(link);
  }
}

async function showSettings() {
  let s;
  try {
    s = await api("/api/settings");
  } catch (e) {
    setStatus("settings-status", e.message);
    return;
  }
  document.getElementById("lan-access").checked = s.lan_access;
  const link = document.getElementById("phone-link");
  link.textContent = s.lan_access
    ? (s.phone_url ? `Open this link on your phone (same WiFi): ${s.phone_url}` : "The phone link appears once the collector knows this Mac's name.")
    : "Turn this on to get a link for your phone.";
  const setup = document.getElementById("phone-setup");
  setup.hidden = !(s.lan_access && s.phone_url);
  if (!setup.hidden) document.getElementById("phone-qr").replaceChildren(qrSvg(s.phone_url));
  document.getElementById("doctor-list").replaceChildren(...(s.doctor.length ? s.doctor.map((d) =>
    el("li", { class: `status-${d.status}` }, d.message, d.fix && (d.status === "warn" || d.status === "fail") ? el("span", { class: "fix", text: d.fix }) : null))
    : [el("li", { class: "muted", text: "The collector hasn't run its checks yet." })]));
}

// The QR code is drawn as dark squares on a white quiet zone so phone cameras read it in dark mode.
function qrSvg(text) {
  const code = qrcode(0, "M");
  code.addData(text);
  code.make();
  const n = code.getModuleCount();
  const quiet = 4;
  const size = n + 2 * quiet;
  const root = svg("svg", { viewBox: `0 0 ${size} ${size}`, "shape-rendering": "crispEdges" });
  root.append(svg("rect", { width: size, height: size, fill: "#fff" }));
  let path = "";
  for (let row = 0; row < n; row++) {
    for (let col = 0; col < n; col++) {
      if (code.isDark(row, col)) path += `M${col + quiet} ${row + quiet}h1v1h-1z`;
    }
  }
  root.append(svg("path", { d: path, fill: "#000" }));
  return root;
}

async function updateSettings(body) {
  try {
    await api("/api/settings", { method: "POST", body: JSON.stringify(body) });
    setStatus("settings-status", "Saved ✓");
    setTimeout(showSettings, 600);
  } catch (e) {
    setStatus("settings-status", e.message);
  }
}

// ---- routing ---------------------------------------------------------------------------------------

const VIEWS = {
  verdict: showVerdict,
  timeline: showTimeline,
  heatmap: showHeatmap,
  compare: showCompare,
  events: showEvents,
  report: () => {},
  settings: showSettings,
};

function route() {
  const name = (location.hash || "#verdict").slice(1);
  const view = VIEWS[name] ? name : "verdict";
  for (const section of document.querySelectorAll(".view")) section.hidden = section.id !== `view-${view}`;
  for (const a of document.querySelectorAll("#tabs a")) a.classList.toggle("active", a.getAttribute("href") === `#${view}`);
  VIEWS[view]();
}

function init() {
  document.getElementById("lag-button").addEventListener("click", markLag);
  document.getElementById("timeline-range").addEventListener("change", showTimeline);
  document.getElementById("timeline-kind").addEventListener("change", showTimeline);
  document.getElementById("heatmap-metric").addEventListener("change", showHeatmap);
  document.getElementById("heatmap-days").addEventListener("change", showHeatmap);
  document.getElementById("event-form").addEventListener("submit", addEvent);
  document.getElementById("report-form").addEventListener("submit", makeReport);
  document.getElementById("lan-access").addEventListener("change", (e) => updateSettings({ lan_access: e.target.checked }));
  document.getElementById("regenerate-token").addEventListener("click", () => updateSettings({ regenerate_token: true }));
  const today = new Date();
  const weekAgo = new Date(today.getTime() - 6 * DAY);
  const iso = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
  document.getElementById("report-from").value = iso(weekAgo);
  document.getElementById("report-to").value = iso(today);
  window.addEventListener("hashchange", route);
  route();
}

init();
