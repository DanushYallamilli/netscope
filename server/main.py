"""
NetScope server: FastAPI app, REST API, WebSocket and background jobs.

Start it with `python run.py` from the project folder.
"""

import asyncio
import concurrent.futures as cf
import csv
import html
import io
import os
import sys
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import discovery, dnsbench, dnsclient, quality
from .connections import ConnectionMonitor
from .db import DB
from .events import events
from .tests_coord import Coordinator, TEST_KINDS, engine
from .traceroute import Tracer
from .traffic import TrafficMonitor

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")

db = DB()
_info = {"v": None, "ts": 0}


def get_info(refresh=False):
    if refresh or _info["v"] is None or time.time() - _info["ts"] > 300:
        _info["v"], _info["ts"] = discovery.network_info(), time.time()
    return _info["v"]


coord = Coordinator(db, get_info)
scan_state = {"running": False, "stage": None, "pct": 0, "message": None,
              "last_scan": None, "method": None, "error": None}
breaches = {}           # device key -> consecutive bad background checks
pool = cf.ThreadPoolExecutor(48)
data_server = None
tracer = Tracer(db, events.emit, get_info)
traffic = TrafficMonitor(get_info, events.emit, discovery.is_admin)
conns = ConnectionMonitor(traffic.name_for)
dns_state = {"running": False, "progress": {}, "error": None}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def thresholds():
    s = db.settings()
    return {k: float(s[k]) for k in ("green_latency", "amber_latency", "green_loss", "amber_loss")}


def display_name(d):
    if d.get("label") or d.get("agent_name") or d.get("hostname"):
        return d.get("label") or d.get("agent_name") or d.get("hostname")
    if d.get("is_gateway"):
        return "Router / gateway"
    v = d.get("vendor")
    if v and not v.startswith("Private"):
        return "%s device" % v.split()[0]
    return d["ip"]


def enriched_devices():
    th = thresholds()
    latest = db.latest_pings()
    out = []
    for d in db.devices():
        p = latest.get(d["key"])
        d["name"] = display_name(d)
        d["ping"] = p
        d["quality"] = quality.classify(p, th) if d["online"] else "grey"
        d["no_icmp"] = bool(d["online"] and p and p["received"] == 0)
        out.append(d)
    out.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
    return out


def summary(devs=None):
    devs = devs if devs is not None else enriched_devices()
    online = [d for d in devs if d["online"]]
    measured = [d["ping"] for d in online if d["ping"] and not d["is_self"]]
    hs = quality.health_score(measured, len(online), len(devs))
    weakest = sorted([d for d in online if d["ping"] and d["ping"]["avg"] is not None and not d["is_self"]],
                     key=lambda d: quality.latency_score(d["ping"]["avg"])
                     + quality.loss_score(d["ping"]["loss_pct"]) - (d["ping"]["avg"] or 0) / 1000)[:5]
    return {
        "health": hs,
        "counts": {"total": len(devs), "online": len(online),
                   "offline": len(devs) - len(online),
                   "new": sum(1 for d in devs if d["new"]),
                   "agents": sum(1 for d in devs if d["is_agent"])},
        "weakest": [{"key": d["key"], "name": d["name"], "ip": d["ip"], "quality": d["quality"],
                     "avg": d["ping"]["avg"], "loss_pct": d["ping"]["loss_pct"],
                     "jitter": d["ping"]["jitter"]} for d in weakest],
    }


def alert(level, kind, message, key=None):
    a = db.add_alert(level, kind, message, key)
    events.emit({"type": "alert", "alert": a})


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------

def _progress(stage, pct, msg):
    scan_state.update(stage=stage, pct=pct, message=msg)
    events.emit({"type": "scan_progress", **scan_state})


async def run_scan():
    if scan_state["running"]:
        return
    if not db.settings()["consent"]:
        raise HTTPException(403, "Please confirm you have permission to scan this network first.")
    scan_state.update(running=True, error=None, pct=0, stage="start", message="Starting scan...")
    events.emit({"type": "scan_progress", **scan_state})
    try:
        info = get_info(refresh=True)
        loop = asyncio.get_running_loop()
        found, method = await loop.run_in_executor(
            pool, lambda: discovery.scan(info, _progress, db.settings()["check_ports"]))
        first_scan = not db.devices()
        new, gone = db.upsert_scan(found)
        # agents stay flagged
        for a in coord.agents.values():
            db.upsert_agent_device(a["ip"], a["name"], a["hostname"])
        if not first_scan:
            for d in new:
                if d.get("is_self") or d.get("is_gateway"):
                    continue
                alert("info", "new_device", "New device joined: %s (%s%s)" % (
                    display_name(d), d["ip"],
                    ", " + d["mac"] if d.get("mac") else ""), db.key_for(d["ip"], d.get("mac")))
        for d in gone:
            alert("warning", "offline", "Device went offline: %s (%s)" % (display_name(d), d["ip"]), d["key"])
        scan_state.update(last_scan=time.time(), method=method)
        # quick quality check of everything we just found
        asyncio.create_task(ping_all())
    except Exception as e:
        scan_state["error"] = str(e)
    finally:
        scan_state.update(running=False)
        events.emit({"type": "scan_progress", **scan_state})
        events.emit({"type": "devices_changed"})


# ---------------------------------------------------------------------------
# Background quality checks
# ---------------------------------------------------------------------------

async def ping_all():
    s = db.settings()
    th = thresholds()
    devs = [d for d in db.devices() if d["online"] and not d["is_self"]]
    if not devs:
        return
    loop = asyncio.get_running_loop()
    count = int(s["bg_ping_count"])
    results = await asyncio.gather(*[
        loop.run_in_executor(pool, quality.ping_host, d["ip"], count, 0.2, 1.0) for d in devs])
    for d, st in zip(devs, results):
        db.add_ping(d["key"], st, "bg")
        c = quality.classify(st, th)
        if c == "red":
            breaches[d["key"]] = breaches.get(d["key"], 0) + 1
            if breaches[d["key"]] == 3:
                alert("warning", "threshold",
                      "%s (%s) has had poor quality for 3 checks in a row: %s ms avg, %s%% loss" % (
                          display_name(d), d["ip"],
                          "-" if st["avg"] is None else round(st["avg"], 1), st["loss_pct"]), d["key"])
        else:
            breaches[d["key"]] = 0
    events.emit({"type": "devices_changed"})


async def scheduler():
    last_scan = 0.0
    last_ping = 0.0
    last_prune = 0.0
    while True:
        await asyncio.sleep(5)
        s = db.settings()
        now = time.time()
        try:
            if s["consent"] and now - last_scan > float(s["scan_interval_min"]) * 60:
                if scan_state["last_scan"] and now - scan_state["last_scan"] < float(s["scan_interval_min"]) * 60:
                    last_scan = scan_state["last_scan"]
                else:
                    last_scan = now
                    await run_scan()
            if now - last_ping > float(s["ping_interval_s"]) and not scan_state["running"]:
                last_ping = now
                await ping_all()
            if now - last_prune > 3600:
                last_prune = now
                db.prune(float(s["retention_days"]))
        except Exception as e:
            print("[scheduler]", e)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app):
    global data_server
    events.bind(asyncio.get_running_loop())
    s = db.settings()
    get_info(refresh=True)
    db.x("UPDATE devices SET is_agent=0")
    try:
        await coord.start(int(s["control_port"]))
    except OSError as e:
        print("[netscope] could not open control port %s: %s" % (s["control_port"], e))
    try:
        data_server = engine.DataServer(s["token"], int(s["data_port"]), name="NetScope server")
        data_server.start()
    except OSError as e:
        print("[netscope] could not open data port %s: %s" % (s["data_port"], e))
    traffic.start()
    task = asyncio.create_task(scheduler())
    yield
    task.cancel()
    traffic.stop_capture()


app = FastAPI(title="NetScope", lifespan=lifespan)


@app.get("/api/state")
def api_state():
    devs = enriched_devices()
    s = db.settings()
    return {
        "network": get_info(),
        "devices": devs,
        "summary": summary(devs),
        "scan": scan_state,
        "nodes": coord.nodes(),
        "alerts": db.alerts(20),
        "settings": s,
        "thresholds": thresholds(),
        "ping_engine": quality.ping_engine_name(),
        "test_kinds": TEST_KINDS,
        "running_tests": list(coord.running.values()),
    }


@app.post("/api/consent")
def api_consent():
    db.save_settings({"consent": True})
    return {"ok": True}


@app.post("/api/scan")
async def api_scan():
    if scan_state["running"]:
        return {"ok": True, "already_running": True}
    if not db.settings()["consent"]:
        raise HTTPException(403, "Please confirm you have permission to scan this network first.")
    asyncio.create_task(run_scan())
    return {"ok": True}


@app.post("/api/device/ping")
async def api_ping(key: str):
    d = db.device(key)
    if not d:
        raise HTTPException(404, "Unknown device")
    s = db.settings()
    loop = asyncio.get_running_loop()
    st = await loop.run_in_executor(pool, quality.ping_host, d["ip"], int(s["ping_count"]), 0.2, 1.0)
    db.add_ping(key, st, "manual")
    events.emit({"type": "devices_changed"})
    return {"stats": st, "quality": quality.classify(st, thresholds()), "engine": quality.ping_engine_name()}


@app.post("/api/device/update")
async def api_device_update(request: Request):
    b = await request.json()
    if "label" in b:
        db.rename(b["key"], b["label"])
    if b.get("seen"):
        db.clear_new(b.get("key"))
    events.emit({"type": "devices_changed"})
    return {"ok": True}


@app.post("/api/device/forget")
def api_forget(key: str):
    db.forget(key)
    events.emit({"type": "devices_changed"})
    return {"ok": True}


RANGES = {"hour": 3600, "day": 86400, "week": 7 * 86400}


def _bucket(rows, span, n=240):
    """Average rows into at most n time buckets so long ranges stay light."""
    if len(rows) <= n:
        return rows
    size = span / n
    out, cur, start = [], [], None
    for r in rows:
        b = int(r["ts"] // size)
        if start is None:
            start = b
        if b != start and cur:
            out.append(_avg(cur))
            cur, start = [], b
        cur.append(r)
    if cur:
        out.append(_avg(cur))
    return out


def _avg(rows):
    o = {"ts": sum(r["ts"] for r in rows) / len(rows)}
    for k in ("avg", "min", "max", "median", "jitter", "jitter_rfc", "loss_pct"):
        v = [r[k] for r in rows if r[k] is not None]
        o[k] = round(sum(v) / len(v), 3) if v else None
    o["sent"] = sum(r["sent"] for r in rows)
    o["received"] = sum(r["received"] for r in rows)
    return o


@app.get("/api/history")
def api_history(device: str = "", range: str = "hour"):
    span = RANGES.get(range, 3600)
    since = time.time() - span
    if device:
        rows = _bucket(db.ping_history(device, since), span)
        tests = [t for t in db.tests(200, since) if t["target_device"] == device or
                 (t["source"] != "server" and coord.agents.get(t["source"], {}).get("device_key") == device)]
        return {"pings": rows, "tests": tests}
    devs = {d["key"]: display_name(d) for d in db.devices()}
    by = {}
    for r in db.ping_history(None, since):
        by.setdefault(r["device_key"], []).append(r)
    return {"series": [{"key": k, "name": devs.get(k, k), "pings": _bucket(v, span, 120)}
                       for k, v in by.items() if k in devs]}


@app.get("/api/settings")
def api_settings():
    return db.settings()


@app.post("/api/settings")
async def api_save_settings(request: Request):
    b = await request.json()
    cur = db.settings()
    clean = {}
    num = {"scan_interval_min": (1, 1440), "ping_interval_s": (15, 3600), "ping_count": (3, 100),
           "bg_ping_count": (1, 20), "green_latency": (1, 1000), "amber_latency": (2, 5000),
           "green_loss": (0, 100), "amber_loss": (0, 100), "retention_days": (1, 365),
           "control_port": (1024, 65535), "data_port": (1024, 65535)}
    for k, (lo, hi) in num.items():
        if k in b:
            try:
                clean[k] = max(lo, min(hi, float(b[k])))
                if k.endswith("_port") or k in ("ping_count", "bg_ping_count"):
                    clean[k] = int(clean[k])
            except (TypeError, ValueError):
                raise HTTPException(400, "Invalid value for %s" % k)
    if "check_ports" in b:
        clean["check_ports"] = bool(b["check_ports"])
    if b.get("token") and b["token"] != cur["token"]:
        t = str(b["token"]).strip()
        if len(t) < 6:
            raise HTTPException(400, "Token must be at least 6 characters")
        clean["token"] = t
    s = db.save_settings(clean)
    restart = any(k in clean and clean[k] != cur[k] for k in ("control_port", "data_port", "token"))
    if "token" in clean and data_server:
        data_server.token = clean["token"]
        restart = any(k in clean and clean[k] != cur[k] for k in ("control_port", "data_port"))
    events.emit({"type": "devices_changed"})
    return {"settings": s, "restart_needed": restart}


@app.get("/api/nodes")
def api_nodes():
    return coord.nodes()


@app.post("/api/tests")
async def api_start_test(request: Request):
    b = await request.json()
    try:
        return await coord.start_test(b.get("kind"), b.get("source"), b.get("target"), b.get("params") or {})
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/tests")
def api_tests(limit: int = 50):
    return db.tests(limit)


@app.post("/api/alerts/read")
def api_alerts_read():
    db.read_alerts()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Traceroute
# ---------------------------------------------------------------------------

@app.post("/api/trace")
async def api_trace(request: Request):
    b = await request.json()
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(pool, tracer.start, str(b.get("target", "")))
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/api/trace/stop")
def api_trace_stop():
    tracer.cancel()
    return {"ok": True}


@app.get("/api/traces")
def api_traces():
    cur = tracer.current if tracer.current and tracer.current["status"] == "running" else None
    eng = tracer.engine()[1]
    return {"running": cur, "recent": db.traces(15), "engine": eng}


@app.get("/api/trace/{tid}")
def api_trace_get(tid: str):
    t = db.trace(tid)
    if not t:
        raise HTTPException(404, "Unknown trace")
    return t


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _valid_ipv4(ip):
    import ipaddress
    try:
        a = ipaddress.IPv4Address(ip.strip())
    except Exception:
        return None
    if a.is_multicast or a.is_unspecified or a.is_reserved:
        return None
    return str(a)


@app.get("/api/dns")
def api_dns():
    info = get_info()
    return {"resolvers": dnsbench.resolver_list(info.get("dns"), info.get("gateway")),
            "running": dns_state["running"], "progress": dns_state["progress"],
            "recent": db.dns_benches(5), "popular": dnsbench.POPULAR}


@app.post("/api/dns/bench")
async def api_dns_bench(request: Request):
    if dns_state["running"]:
        raise HTTPException(400, "A benchmark is already running")
    b = await request.json()
    extra = [ip for ip in (_valid_ipv4(x) for x in (b.get("custom") or [])[:3]) if ip]
    info = get_info()
    resolvers = dnsbench.resolver_list(info.get("dns"), info.get("gateway"), extra)
    skip = set(b.get("skip") or [])
    resolvers = [r for r in resolvers if r["ip"] not in skip]
    if not resolvers:
        raise HTTPException(400, "Choose at least one resolver")
    dns_state.update(running=True, error=None, progress={r["ip"]: 0 for r in resolvers})
    events.emit({"type": "dns_progress", "progress": dns_state["progress"], "running": True})

    def progress(r, done, steps):
        dns_state["progress"][r["ip"]] = round(100 * done / steps)
        events.emit({"type": "dns_progress", "progress": dns_state["progress"], "running": True})

    async def run():
        loop = asyncio.get_running_loop()
        try:
            res = await loop.run_in_executor(pool, dnsbench.run, resolvers, progress)
            db.add_dns_bench(res)
            events.emit({"type": "dns_done", "result": res})
        except Exception as e:
            dns_state["error"] = str(e)
            events.emit({"type": "dns_done", "error": str(e)})
        finally:
            dns_state["running"] = False

    asyncio.create_task(run())
    return {"ok": True, "resolvers": resolvers}


@app.get("/api/dns/lookup")
async def api_dns_lookup(name: str, type: str = "A", server: str = ""):
    srv = _valid_ipv4(server) if server else None
    if not srv:
        dns = [d for d in get_info().get("dns") or []]
        srv = dns[0] if dns else "1.1.1.1"
    qtype = type.upper()
    if qtype not in dnsclient.TYPES or qtype in ("PTR", "SOA"):
        raise HTTPException(400, "Unsupported record type")
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(pool, lambda: dnsclient.query(srv, name, qtype, timeout=3))
    except dnsclient.DNSError as e:
        raise HTTPException(400, str(e))
    except (TimeoutError, OSError) as e:
        if "timed out" in str(e).lower() or isinstance(e, TimeoutError):
            raise HTTPException(504, "No answer from %s within 3 seconds" % srv)
        raise HTTPException(502, "Could not reach %s: %s" % (srv, e))


# ---------------------------------------------------------------------------
# Traffic and connections (this computer)
# ---------------------------------------------------------------------------

@app.get("/api/traffic")
def api_traffic():
    return traffic.state()


@app.post("/api/traffic/capture")
async def api_capture(request: Request):
    b = await request.json()
    loop = asyncio.get_running_loop()
    try:
        if b.get("action") == "stop":
            return await loop.run_in_executor(pool, traffic.stop_capture)
        return await loop.run_in_executor(pool, traffic.start_capture)
    except RuntimeError as e:
        raise HTTPException(400, str(e))


@app.get("/api/connections")
async def api_connections():
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(pool, conns.snapshot)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.get("/api/report.csv")
def report_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["name", "ip", "mac", "vendor", "type", "hostname", "status", "agent", "open_ports",
                "latency_avg_ms", "latency_min_ms", "latency_max_ms", "jitter_ms", "jitter_rfc3550_ms",
                "loss_pct", "quality", "first_seen", "last_seen"])
    for d in enriched_devices():
        p = d["ping"] or {}
        w.writerow([d["name"], d["ip"], d["mac"], d["vendor"], d["type"], d["hostname"],
                    "online" if d["online"] else "offline", "yes" if d["is_agent"] else "",
                    " ".join(str(x) for x in d["ports"]), p.get("avg"), p.get("min"), p.get("max"),
                    p.get("jitter"), p.get("jitter_rfc"), p.get("loss_pct"), d["quality"],
                    time.strftime("%Y-%m-%d %H:%M", time.localtime(d["first_seen"])) if d["first_seen"] else "",
                    time.strftime("%Y-%m-%d %H:%M", time.localtime(d["last_seen"])) if d["last_seen"] else ""])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=netscope-devices.csv"})


def _spark(values, w=160, h=32, color="#2563eb"):
    vals = [v for v in values if v is not None]
    if len(vals) < 2:
        return '<span class="muted">not enough data</span>'
    lo, hi = min(vals), max(vals)
    rng = (hi - lo) or 1
    pts = []
    for i, v in enumerate(values):
        if v is None:
            continue
        x = i * (w - 4) / (len(values) - 1) + 2
        y = h - 2 - (v - lo) * (h - 4) / rng
        pts.append("%.1f,%.1f" % (x, y))
    return ('<svg width="%d" height="%d" viewBox="0 0 %d %d"><polyline fill="none" stroke="%s" '
            'stroke-width="1.5" points="%s"/></svg>' % (w, h, w, h, color, " ".join(pts)))


@app.get("/api/report.html", response_class=HTMLResponse)
def report_html():
    info = get_info()
    devs = enriched_devices()
    sm = summary(devs)
    e = html.escape
    since = time.time() - 86400
    rows = []
    qcol = {"green": "#16a34a", "amber": "#d97706", "red": "#dc2626", "grey": "#9ca3af"}
    for d in devs:
        p = d["ping"] or {}
        hist = [r["avg"] for r in _bucket(db.ping_history(d["key"], since), 86400, 60)]
        rows.append("<tr><td><span class='dot' style='background:%s'></span>%s</td><td>%s</td><td>%s</td>"
                    "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                        qcol[d["quality"]], e(d["name"]), e(d["ip"]), e(d["mac"] or "-"), e(d["vendor"] or "-"),
                        e(d["type"]), "online" if d["online"] else "offline",
                        "-" if p.get("avg") is None else "%.1f" % p["avg"],
                        "-" if p.get("jitter") is None else "%.1f" % p["jitter"],
                        "-" if p.get("loss_pct") is None else "%.1f%%" % p["loss_pct"],
                        _spark(hist)))
    trows = []
    for t in db.tests(30):
        r = t["result"] or {}
        if t["kind"] == "tcp":
            res = "%s Mbps (%s, %d stream%s)" % (r.get("avg_mbps", "-"), t["params"].get("direction"),
                                                 t["params"].get("streams", 1),
                                                 "" if t["params"].get("streams", 1) == 1 else "s")
        elif t["kind"] == "udp":
            res = "%s Mbps, loss %s%%, jitter %s ms, out-of-order %s" % (
                r.get("throughput_mbps", "-"), r.get("loss_pct", "-"), r.get("jitter_ms", "-"),
                r.get("out_of_order", "-"))
        else:
            res = "idle %s ms -> loaded %s ms (+%s ms)" % (
                (r.get("idle") or {}).get("avg", "-"), (r.get("loaded") or {}).get("avg", "-"),
                r.get("latency_increase_ms", "-"))
        trows.append("<tr><td>%s</td><td>%s</td><td>%s &rarr; %s</td><td>%s</td></tr>" % (
            time.strftime("%Y-%m-%d %H:%M", time.localtime(t["ts"])), e(TEST_KINDS.get(t["kind"], t["kind"])),
            e(t["source"]), e(t["target"]), e(res if t["status"] == "done" else (t["error"] or t["status"]))))
    page = """<!doctype html><html><head><meta charset="utf-8"><title>NetScope report</title>
<style>body{font:13px/1.45 system-ui,sans-serif;color:#111;margin:32px;max-width:1100px}
h1{margin:0 0 4px}h2{margin-top:28px;border-bottom:1px solid #ddd;padding-bottom:4px}
table{border-collapse:collapse;width:100%%}td,th{text-align:left;padding:5px 8px;border-bottom:1px solid #eee;vertical-align:middle}
th{background:#f6f7f9}.muted{color:#888}.dot{display:inline-block;width:9px;height:9px;border-radius:50%%;margin-right:6px}
.kv{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.kv div{background:#f6f7f9;padding:8px;border-radius:6px}
.kv b{display:block;font-size:11px;color:#666;font-weight:500}@media print{button{display:none}}</style></head><body>
<button onclick="print()" style="float:right">Print / Save as PDF</button>
<h1>NetScope network report</h1><div class="muted">Generated %s</div>
<h2>Network</h2><div class="kv">
<div><b>This machine</b>%s (%s)</div><div><b>Subnet</b>%s</div><div><b>Gateway</b>%s</div><div><b>DNS</b>%s</div>
<div><b>Health score</b>%s / 100</div><div><b>Devices</b>%d online / %d known</div><div><b>Agents</b>%d</div>
<div><b>Last scan</b>%s</div></div>
<h2>Devices</h2><table><tr><th>Device</th><th>IP</th><th>MAC</th><th>Vendor</th><th>Type</th><th>Status</th>
<th>Latency ms</th><th>Jitter ms</th><th>Loss</th><th>Latency, last 24 h</th></tr>%s</table>
<h2>Throughput tests</h2><table><tr><th>When</th><th>Test</th><th>Path</th><th>Result</th></tr>%s</table>
<p class="muted">Health score = 40%% latency score + 40%% loss score + 20%% availability.
Latency score is 100 at &le;20 ms falling to 0 at 300 ms; loss score is 100 at 0%% falling to 0 at 10%%.</p>
</body></html>""" % (
        time.strftime("%Y-%m-%d %H:%M"), e(info["hostname"]), e(info["ip"]), e(info["subnet"]),
        e(info["gateway"] or "-"), e(", ".join(info["dns"]) or "-"),
        "-" if sm["health"] is None else sm["health"], sm["counts"]["online"], sm["counts"]["total"],
        len(coord.agents),
        time.strftime("%H:%M", time.localtime(scan_state["last_scan"])) if scan_state["last_scan"] else "never",
        "".join(rows) or "<tr><td colspan=10 class=muted>No devices yet</td></tr>",
        "".join(trows) or "<tr><td colspan=4 class=muted>No tests yet</td></tr>")
    return page.replace("</body></html>", _report_extra() + "</body></html>")


def _report_extra():
    """Latest traceroute and DNS benchmark sections for the printable report."""
    e = html.escape
    out = []
    traces = db.traces(1)
    if traces:
        t = traces[0]
        sm = t.get("summary") or {}
        rows = "".join(
            "<tr><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                h["hop"], e(h["ip"] or "* * *"), e(h.get("hostname") or ""), e(h.get("label") or ""),
                "-" if h.get("avg") is None else "%.1f ms" % h["avg"])
            for h in t["hops"])
        path = " &rarr; ".join(e("AS%d %s" % (a["asn"], a.get("name") or "")) for a in sm.get("as_path", []))
        out.append("<h2>Traceroute to %s (%s)</h2><p class='muted'>%s, %s hops, %s%s</p>"
                   "<table><tr><th>Hop</th><th>Router</th><th>Hostname</th><th>Network</th><th>Avg RTT</th></tr>%s</table>"
                   % (e(t["target"]), e(t["ip"]), time.strftime("%Y-%m-%d %H:%M", time.localtime(t["ts"])),
                      sm.get("hops", len(t["hops"])), "destination reached" if sm.get("reached") else "destination not reached",
                      ("<br>Networks crossed: " + path) if path else "", rows))
    benches = db.dns_benches(1)
    if benches:
        b = benches[0]
        rows = "".join(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                e(r["name"]), e(r["ip"]),
                "-" if r.get("cached_ms") is None else "%.1f ms" % r["cached_ms"],
                "-" if r.get("uncached_ms") is None else "%.1f ms" % r["uncached_ms"],
                "-" if r.get("answered_pct") is None else "%.0f%%" % r["answered_pct"])
            for r in b["results"])
        out.append("<h2>DNS benchmark</h2><p class='muted'>%s. Fastest cached: %s. Fastest uncached: %s.</p>"
                   "<table><tr><th>Resolver</th><th>IP</th><th>Cached (median)</th><th>Uncached (median)</th>"
                   "<th>Answered</th></tr>%s</table>" % (
                       time.strftime("%Y-%m-%d %H:%M", time.localtime(b["ts"])), e(b.get("fastest") or "-"),
                       e(b.get("fastest_uncached") or "-"), rows))
    return "".join(out)


# ---------------------------------------------------------------------------
# WebSocket + static files
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def ws(websocket: WebSocket):
    await websocket.accept()
    events.clients.add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        events.clients.discard(websocket)


@app.get("/")
def index():
    return FileResponse(os.path.join(WEB, "index.html"))


app.mount("/", StaticFiles(directory=WEB), name="web")
