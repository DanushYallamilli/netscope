"""
SQLite storage: devices, ping history, throughput tests, alerts and settings.

Uses the standard-library sqlite3 module with one shared connection guarded by
a lock (the server is small; this keeps things simple and easy to read).
"""

import json
import os
import secrets
import sqlite3
import threading
import time

DB_PATH = os.environ.get("NETSCOPE_DB", os.path.join(os.path.dirname(os.path.dirname(__file__)), "netscope.db"))

DEFAULT_SETTINGS = {
    "consent": False,                 # one-time "only scan networks you own" confirmation
    "scan_interval_min": 10,          # automatic rescan
    "ping_interval_s": 60,            # background quality checks
    "ping_count": 20,                 # pings in a manual test
    "bg_ping_count": 5,               # pings in a background check
    "green_latency": 20, "amber_latency": 100,   # ms
    "green_loss": 1, "amber_loss": 5,            # %
    "control_port": 5600, "data_port": 5601,
    "token": None,                    # generated on first run
    "retention_days": 7,
    "check_ports": True,
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS devices (
    key TEXT PRIMARY KEY,          -- MAC if known, otherwise ip:<address>
    ip TEXT, mac TEXT, vendor TEXT, hostname TEXT, type TEXT,
    ports TEXT, randomized_mac INTEGER DEFAULT 0,
    is_self INTEGER DEFAULT 0, is_gateway INTEGER DEFAULT 0, is_agent INTEGER DEFAULT 0,
    agent_name TEXT, label TEXT,
    first_seen REAL, last_seen REAL, online INTEGER DEFAULT 1, new INTEGER DEFAULT 1
);
CREATE TABLE IF NOT EXISTS pings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_key TEXT, ts REAL, kind TEXT,
    sent INTEGER, received INTEGER, loss_pct REAL,
    min REAL, avg REAL, max REAL, median REAL, jitter REAL, jitter_rfc REAL
);
CREATE INDEX IF NOT EXISTS ix_pings ON pings(device_key, ts);
CREATE TABLE IF NOT EXISTS tests (
    id TEXT PRIMARY KEY, ts REAL, kind TEXT, status TEXT,
    source TEXT, target TEXT, source_ip TEXT, target_ip TEXT,
    target_device TEXT, params TEXT, result TEXT, error TEXT
);
CREATE TABLE IF NOT EXISTS traces (
    id TEXT PRIMARY KEY, ts REAL, target TEXT, ip TEXT, status TEXT, data TEXT
);
CREATE TABLE IF NOT EXISTS dns_bench (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, data TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, level TEXT, kind TEXT,
    message TEXT, device_key TEXT, read INTEGER DEFAULT 0
);
"""


class DB:
    def __init__(self, path=DB_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        s = self.settings()
        if not s.get("token"):
            self.save_settings({"token": secrets.token_urlsafe(9)})

    def q(self, sql, args=()):
        with self.lock:
            return [dict(r) for r in self.conn.execute(sql, args).fetchall()]

    def x(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur

    # --- settings ------------------------------------------------------------
    def settings(self):
        out = dict(DEFAULT_SETTINGS)
        for r in self.q("SELECT k, v FROM settings"):
            out[r["k"]] = json.loads(r["v"])
        return out

    def save_settings(self, upd):
        with self.lock:
            for k, v in upd.items():
                if k in DEFAULT_SETTINGS:
                    self.conn.execute("INSERT OR REPLACE INTO settings VALUES (?, ?)", (k, json.dumps(v)))
            self.conn.commit()
        return self.settings()

    # --- devices -------------------------------------------------------------
    @staticmethod
    def key_for(ip, mac):
        return mac if mac else "ip:" + ip

    def devices(self):
        rows = self.q("SELECT * FROM devices")
        for r in rows:
            r["ports"] = json.loads(r["ports"] or "[]")
            for b in ("randomized_mac", "is_self", "is_gateway", "is_agent", "online", "new"):
                r[b] = bool(r[b])
        return rows

    def device(self, key):
        d = [r for r in self.devices() if r["key"] == key]
        return d[0] if d else None

    def upsert_scan(self, found):
        """Merge a scan result. Returns (new_devices, gone_devices)."""
        now = time.time()
        existing = {d["key"]: d for d in self.devices()}
        by_ip = {d["ip"]: d for d in existing.values()}
        seen, new = set(), []
        with self.lock:
            for f in found:
                key = self.key_for(f["ip"], f.get("mac"))
                # a device first seen without a MAC may now have one
                old = existing.get(key)
                if old is None and f.get("mac") and ("ip:" + f["ip"]) in existing:
                    self.conn.execute("UPDATE devices SET key=? WHERE key=?", (key, "ip:" + f["ip"]))
                    self.conn.execute("UPDATE pings SET device_key=? WHERE device_key=?", (key, "ip:" + f["ip"]))
                    old = existing.pop("ip:" + f["ip"])
                    existing[key] = old
                # an IP that now belongs to a different MAC: free the IP on the old record
                prev = by_ip.get(f["ip"])
                if prev and prev["key"] != key and prev["key"] in existing:
                    self.conn.execute("UPDATE devices SET online=0 WHERE key=?", (prev["key"],))
                seen.add(key)
                vals = (f["ip"], f.get("mac"), f.get("vendor"), f.get("hostname"), f.get("type"),
                        json.dumps(f.get("ports", [])), int(bool(f.get("randomized_mac"))),
                        int(bool(f.get("is_self"))), int(bool(f.get("is_gateway"))))
                if old is None:
                    self.conn.execute(
                        "INSERT INTO devices (ip, mac, vendor, hostname, type, ports, randomized_mac, is_self,"
                        " is_gateway, key, first_seen, last_seen, online, new) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,1,?)",
                        vals + (key, now, now, 0 if (f.get("is_self") or f.get("is_gateway")) else 1))
                    new.append(f)
                else:
                    self.conn.execute(
                        "UPDATE devices SET ip=?, mac=?, vendor=COALESCE(?, vendor), hostname=COALESCE(?, hostname),"
                        " type=?, ports=?, randomized_mac=?, is_self=?, is_gateway=?, last_seen=?, online=1"
                        " WHERE key=?", vals + (now, key))
            gone = [d for k, d in existing.items() if k not in seen and d["online"] and not d["is_agent"]]
            for d in gone:
                self.conn.execute("UPDATE devices SET online=0 WHERE key=?", (d["key"],))
            self.conn.commit()
        return new, gone

    def upsert_agent_device(self, ip, name, hostname):
        """Agents appear on the map even if a scan hasn't found them yet."""
        now = time.time()
        d = [r for r in self.devices() if r["ip"] == ip and r["online"]] or \
            [r for r in self.devices() if r["ip"] == ip]
        if d:
            self.x("UPDATE devices SET is_agent=1, agent_name=?, online=1, last_seen=?,"
                   " hostname=COALESCE(hostname, ?) WHERE key=?", (name, now, hostname, d[0]["key"]))
            return d[0]["key"]
        key = "ip:" + ip
        self.x("INSERT OR REPLACE INTO devices (key, ip, hostname, type, ports, is_agent, agent_name,"
               " first_seen, last_seen, online, new) VALUES (?,?,?,?,?,1,?,?,?,1,0)",
               (key, ip, hostname, "pc", "[]", name, now, now))
        return key

    def set_agent_flag(self, ip, flag):
        self.x("UPDATE devices SET is_agent=? WHERE ip=?", (int(flag), ip))

    def mark_seen(self, key, online=True):
        self.x("UPDATE devices SET online=?, last_seen=CASE WHEN ? THEN ? ELSE last_seen END WHERE key=?",
               (int(online), int(online), time.time(), key))

    def clear_new(self, key=None):
        if key:
            self.x("UPDATE devices SET new=0 WHERE key=?", (key,))
        else:
            self.x("UPDATE devices SET new=0")

    def rename(self, key, label):
        self.x("UPDATE devices SET label=? WHERE key=?", (label or None, key))

    def forget(self, key):
        self.x("DELETE FROM devices WHERE key=?", (key,))
        self.x("DELETE FROM pings WHERE device_key=?", (key,))

    # --- pings ---------------------------------------------------------------
    def add_ping(self, key, stats, kind="bg", ts=None):
        self.x("INSERT INTO pings (device_key, ts, kind, sent, received, loss_pct, min, avg, max, median,"
               " jitter, jitter_rfc) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
               (key, ts or time.time(), kind, stats["sent"], stats["received"], stats["loss_pct"],
                stats["min"], stats["avg"], stats["max"], stats["median"], stats["jitter"],
                stats["jitter_rfc"]))

    def latest_pings(self):
        rows = self.q("SELECT p.* FROM pings p JOIN (SELECT device_key, MAX(ts) m FROM pings"
                      " GROUP BY device_key) l ON p.device_key=l.device_key AND p.ts=l.m")
        return {r["device_key"]: r for r in rows}

    def ping_history(self, key=None, since=0):
        if key:
            return self.q("SELECT * FROM pings WHERE device_key=? AND ts>=? ORDER BY ts", (key, since))
        return self.q("SELECT * FROM pings WHERE ts>=? ORDER BY ts", (since,))

    # --- tests ---------------------------------------------------------------
    def add_test(self, t):
        self.x("INSERT INTO tests (id, ts, kind, status, source, target, source_ip, target_ip, target_device,"
               " params) VALUES (?,?,?,?,?,?,?,?,?,?)",
               (t["id"], t["ts"], t["kind"], "running", t["source"], t["target"], t["source_ip"],
                t["target_ip"], t.get("target_device"), json.dumps(t["params"])))

    def finish_test(self, tid, status, result=None, error=None):
        self.x("UPDATE tests SET status=?, result=?, error=? WHERE id=?",
               (status, json.dumps(result) if result is not None else None, error, tid))

    def tests(self, limit=50, since=0):
        rows = self.q("SELECT * FROM tests WHERE ts>=? ORDER BY ts DESC LIMIT ?", (since, limit))
        for r in rows:
            r["params"] = json.loads(r["params"] or "{}")
            r["result"] = json.loads(r["result"]) if r["result"] else None
        return rows

    # --- alerts --------------------------------------------------------------
    def add_alert(self, level, kind, message, device_key=None):
        cur = self.x("INSERT INTO alerts (ts, level, kind, message, device_key) VALUES (?,?,?,?,?)",
                     (time.time(), level, kind, message, device_key))
        return {"id": cur.lastrowid, "ts": time.time(), "level": level, "kind": kind,
                "message": message, "device_key": device_key, "read": 0}

    def alerts(self, limit=50):
        return self.q("SELECT * FROM alerts ORDER BY ts DESC LIMIT ?", (limit,))

    def read_alerts(self):
        self.x("UPDATE alerts SET read=1")

    # --- traceroutes ----------------------------------------------------------
    def add_trace(self, tr):
        self.x("INSERT OR REPLACE INTO traces (id, ts, target, ip, status, data) VALUES (?,?,?,?,?,?)",
               (tr["id"], tr["ts"], tr["target"], tr["ip"], tr["status"], json.dumps(tr)))
        self.x("DELETE FROM traces WHERE id NOT IN (SELECT id FROM traces ORDER BY ts DESC LIMIT 30)")

    def traces(self, limit=15):
        rows = self.q("SELECT data FROM traces ORDER BY ts DESC LIMIT ?", (limit,))
        return [json.loads(r["data"]) for r in rows]

    def trace(self, tid):
        r = self.q("SELECT data FROM traces WHERE id=?", (tid,))
        return json.loads(r[0]["data"]) if r else None

    # --- DNS benchmarks ------------------------------------------------------
    def add_dns_bench(self, res):
        self.x("INSERT INTO dns_bench (ts, data) VALUES (?, ?)", (res["ts"], json.dumps(res)))
        self.x("DELETE FROM dns_bench WHERE id NOT IN (SELECT id FROM dns_bench ORDER BY ts DESC LIMIT 20)")

    def dns_benches(self, limit=10):
        return [json.loads(r["data"]) for r in self.q("SELECT data FROM dns_bench ORDER BY ts DESC LIMIT ?", (limit,))]

    # --- housekeeping --------------------------------------------------------
    def prune(self, days):
        cut = time.time() - days * 86400
        self.x("DELETE FROM pings WHERE ts<?", (cut,))
        self.x("DELETE FROM alerts WHERE ts<?", (cut,))
        self.x("DELETE FROM tests WHERE ts<?", (cut,))
