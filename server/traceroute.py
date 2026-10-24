"""
Traceroute: the path your packets take to reach a website.

How it works
------------
Every IP packet carries a TTL (time to live). Each router that forwards the
packet subtracts 1, and a router that brings it to 0 throws the packet away and
sends back an ICMP "Time Exceeded" message (type 11) from its own address.

So we send pings with TTL = 1, 2, 3, ... The router that is 1 hop away answers
the TTL=1 ping, the router 2 hops away answers TTL=2, and so on, until the
destination itself answers with a normal Echo Reply (type 0). We send 3 probes
per hop and time each one.

A hop that shows * * * didn't answer in time - many routers are configured not
to send Time Exceeded messages, but they still forward traffic normally.

Engines
-------
* icmplib with raw sockets (needs admin/root) - our own per-TTL loop below.
* The operating system's tracert/traceroute command, parsed line by line.
  Used on Windows (it works reliably through Windows Firewall) and whenever we
  don't have admin rights.

Which network each router belongs to
------------------------------------
The internet is made of ~75,000 independently run networks called Autonomous
Systems (AS), which exchange routes with BGP. We look up each public router's
AS number and name with a DNS TXT query to Team Cymru's IP-to-ASN service, e.g.
    8.8.8.8.origin.asn.cymru.com  ->  "15169 | 8.8.8.0/24 | US | arin | ..."
    AS15169.asn.cymru.com         ->  "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US"
"""

import concurrent.futures as cf
import ipaddress
import platform
import random
import re
import shutil
import socket
import subprocess
import threading
import time
import uuid

from . import dnsclient

SYSTEM = platform.system()
WIN = SYSTEM == "Windows"
MAX_HOPS = 30
PROBES = 3
TIMEOUT = 1.0

CGNAT = ipaddress.ip_network("100.64.0.0/10")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def classify_ip(ip):
    if not ip:
        return None
    a = ipaddress.ip_address(ip)
    if a.is_loopback:
        return "loopback"
    if a in CGNAT:
        return "cgnat"          # shared address space used inside ISPs (carrier-grade NAT)
    if a.is_private or a.is_link_local:
        return "private"
    return "public"


_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_RTT_RE = re.compile(r"(<\s*1|\d+(?:\.\d+)?)\s*ms|(\*)")


def parse_trace_line(line):
    """Parse one line of Windows `tracert -d` or Unix `traceroute -n` output.

    Windows:  "  3    12 ms    11 ms    13 ms  10.20.30.1"
              "  4     *        *        *     Request timed out."
    Linux:    " 3  10.20.30.1  11.8 ms  12.1 ms  11.9 ms"
              " 4  * * *"
    """
    m = re.match(r"^\s*(\d+)\s+(.*)$", line)
    if not m:
        return None
    n = int(m.group(1))
    if not 1 <= n <= 64:
        return None
    rest = m.group(2)
    ips = _IP_RE.findall(rest)
    rtts = []
    for t in _RTT_RE.finditer(rest):
        if t.group(2):
            rtts.append(None)
        else:
            v = t.group(1).replace(" ", "")
            rtts.append(0.5 if v.startswith("<") else float(v))
    if not rtts and not ips:
        return None
    return {"hop": n, "ip": ips[0] if ips else None, "rtts": rtts[:PROBES] or [None] * PROBES}


def hop_stats(rtts):
    got = [r for r in rtts if r is not None]
    return {
        "min": round(min(got), 2) if got else None,
        "avg": round(sum(got) / len(got), 2) if got else None,
        "max": round(max(got), 2) if got else None,
        "loss_pct": round(100.0 * (len(rtts) - len(got)) / len(rtts), 1) if rtts else None,
    }


_asn_cache = {}
_asn_lock = threading.Lock()


def asn_lookup(ip, resolver):
    """AS number, prefix, country and network name for a public IP (cached)."""
    with _asn_lock:
        hit = _asn_cache.get(ip)
    if hit is not None:
        return hit or None
    info = {}
    try:
        rev = ".".join(reversed(ip.split(".")))
        r = dnsclient.query(resolver, rev + ".origin.asn.cymru.com", "TXT", timeout=1.5)
        txt = next((x["value"] for x in dnsclient.answers(r, "TXT")), None)
        if txt:
            parts = [p.strip() for p in txt.split("|")]
            asn = parts[0].split()[0]
            info = {"asn": int(asn), "prefix": parts[1] if len(parts) > 1 else None,
                    "country": parts[2] if len(parts) > 2 else None}
            r2 = dnsclient.query(resolver, "AS%s.asn.cymru.com" % asn, "TXT", timeout=1.5)
            txt2 = next((x["value"] for x in dnsclient.answers(r2, "TXT")), None)
            if txt2:
                info["as_name"] = txt2.split("|")[-1].strip()
    except Exception:
        info = {}
    with _asn_lock:
        _asn_cache[ip] = info
    return info or None


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def resolve_target(target):
    target = target.strip()
    target = re.sub(r"^[a-z]+://", "", target, flags=re.I).split("/")[0].split(":")[0]
    if not target or len(target) > 253 or not re.match(r"^[A-Za-z0-9.\-_]+$", target):
        raise ValueError("Enter a website name like google.com or an IPv4 address")
    try:
        ip = str(ipaddress.IPv4Address(target))
    except ipaddress.AddressValueError:
        try:
            ip = socket.gethostbyname(target)
        except OSError:
            raise ValueError("Could not resolve %s - check the name and your internet connection" % target)
    a = ipaddress.ip_address(ip)
    if a.is_multicast or a.is_unspecified or a.is_reserved or str(a) == "255.255.255.255":
        raise ValueError("%s is not a valid destination" % ip)
    return target, ip


# ---------------------------------------------------------------------------
# Engines
# ---------------------------------------------------------------------------

def icmplib_raw_available():
    if WIN:
        return False
    try:
        from icmplib import ICMPv4Socket
        s = ICMPv4Socket(privileged=True)
        s.close()
        return True
    except Exception:
        return False


def system_command_available():
    return bool(shutil.which("tracert" if WIN else "traceroute"))


def trace_icmplib(ip, on_hop, stop, max_hops=MAX_HOPS, probes=PROBES, timeout=TIMEOUT):
    """Our own traceroute: ICMP Echo Requests with TTL 1, 2, 3, ..."""
    from icmplib import ICMPv4Socket, ICMPRequest, ICMPLibError

    sock = ICMPv4Socket(privileged=True)
    ident = random.randint(1, 0xFFFF)
    seq = 0
    try:
        for ttl in range(1, max_hops + 1):
            rtts, src, reached = [], None, False
            for _ in range(probes):
                if stop.is_set():
                    return
                req = ICMPRequest(destination=ip, id=ident, sequence=seq, ttl=ttl)
                seq += 1
                try:
                    sock.send(req)
                    reply = sock.receive(req, timeout)
                    rtts.append(round((reply.time - req.time) * 1000, 3))
                    src = src or reply.source
                    if reply.type == 0 or (reply.type == 3 and reply.source == ip):
                        reached = True          # Echo Reply (or "port unreachable") from the destination
                except ICMPLibError:
                    rtts.append(None)           # no answer within the timeout
            on_hop({"hop": ttl, "ip": src, "rtts": rtts})
            if reached:
                return
    finally:
        sock.close()


def trace_system(ip, on_hop, stop, max_hops=MAX_HOPS):
    if WIN:
        cmd = ["tracert", "-d", "-h", str(max_hops), "-w", "800", ip]
    else:
        cmd = ["traceroute", "-n", "-q", str(PROBES), "-w", "1", "-m", str(max_hops), ip]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace",
                         creationflags=0x08000000 if WIN else 0)
    try:
        for line in p.stdout:
            if stop.is_set():
                break
            hop = parse_trace_line(line)
            if hop:
                on_hop(hop)
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()


# ---------------------------------------------------------------------------
# Running a trace for the dashboard
# ---------------------------------------------------------------------------

class Tracer:
    def __init__(self, db, emit, get_info):
        self.db, self.emit, self.get_info = db, emit, get_info
        self.current = None
        self.stop = threading.Event()
        self.pool = cf.ThreadPoolExecutor(8)
        self.lock = threading.Lock()
        self.futures = []

    def engine(self):
        if icmplib_raw_available():
            return "icmplib", "NetScope's own ICMP traceroute (raw socket)"
        if system_command_available():
            return "system", ("Windows tracert" if WIN else "system traceroute command")
        return None, None

    def start(self, target):
        with self.lock:
            if self.current and self.current["status"] == "running":
                raise ValueError("A trace is already running - stop it first")
            name, ip = resolve_target(target)
            eng, eng_label = self.engine()
            if not eng:
                raise ValueError("No traceroute method available. Run NetScope as admin/root, or install the "
                                 "traceroute command (sudo apt install traceroute).")
            info = self.get_info()
            self.stop.clear()
            self.futures = []
            self.current = {
                "id": uuid.uuid4().hex, "ts": time.time(), "target": name, "ip": ip,
                "engine": eng_label, "status": "running", "hops": [], "error": None,
                "gateway": info.get("gateway"), "summary": None,
            }
            cur = dict(self.current)
        self.emit({"type": "trace_started", "trace": cur})
        threading.Thread(target=self._run, args=(self.current, eng), daemon=True).start()
        return cur

    def cancel(self):
        self.stop.set()

    def _resolver(self):
        dns = [d for d in self.get_info().get("dns") or [] if not d.startswith("127.")]
        return dns[0] if dns else "1.1.1.1"

    def _label(self, h, tr):
        k = h["kind"]
        if h["ip"] is None:
            return "No reply"
        if h["ip"] == tr["ip"]:
            return "Destination"
        if h["ip"] == tr["gateway"] or (h["hop"] == 1 and k == "private"):
            return "Your router"
        if k == "private":
            return "Private network (ISP or building)"
        if k == "cgnat":
            return "ISP (carrier-grade NAT)"
        if h.get("as_name"):
            return h["as_name"]
        return "Internet router"

    def _on_hop(self, tr, raw):
        h = {"hop": raw["hop"], "ip": raw["ip"], "rtts": raw["rtts"]}
        h.update(hop_stats(raw["rtts"]))
        h["kind"] = classify_ip(raw["ip"])
        h["hostname"] = None
        h["label"] = self._label(h, tr)
        tr["hops"] = [x for x in tr["hops"] if x["hop"] != h["hop"]] + [h]
        tr["hops"].sort(key=lambda x: x["hop"])
        self.emit({"type": "trace_hop", "id": tr["id"], "hop": h})
        if h["ip"]:
            self.futures.append(self.pool.submit(self._enrich, tr, h))

    def _enrich(self, tr, h):
        """Hostname and AS lookups happen in the background so the trace isn't slowed down."""
        name = reverse_dns(h["ip"])
        asn = asn_lookup(h["ip"], self._resolver()) if h["kind"] == "public" else None
        h["hostname"] = name
        if asn:
            h.update(asn=asn.get("asn"), as_name=asn.get("as_name"), prefix=asn.get("prefix"),
                     country=asn.get("country"))
        h["label"] = self._label(h, tr)
        self.emit({"type": "trace_hop", "id": tr["id"], "hop": h})

    def _run(self, tr, eng):
        try:
            if eng == "icmplib":
                trace_icmplib(tr["ip"], lambda raw: self._on_hop(tr, raw), self.stop)
            else:
                trace_system(tr["ip"], lambda raw: self._on_hop(tr, raw), self.stop)
            tr["status"] = "stopped" if self.stop.is_set() else "done"
        except Exception as e:
            tr["status"], tr["error"] = "error", str(e) or e.__class__.__name__
        # give the background hostname / network lookups a moment to finish
        cf.wait(self.futures, timeout=5)
        tr["summary"] = summarize(tr)
        self.db.add_trace(tr)
        self.emit({"type": "trace_done", "trace": tr})


def summarize(tr):
    hops = tr["hops"]
    answered = [h for h in hops if h["min"] is not None]
    reached = any(h["ip"] == tr["ip"] for h in hops)
    # Path through autonomous systems: consecutive duplicates collapsed
    as_path = []
    for h in hops:
        if h.get("asn") and (not as_path or as_path[-1]["asn"] != h["asn"]):
            as_path.append({"asn": h["asn"], "name": h.get("as_name"), "first_hop": h["hop"]})
    # Biggest increase in minimum RTT between consecutive answering hops:
    # usually a long-distance link (e.g. a submarine cable or a link to another city)
    jump = None
    for a, b in zip(answered, answered[1:]):
        d = b["min"] - a["min"]
        if jump is None or d > jump["ms"]:
            jump = {"from": a["hop"], "to": b["hop"], "ms": round(d, 1)}
    last = next((h for h in reversed(hops) if h["ip"] == tr["ip"]), None)
    return {
        "hops": len(hops),
        "reached": reached,
        "rtt_ms": last["avg"] if last else None,
        "silent_hops": sum(1 for h in hops if h["ip"] is None),
        "as_path": as_path,
        "jump": jump if jump and jump["ms"] >= 5 else None,
    }
