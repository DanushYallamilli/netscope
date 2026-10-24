"""
Live traffic monitor for THIS computer.

Two parts:

1. Bandwidth (always on, no admin needed): the operating system counts the
   bytes and packets sent/received on each network interface. Sampling those
   counters once a second gives upload/download speed.

2. Packet capture (only while you press "Start capture"; needs admin/root and
   Npcap on Windows): scapy sniffs packets on the interface in NON-promiscuous
   mode, so it only sees this computer's own traffic plus broadcasts. For each
   packet we look ONLY at the headers - layer 2 type, IP protocol and port
   numbers - and add its size to a protocol category. Payloads are never stored.
   Everything is kept in memory and cleared when you start a new capture.

   One extra trick: DNS answers to this computer are plain text, so we note
   which name each IP address was looked up as. That lets the conversations
   list show "youtube.com" instead of just 142.250.x.x.
"""

import collections
import socket
import threading
import time

import psutil

CAPTURE_LIMIT_S = 15 * 60          # auto-stop a capture after 15 minutes

# category -> (chart group, OSI layer, short explanation)
CATEGORIES = {
    "HTTPS (TLS over TCP)": ("HTTPS", 7, "Encrypted web traffic: HTTP inside TLS, over TCP port 443."),
    "QUIC (HTTP/3)": ("QUIC", 7, "HTTP/3 over UDP port 443. Used by Google, YouTube and others; TLS is built into QUIC."),
    "DNS": ("DNS", 7, "Name lookups on port 53, usually UDP."),
    "HTTP": ("HTTP", 7, "Unencrypted web traffic on port 80 or 8080."),
    "mDNS": ("Local discovery", 7, "Multicast DNS on UDP 5353: devices announcing themselves (printers, Chromecasts, Macs)."),
    "SSDP / UPnP": ("Local discovery", 7, "UDP 1900 multicast: smart TVs and routers advertising services."),
    "NetBIOS / LLMNR": ("Local discovery", 7, "Windows name discovery on UDP 137/138 and 5355."),
    "DHCP": ("Local discovery", 7, "UDP 67/68: how devices get an IP address from the router."),
    "ARP": ("Local discovery", 2, "Layer 2: 'who has this IP?' broadcasts that map IP addresses to MAC addresses."),
    "NetScope": ("NetScope", 7, "NetScope's own dashboard (8000), agent control (5600) and test (5601) traffic."),
    "NTP": ("Other UDP", 7, "Clock synchronisation on UDP 123."),
    "Calls (STUN / RTP)": ("Other UDP", 7, "Video/voice calls: STUN on UDP 3478/19302-19309 for NAT traversal."),
    "SSH": ("Other TCP", 7, "Secure shell on TCP 22."),
    "SMB file sharing": ("Other TCP", 7, "Windows file sharing on TCP 445."),
    "Email": ("Other TCP", 7, "SMTP/IMAP/POP3 mail ports."),
    "Other TCP": ("Other TCP", 4, "TCP traffic on ports NetScope doesn't have a name for."),
    "Other UDP": ("Other UDP", 4, "UDP traffic on ports NetScope doesn't have a name for."),
    "ICMP": ("Other", 3, "Layer 3 control messages: ping, Time Exceeded (traceroute), unreachable."),
    "IPv6 control": ("Other", 3, "ICMPv6: IPv6 neighbour discovery and router advertisements."),
    "Other": ("Other", 2, "Anything else (other layer 2 or layer 3 protocols)."),
}
# fixed order = fixed colour slot in the charts
GROUPS = ["HTTPS", "QUIC", "DNS", "HTTP", "Local discovery", "NetScope", "Other TCP", "Other UDP", "Other"]

TCP_PORTS = {443: "HTTPS (TLS over TCP)", 80: "HTTP", 8080: "HTTP", 53: "DNS", 22: "SSH", 445: "SMB file sharing",
             25: "Email", 465: "Email", 587: "Email", 993: "Email", 995: "Email", 143: "Email", 110: "Email",
             8000: "NetScope", 5600: "NetScope", 5601: "NetScope"}
UDP_PORTS = {53: "DNS", 443: "QUIC (HTTP/3)", 5353: "mDNS", 1900: "SSDP / UPnP", 137: "NetBIOS / LLMNR",
             138: "NetBIOS / LLMNR", 5355: "NetBIOS / LLMNR", 67: "DHCP", 68: "DHCP", 123: "NTP",
             3478: "Calls (STUN / RTP)", 5601: "NetScope"}
UDP_PORTS.update({p: "Calls (STUN / RTP)" for p in range(19302, 19310)})


def classify_ports(proto, sport, dport):
    table = TCP_PORTS if proto == "tcp" else UDP_PORTS
    for p in (dport, sport):                 # the server side usually has the well-known port
        if p in table:
            return table[p]
    return "Other TCP" if proto == "tcp" else "Other UDP"


def classify(pkt):
    """Header-only classification of a scapy packet."""
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        return classify_ports("tcp", t.sport, t.dport)
    if pkt.haslayer(UDP):
        u = pkt[UDP]
        return classify_ports("udp", u.sport, u.dport)
    if pkt.haslayer(ICMP):
        return "ICMP"
    try:
        from scapy.layers.inet6 import IPv6
        if pkt.haslayer(IPv6) and pkt[IPv6].nh == 58:
            return "IPv6 control"
    except Exception:
        pass
    return "Other"


def dns_answers(pkt):
    """(query name, [IPv4 addresses]) from a DNS response, or None."""
    from scapy.layers.dns import DNS
    if not pkt.haslayer(DNS):
        return None
    d = pkt[DNS]
    if not d.qr or not d.ancount:
        return None
    try:
        qd = d.qd[0] if isinstance(d.qd, list) else d.qd
        qname = qd.qname.decode(errors="ignore").rstrip(".")
    except Exception:
        return None
    ips = []
    an = d.an
    rrs = an if isinstance(an, list) else [an[i] for i in range(d.ancount)] if an else []
    for rr in rrs:
        try:
            if rr.type == 1:
                ips.append(str(rr.rdata))
        except Exception:
            continue
    return qname, ips


def local_addresses():
    out = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                out.add(a.address.split("%")[0])
    return out


class TrafficMonitor:
    def __init__(self, get_info, emit, is_admin):
        self.get_info, self.emit, self.is_admin = get_info, emit, is_admin
        self.lock = threading.Lock()
        self.bw = collections.deque(maxlen=300)           # 5 minutes of 1-second samples
        self.proto_hist = collections.deque(maxlen=120)   # 2 minutes of per-second bytes per group
        self.names = {}                                   # ip -> domain name seen in DNS answers
        self.sniffer = None
        self.capture = {"running": False, "started": None, "error": None, "stopped": None}
        self._reset_counters()
        self._stop = threading.Event()

    # ---------------------------------------------------------------- bandwidth
    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()

    def _counters(self):
        iface = self.get_info().get("interface")
        per = psutil.net_io_counters(pernic=True)
        c = per.get(iface) if iface else None
        return c or psutil.net_io_counters()

    def _loop(self):
        prev, prev_t = self._counters(), time.time()
        while not self._stop.is_set():
            time.sleep(1 - (time.time() % 1) + 0.01)
            try:
                cur, t = self._counters(), time.time()
            except Exception:
                continue
            dt = max(t - prev_t, 1e-3)
            s = {
                "ts": round(t, 2),
                "rx_mbps": round(max(cur.bytes_recv - prev.bytes_recv, 0) * 8 / dt / 1e6, 3),
                "tx_mbps": round(max(cur.bytes_sent - prev.bytes_sent, 0) * 8 / dt / 1e6, 3),
                "rx_pps": round(max(cur.packets_recv - prev.packets_recv, 0) / dt, 1),
                "tx_pps": round(max(cur.packets_sent - prev.packets_sent, 0) / dt, 1),
            }
            prev, prev_t = cur, t
            self.bw.append(s)
            msg = {"type": "traffic", "bw": s}
            with self.lock:
                if self.capture["running"]:
                    sec = {g: round(b * 8 / 1e6, 4) for g, b in self.sec_groups.items()}
                    self.sec_groups = collections.Counter()
                    sample = {"ts": s["ts"], "groups": sec}
                    self.proto_hist.append(sample)
                    msg["proto"] = sample
                    msg["capture"] = self._summary_locked()
                    if time.time() - self.capture["started"] > CAPTURE_LIMIT_S:
                        threading.Thread(target=self.stop_capture, args=("Stopped automatically after 15 minutes",),
                                         daemon=True).start()
            self.emit(msg)

    # ---------------------------------------------------------------- capture
    def _reset_counters(self):
        self.cats = collections.defaultdict(lambda: [0, 0])     # category -> [packets, bytes]
        self.sec_groups = collections.Counter()                  # group -> bytes this second
        self.convs = {}                                          # remote ip -> dict
        self.total = {"packets": 0, "bytes": 0, "broadcast": 0, "multicast": 0, "in": 0, "out": 0}
        self.proto_hist = collections.deque(maxlen=120)

    def start_capture(self):
        if self.capture["running"]:
            return self.state()
        if not self.is_admin():
            raise RuntimeError("Packet capture needs NetScope to run as administrator (Windows) or with sudo "
                               "(macOS/Linux). Bandwidth still works without it.")
        try:
            from scapy.all import AsyncSniffer, conf
        except Exception as e:
            raise RuntimeError("scapy is not installed: %s" % e)
        with self.lock:
            self._reset_counters()
            self.local = local_addresses()
        try:
            conf.sniff_promisc = False
            self.sniffer = AsyncSniffer(prn=self._packet, store=False)
            self.sniffer.start()
            time.sleep(0.6)
            th = getattr(self.sniffer, "thread", None)
            if th is not None and not th.is_alive():
                raise RuntimeError(getattr(self.sniffer, "exception", None) or "capture thread stopped")
        except Exception as e:
            self.sniffer = None
            msg = str(e)
            if "winpcap" in msg.lower() or "npcap" in msg.lower() or "pcap" in msg.lower():
                msg = "Npcap is not installed. Install it from npcap.com (tick 'WinPcap API-compatible mode') and restart NetScope."
            raise RuntimeError("Could not start capture: %s" % msg)
        with self.lock:
            self.capture = {"running": True, "started": time.time(), "error": None, "stopped": None}
        st = self.state()
        self.emit({"type": "capture_state", "state": st})
        return st

    def stop_capture(self, reason=None):
        sn, self.sniffer = self.sniffer, None
        if sn is not None:
            try:
                sn.stop(join=True)
            except Exception:
                pass
        with self.lock:
            if self.capture["running"]:
                self.capture.update(running=False, stopped=time.time(), error=reason)
        st = self.state()
        self.emit({"type": "capture_state", "state": st})
        return st

    def _packet(self, pkt):
        try:
            size = len(pkt)
            cat = classify(pkt)
            group = CATEGORIES.get(cat, ("Other",))[0]
            remote, direction = None, None
            src = dst = None
            if pkt.haslayer("IP"):
                src, dst = pkt["IP"].src, pkt["IP"].dst
            elif pkt.haslayer("IPv6"):
                src, dst = pkt["IPv6"].src, pkt["IPv6"].dst
            names = None
            if cat == "DNS":
                names = dns_answers(pkt)
            with self.lock:
                c = self.cats[cat]
                c[0] += 1
                c[1] += size
                self.sec_groups[group] += size
                t = self.total
                t["packets"] += 1
                t["bytes"] += size
                if pkt.haslayer("Ether"):
                    d = pkt["Ether"].dst.lower()
                    if d == "ff:ff:ff:ff:ff:ff":
                        t["broadcast"] += 1
                    elif int(d.split(":")[0], 16) & 1:
                        t["multicast"] += 1
                if src is not None:
                    if src in self.local:
                        remote, direction = dst, "out"
                    elif dst in self.local:
                        remote, direction = src, "in"
                    else:
                        remote, direction = dst, "other"
                    if direction in ("in", "out"):
                        t[direction] += size
                    cv = self.convs.get(remote)
                    if cv is None:
                        if len(self.convs) > 3000:
                            smallest = min(self.convs, key=lambda k: self.convs[k]["bytes"])
                            del self.convs[smallest]
                        cv = self.convs[remote] = {"ip": remote, "in": 0, "out": 0, "bytes": 0, "packets": 0,
                                                   "cats": collections.Counter(), "first": time.time()}
                    cv["bytes"] += size
                    cv["packets"] += 1
                    if direction == "in":
                        cv["in"] += size
                    elif direction == "out":
                        cv["out"] += size
                    cv["cats"][cat] += size
                    cv["last"] = time.time()
                if names:
                    for ip in names[1]:
                        self.names[ip] = names[0]
                    if len(self.names) > 5000:
                        self.names.clear()
        except Exception:
            pass

    # ---------------------------------------------------------------- reporting
    def name_for(self, ip):
        return self.names.get(ip)

    def _summary_locked(self, conv_limit=12):
        cats = []
        for name, (pk, by) in self.cats.items():
            g, layer, expl = CATEGORIES.get(name, ("Other", 0, ""))
            cats.append({"name": name, "group": g, "layer": layer, "about": expl, "packets": pk, "bytes": by})
        cats.sort(key=lambda c: -c["bytes"])
        convs = sorted(self.convs.values(), key=lambda c: -c["bytes"])[:conv_limit]
        conv_out = []
        for c in convs:
            top = c["cats"].most_common(2)
            conv_out.append({"ip": c["ip"], "name": self.names.get(c["ip"]), "in": c["in"], "out": c["out"],
                             "bytes": c["bytes"], "packets": c["packets"], "protocols": [k for k, _ in top],
                             "scope": _scope(c["ip"])})
        cap = dict(self.capture)
        cap["seconds"] = round((time.time() if cap["running"] else (cap["stopped"] or time.time()))
                               - cap["started"], 1) if cap["started"] else 0
        return {"capture": cap, "total": dict(self.total), "categories": cats, "conversations": conv_out}

    def state(self):
        with self.lock:
            s = self._summary_locked()
            s["bandwidth"] = list(self.bw)
            s["proto_hist"] = list(self.proto_hist)
        s["groups"] = GROUPS
        s["admin"] = bool(self.is_admin())
        return s


def _scope(ip):
    import ipaddress
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "other"
    if a.is_multicast or str(a) == "255.255.255.255" or ip.endswith(".255"):
        return "broadcast"
    if a.is_loopback:
        return "this computer"
    if a.is_private or a.is_link_local:
        return "local network"
    return "internet"
