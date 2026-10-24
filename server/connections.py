"""
TCP connection monitor for THIS computer.

The operating system keeps a table of every socket: local address and port,
remote address and port, the TCP state, and which program owns it. This is
what `netstat -ano` (Windows) or `ss -tanp` (Linux) print. psutil reads the
same table.

TCP states (RFC 9293, the TCP state machine):
  LISTEN       a server waiting for connections
  SYN_SENT     we sent SYN, waiting for SYN+ACK               (3-way handshake)
  SYN_RECV     we got SYN, sent SYN+ACK, waiting for ACK      (3-way handshake)
  ESTABLISHED  open, data flowing
  FIN_WAIT1    we closed and sent FIN, waiting for its ACK
  FIN_WAIT2    our FIN was ACKed, waiting for the other side's FIN
  CLOSE_WAIT   the other side closed; waiting for OUR program to close
  LAST_ACK     we closed after them, waiting for the final ACK
  CLOSING      both sides sent FIN at the same time
  TIME_WAIT    closed; kept for 2 x MSL so late packets can't confuse a new connection
"""

import concurrent.futures as cf
import ipaddress
import socket
import threading
import time

import psutil

STATE_ORDER = ["LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2",
               "CLOSING", "TIME_WAIT", "CLOSE_WAIT", "LAST_ACK", "CLOSE"]

SERVICES = {20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP",
            110: "POP3", 123: "NTP", 135: "Windows RPC", 137: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 465: "SMTPS", 554: "RTSP", 587: "SMTP", 631: "IPP printing",
            993: "IMAPS", 995: "POP3S", 1900: "SSDP", 3306: "MySQL", 3389: "Remote Desktop", 5000: "UPnP / dev server",
            5037: "Android ADB", 5353: "mDNS", 5432: "PostgreSQL", 5600: "NetScope agents", 5601: "NetScope tests",
            7680: "Windows Update delivery", 8000: "NetScope dashboard", 8080: "HTTP-alt", 27017: "MongoDB",
            5228: "Google push (FCM)", 5222: "XMPP / chat", 3478: "STUN"}


def service_name(port):
    if port in SERVICES:
        return SERVICES[port]
    try:
        return socket.getservbyport(port)
    except Exception:
        return None


def scope(ip):
    try:
        a = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return "other"
    if a.is_loopback:
        return "this computer"
    if a.is_private or a.is_link_local:
        return "local network"
    return "internet"


def listen_scope(ip):
    if ip in ("0.0.0.0", "::", ""):
        return "all interfaces", "Other devices on the network can connect"
    if ip.startswith("127.") or ip == "::1":
        return "this computer only", "Only programs on this computer can connect"
    return "one interface (%s)" % ip, "Reachable on that interface's network"


class ConnectionMonitor:
    def __init__(self, name_for):
        self.name_for = name_for          # ip -> domain seen by the traffic monitor's DNS sniffing
        self.rdns = {}
        self.pending = set()
        self.lock = threading.Lock()
        self.pool = cf.ThreadPoolExecutor(6)
        self.proc_names = {}

    def _proc(self, pid):
        if not pid:
            return None
        n = self.proc_names.get(pid)
        if n is None:
            try:
                n = psutil.Process(pid).name()
            except Exception:
                n = "pid %d" % pid
            if len(self.proc_names) > 2000:
                self.proc_names.clear()
            self.proc_names[pid] = n
        return n

    def _host(self, ip):
        """Best name for a remote IP: the domain this computer looked up, else reverse DNS (filled in later)."""
        n = self.name_for(ip) if self.name_for else None
        if n:
            return n
        with self.lock:
            if ip in self.rdns:
                return self.rdns[ip]
            if ip not in self.pending and len(self.pending) < 64:
                self.pending.add(ip)
                self.pool.submit(self._lookup, ip)
        return None

    def _lookup(self, ip):
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = None
        with self.lock:
            self.rdns[ip] = name
            self.pending.discard(ip)
            if len(self.rdns) > 5000:
                self.rdns.clear()

    def snapshot(self):
        try:
            conns = psutil.net_connections(kind="inet")
            error = None
        except psutil.AccessDenied:
            conns, error = [], ("The operating system refused access to the connection table. On macOS, run "
                                "NetScope with sudo to see every program's connections.")
        counts = {s: 0 for s in STATE_ORDER}
        tcp, listening, udp = [], [], []
        procs = {}
        for c in conns:
            proc = self._proc(c.pid)
            lip, lport = (c.laddr.ip, c.laddr.port) if c.laddr else ("", 0)
            if c.type == socket.SOCK_STREAM:
                st = c.status if c.status in counts else ("CLOSE" if c.status else "CLOSE")
                if c.status == "NONE":
                    continue
                counts[st] = counts.get(st, 0) + 1
                if st == "LISTEN":
                    sc, why = listen_scope(lip)
                    listening.append({"proto": "TCP", "ip": lip, "port": lport, "service": service_name(lport),
                                      "process": proc, "pid": c.pid, "scope": sc, "scope_note": why})
                    continue
                rip, rport = (c.raddr.ip, c.raddr.port) if c.raddr else ("", 0)
                rs = scope(rip) if rip else "other"
                tcp.append({"state": st, "local": "%s:%d" % (lip, lport), "lport": lport,
                            "rip": rip, "rport": rport, "remote_scope": rs,
                            "host": self._host(rip) if rip and rs != "this computer" else None,
                            "service": service_name(rport) or service_name(lport),
                            "process": proc, "pid": c.pid,
                            "family": "IPv6" if c.family == socket.AF_INET6 else "IPv4"})
                key = proc or "unknown"
                procs[key] = procs.get(key, 0) + 1
            else:
                if not c.raddr:
                    sc, why = listen_scope(lip)
                    udp.append({"proto": "UDP", "ip": lip, "port": lport, "service": service_name(lport),
                                "process": proc, "pid": c.pid, "scope": sc, "scope_note": why})
        order = {s: i for i, s in enumerate(STATE_ORDER)}
        tcp.sort(key=lambda r: (order.get(r["state"], 99), r["process"] or "", r["rip"]))
        listening.sort(key=lambda r: (r["scope"] != "all interfaces", r["port"]))
        udp.sort(key=lambda r: r["port"])
        top = sorted(procs.items(), key=lambda kv: -kv[1])[:8]
        return {
            "ts": time.time(), "error": error, "counts": counts,
            "tcp": tcp[:500], "tcp_total": len(tcp),
            "listening": listening, "udp": udp[:200], "udp_total": len(udp),
            "top_processes": [{"process": p, "connections": n} for p, n in top],
            "exposed": sum(1 for x in listening if x["scope"] == "all interfaces"),
        }
