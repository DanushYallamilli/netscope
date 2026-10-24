"""Tests for the DNS client, traceroute parsing, traffic classification and TCP states.
Run:  python -m pytest tests
"""

import os
import socket
import struct
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import pytest  # noqa: E402

from server import connections, dnsbench, dnsclient, traceroute, traffic  # noqa: E402


# ---------------------------------------------------------------- DNS packet format
def test_query_bytes_match_rfc1035():
    qid, pkt = dnsclient.build_query("www.example.com", "A", qid=0x1234)
    assert pkt[:12] == bytes.fromhex("1234 0100 0001 0000 0000 0000".replace(" ", ""))
    assert pkt[12:29] == b"\x03www\x07example\x03com\x00"
    assert pkt[29:] == b"\x00\x01\x00\x01"                 # type A, class IN
    segs = dnsclient.query_segments(pkt)
    assert [s["part"] for s in segs] == ["header", "qname", "qtype_qclass"]
    assert segs[-1]["end"] == len(pkt)


@pytest.mark.parametrize("bad", ["", "a..b", "x" * 64 + ".com", "bad name.com", "evil;rm.com"])
def test_invalid_names_rejected(bad):
    with pytest.raises(dnsclient.DNSError):
        dnsclient.encode_name(bad)


def _response(qid, name, answers, flags=0x8180, tc=False):
    """Build a DNS response with name compression (answers point back to the question name at offset 12)."""
    if tc:
        flags |= 0x0200
    hdr = struct.pack("!HHHHHH", qid, flags, 1, len(answers), 0, 0)
    q = dnsclient.encode_name(name) + struct.pack("!HH", 1, 1)
    body = b""
    for rtype, ttl, rdata in answers:
        body += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, ttl, len(rdata)) + rdata
    return hdr + q + body


def test_parse_compressed_answers_and_cname():
    cname = b"\x03cdn\xc0\x0c"          # "cdn." + pointer to the question name
    data = _response(7, "example.com", [(5, 300, cname), (1, 60, socket.inet_aton("93.184.216.34")),
                                        (1, 60, socket.inet_aton("93.184.216.35"))])
    res = dnsclient.parse_response(data)
    h = res["header"]
    assert h["qr"] and h["rd"] and h["ra"] and h["rcode_name"] == "NOERROR"
    assert res["records"][0]["type"] == "CNAME" and res["records"][0]["value"] == "cdn.example.com"
    assert [r["value"] for r in dnsclient.answers(res, "A")] == ["93.184.216.34", "93.184.216.35"]
    assert res["records"][1]["ttl"] == 60


def test_compression_loop_is_rejected():
    data = struct.pack("!HHHHHH", 1, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"   # pointer to itself
    with pytest.raises(dnsclient.DNSError):
        dnsclient.parse_response(data)


class FakeDNS:
    """A tiny DNS server on localhost: answers over UDP, or sets TC and answers over TCP."""

    def __init__(self, truncate=False):
        self.truncate = truncate
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(1)
        threading.Thread(target=self._udp, daemon=True).start()
        threading.Thread(target=self._tcp, daemon=True).start()

    def _answer(self, q, tc):
        qid = struct.unpack_from("!H", q)[0]
        name, _ = dnsclient.read_name(q, 12)
        if name.startswith("nx-"):
            return _response(qid, name, [], flags=0x8183)                 # NXDOMAIN
        return _response(qid, name, [(1, 120, socket.inet_aton("10.1.2.3"))], tc=tc)

    def _udp(self):
        while True:
            q, addr = self.udp.recvfrom(512)
            self.udp.sendto(b"\x00\x00junk-with-wrong-id", addr)           # must be ignored
            self.udp.sendto(self._answer(q, self.truncate), addr)

    def _tcp(self):
        while True:
            c, _ = self.tcp.accept()
            n = struct.unpack("!H", c.recv(2))[0]
            q = c.recv(n)
            a = self._answer(q, False)
            c.sendall(struct.pack("!H", len(a)) + a)
            c.close()


def test_query_over_udp_ignores_wrong_id():
    srv = FakeDNS()
    r = dnsclient.query("127.0.0.1", "github.com", port=srv.port)
    assert r["transport"] == "UDP"
    assert dnsclient.answers(r)[0]["value"] == "10.1.2.3"
    assert r["query_bytes"] == 28 and r["ms"] >= 0


def test_truncated_answer_retries_over_tcp():
    srv = FakeDNS(truncate=True)
    r = dnsclient.query("127.0.0.1", "big.example.com", port=srv.port)
    assert r["transport"].startswith("TCP")
    assert dnsclient.answers(r)[0]["value"] == "10.1.2.3"


def test_nxdomain():
    srv = FakeDNS()
    r = dnsclient.query("127.0.0.1", "nx-abc.example.com", port=srv.port)
    assert r["header"]["rcode_name"] == "NXDOMAIN" and not dnsclient.answers(r)


def test_benchmark_stats_and_resolver_names():
    s = dnsbench.summarize([10, 12], [1, 2, 3, 4, 100], [40, 60], total=10, answered=9)
    assert s["cached_ms"] == 3 and s["uncached_ms"] == 50 and s["answered_pct"] == 90.0
    rs = dnsbench.resolver_list(["192.168.1.1", "8.8.8.8"], "192.168.1.1")
    assert rs[0] == {"name": "Your router", "ip": "192.168.1.1", "kind": "router"}
    assert [r["ip"] for r in rs].count("8.8.8.8") == 1                      # no duplicates


# ---------------------------------------------------------------- traceroute
@pytest.mark.parametrize("line,hop,ip,rtts", [
    ("  1    <1 ms    <1 ms    <1 ms  192.168.1.1", 1, "192.168.1.1", [0.5, 0.5, 0.5]),
    ("  7    24 ms    23 ms    25 ms  72.14.211.36", 7, "72.14.211.36", [24, 23, 25]),
    ("  4     *        *        *     Request timed out.", 4, None, [None, None, None]),
    ("  5    12 ms     *       13 ms  10.0.0.1", 5, "10.0.0.1", [12, None, 13]),
    (" 3  10.20.30.1  11.812 ms  12.1 ms  11.9 ms", 3, "10.20.30.1", [11.812, 12.1, 11.9]),
    (" 9  * * *", 9, None, [None, None, None]),
    (" 6  100.64.0.1  5.1 ms 100.64.0.2  5.3 ms  5.2 ms", 6, "100.64.0.1", [5.1, 5.3, 5.2]),
])
def test_parse_trace_lines(line, hop, ip, rtts):
    h = traceroute.parse_trace_line(line)
    assert h["hop"] == hop and h["ip"] == ip and h["rtts"] == rtts


@pytest.mark.parametrize("line", ["Tracing route to 8.8.8.8 over a maximum of 30 hops", "",
                                  "traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets", "Trace complete."])
def test_trace_header_lines_ignored(line):
    assert traceroute.parse_trace_line(line) is None


def test_classify_ip():
    assert traceroute.classify_ip("192.168.1.1") == "private"
    assert traceroute.classify_ip("100.72.0.1") == "cgnat"
    assert traceroute.classify_ip("8.8.8.8") == "public"
    assert traceroute.classify_ip(None) is None


def test_trace_summary():
    def hop(n, ip, rtt, asn=None):
        h = {"hop": n, "ip": ip, "rtts": [rtt] * 3 if rtt else [None] * 3}
        h.update(traceroute.hop_stats(h["rtts"]))
        if asn:
            h.update(asn=asn, as_name="AS%d net" % asn)
        return h
    tr = {"ip": "8.8.8.8", "hops": [hop(1, "192.168.1.1", 1), hop(2, None, None), hop(3, "49.44.1.1", 9, 55836),
                                    hop(4, "49.44.1.2", 10, 55836), hop(5, "72.14.1.1", 40, 15169),
                                    hop(6, "8.8.8.8", 41, 15169)]}
    s = traceroute.summarize(tr)
    assert s["reached"] and s["hops"] == 6 and s["silent_hops"] == 1 and s["rtt_ms"] == 41
    assert [a["asn"] for a in s["as_path"]] == [55836, 15169]
    assert s["jump"] == {"from": 4, "to": 5, "ms": 30.0}


@pytest.mark.parametrize("target,ok", [("https://github.com/x", True), ("8.8.8.8", True), ("224.0.0.1", False),
                                       ("bad name", False), ("0.0.0.0", False)])
def test_resolve_target_validation(target, ok):
    if not ok:
        with pytest.raises(ValueError):
            traceroute.resolve_target(target)
    elif target[0].isdigit():
        assert traceroute.resolve_target(target) == (target, target)


# ---------------------------------------------------------------- traffic / connections
@pytest.mark.parametrize("proto,sport,dport,cat", [
    ("tcp", 51000, 443, "HTTPS (TLS over TCP)"), ("udp", 443, 51000, "QUIC (HTTP/3)"),
    ("udp", 53000, 53, "DNS"), ("udp", 5353, 5353, "mDNS"), ("tcp", 40000, 5601, "NetScope"),
    ("udp", 40000, 19305, "Calls (STUN / RTP)"), ("tcp", 40000, 41000, "Other TCP")])
def test_classify_ports(proto, sport, dport, cat):
    assert traffic.classify_ports(proto, sport, dport) == cat
    assert cat in traffic.CATEGORIES and traffic.CATEGORIES[cat][0] in traffic.GROUPS


def test_classify_scapy_packets():
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.l2 import ARP, Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    assert traffic.classify(Ether() / ARP()) == "ARP"
    assert traffic.classify(Ether() / IP() / ICMP()) == "ICMP"
    assert traffic.classify(Ether() / IP() / TCP(sport=50000, dport=443)) == "HTTPS (TLS over TCP)"
    pkt = Ether() / IP(src="8.8.8.8") / UDP(sport=53, dport=50000) / DNS(
        qr=1, qd=DNSQR(qname="youtube.com"), an=DNSRR(rrname="youtube.com", type="A", rdata="142.250.1.1"))
    pkt = Ether(bytes(pkt))
    assert traffic.classify(pkt) == "DNS"
    assert traffic.dns_answers(pkt) == ("youtube.com", ["142.250.1.1"])


def test_listen_scope():
    assert connections.listen_scope("0.0.0.0")[0] == "all interfaces"
    assert connections.listen_scope("127.0.0.1")[0] == "this computer only"
    assert connections.scope("8.8.8.8") == "internet"
    assert connections.scope("192.168.1.5") == "local network"


def test_connection_snapshot_shape():
    snap = connections.ConnectionMonitor(lambda ip: None).snapshot()
    assert set(connections.STATE_ORDER) <= set(snap["counts"])
    assert snap["tcp_total"] == len(snap["tcp"]) or snap["tcp_total"] > 500
