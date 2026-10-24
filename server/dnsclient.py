"""
A small DNS client written from scratch (RFC 1035), so you can see exactly what
goes on the wire.

Used by:
  * the DNS benchmark and the lookup inspector (DNS page)
  * traceroute, to find which network (autonomous system) each router belongs to

A DNS message is:

    +---------------------+
    | Header   (12 bytes) |  ID, flags, and how many records are in each section
    +---------------------+
    | Question            |  QNAME (length-prefixed labels), QTYPE, QCLASS
    +---------------------+
    | Answer              |  resource records: NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA
    | Authority           |
    | Additional          |
    +---------------------+

Queries go over UDP port 53. If the answer is too big for one UDP datagram the
server sets the TC (truncated) flag and we repeat the query over TCP, where each
message is prefixed with a 2-byte length.
"""

import random
import socket
import struct
import time

TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DNSError(Exception):
    pass


# ---------------------------------------------------------------------------
# Building a query
# ---------------------------------------------------------------------------

def encode_name(name):
    """www.example.com -> b'\\x03www\\x07example\\x03com\\x00'"""
    name = name.strip().rstrip(".")
    if not name or len(name) > 253:
        raise DNSError("Enter a valid domain name")
    out = bytearray()
    for label in name.split("."):
        try:
            b = label.encode("idna")
        except UnicodeError:
            raise DNSError("Invalid domain name")
        if not b or len(b) > 63:
            raise DNSError("Invalid domain name")
        if not all(chr(c).isalnum() or c in (45, 95) for c in b):   # letters, digits, - and _
            raise DNSError("Invalid character in domain name")
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def build_query(name, qtype="A", qid=None, recursion_desired=True):
    """Return (id, packet bytes)."""
    if qtype not in TYPES:
        raise DNSError("Unsupported record type")
    qid = random.randint(0, 0xFFFF) if qid is None else qid
    flags = 0x0100 if recursion_desired else 0x0000          # RD bit = "please recurse for me"
    header = struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0)  # 1 question, 0 answers...
    question = encode_name(name) + struct.pack("!HH", TYPES[qtype], 1)   # QCLASS 1 = IN (Internet)
    return qid, header + question


def query_segments(packet):
    """Byte ranges of each part of a query, for the annotated hex view."""
    name_end = packet.index(0, 12) + 1
    return [
        {"part": "header", "start": 0, "end": 12},
        {"part": "qname", "start": 12, "end": name_end},
        {"part": "qtype_qclass", "start": name_end, "end": name_end + 4},
    ]


# ---------------------------------------------------------------------------
# Parsing a response
# ---------------------------------------------------------------------------

def read_name(data, off):
    """Read a (possibly compressed) domain name. Returns (name, offset after it).

    Compression: a byte starting with binary 11 is a pointer - the next 14 bits
    give an earlier offset in the message where the rest of the name continues.
    """
    labels, jumped, end, hops = [], False, None, 0
    while True:
        if off >= len(data):
            raise DNSError("Truncated name")
        n = data[off]
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(data):
                raise DNSError("Truncated pointer")
            ptr = ((n & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            off, jumped, hops = ptr, True, hops + 1
            if hops > 30:
                raise DNSError("Compression loop")
            continue
        if n == 0:
            off += 1
            break
        labels.append(data[off + 1:off + 1 + n].decode("ascii", errors="replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def decode_rdata(data, off, rtype, rdlen):
    rd = data[off:off + rdlen]
    if rtype == 1 and rdlen == 4:
        return socket.inet_ntoa(rd)
    if rtype == 28 and rdlen == 16:
        return socket.inet_ntop(socket.AF_INET6, rd)
    if rtype in (2, 5, 12):
        return read_name(data, off)[0]
    if rtype == 15:
        pref = struct.unpack_from("!H", data, off)[0]
        return "%d %s" % (pref, read_name(data, off + 2)[0])
    if rtype == 16:
        parts, i = [], 0
        while i < len(rd):
            n = rd[i]
            parts.append(rd[i + 1:i + 1 + n].decode("utf-8", errors="replace"))
            i += 1 + n
        return "".join(parts)
    if rtype == 6:
        mname, o = read_name(data, off)
        rname, o = read_name(data, o)
        serial, refresh, retry, expire, minimum = struct.unpack_from("!IIIII", data, o)
        return "%s %s serial %d, negative-cache TTL %d s" % (mname, rname, serial, minimum)
    return rd.hex()


def parse_response(data):
    if len(data) < 12:
        raise DNSError("Response too short")
    qid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", data)
    header = {
        "id": qid,
        "qr": bool(flags & 0x8000),     # 1 = this is a response
        "opcode": (flags >> 11) & 0xF,
        "aa": bool(flags & 0x0400),     # authoritative answer
        "tc": bool(flags & 0x0200),     # truncated
        "rd": bool(flags & 0x0100),     # recursion desired (copied from query)
        "ra": bool(flags & 0x0080),     # recursion available
        "rcode": flags & 0xF,
        "rcode_name": RCODES.get(flags & 0xF, str(flags & 0xF)),
        "qdcount": qd, "ancount": an, "nscount": ns, "arcount": ar,
    }
    off = 12
    questions = []
    for _ in range(qd):
        name, off = read_name(data, off)
        qtype, qclass = struct.unpack_from("!HH", data, off)
        off += 4
        questions.append({"name": name, "type": TYPE_NAMES.get(qtype, str(qtype))})
    records = []
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            name, off = read_name(data, off)
            if off + 10 > len(data):
                raise DNSError("Truncated record")
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
            off += 10
            if rtype == 41:                      # EDNS OPT pseudo-record - not a real answer
                off += rdlen
                continue
            records.append({"section": section, "name": name, "type": TYPE_NAMES.get(rtype, str(rtype)),
                            "ttl": ttl, "value": decode_rdata(data, off, rtype, rdlen)})
            off += rdlen
    return {"header": header, "questions": questions, "records": records}


# ---------------------------------------------------------------------------
# Sending
# ---------------------------------------------------------------------------

def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        b = s.recv(n - len(buf))
        if not b:
            raise DNSError("Connection closed")
        buf += b
    return buf


def _query_tcp(server, packet, timeout, port):
    with socket.create_connection((server, port), timeout=timeout) as s:
        s.sendall(struct.pack("!H", len(packet)) + packet)
        n = struct.unpack("!H", _recv_exact(s, 2))[0]
        return _recv_exact(s, n)


def query(server, name, qtype="A", timeout=2.0, port=53):
    """Send one query and return the parsed response plus timing and sizes.

    Raises socket.timeout if no answer arrives in time.
    """
    qid, packet = build_query(name, qtype)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        deadline = time.perf_counter() + timeout
        t0 = time.perf_counter()
        s.sendto(packet, (server, port))
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                raise socket.timeout("timed out")
            s.settimeout(left)
            data, addr = s.recvfrom(4096)
            # The 16-bit ID ties the answer to our question. Anything else is ignored
            # (a random ID is also what makes DNS answers harder to spoof).
            if addr[0] == server and len(data) >= 12 and struct.unpack_from("!H", data)[0] == qid:
                break
        ms = (time.perf_counter() - t0) * 1000
    finally:
        s.close()
    transport = "UDP"
    res = parse_response(data)
    if res["header"]["tc"]:
        t0 = time.perf_counter()
        data = _query_tcp(server, packet, timeout, port)
        ms = (time.perf_counter() - t0) * 1000
        res = parse_response(data)
        transport = "TCP (answer was truncated over UDP)"
    res.update(ms=round(ms, 3), server=server, transport=transport, query_bytes=len(packet),
               response_bytes=len(data), query_hex=packet.hex(), segments=query_segments(packet),
               name=name, qtype=qtype)
    return res


def answers(res, rtype="A"):
    return [r for r in res.get("records", []) if r["section"] == "answer" and r["type"] == rtype]
