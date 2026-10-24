#!/usr/bin/env python3
"""
NetScope Agent
==============

A small, standard-library-only program that you run on any machine you want
to run throughput tests to/from (a teammate's laptop, a lab PC, a Raspberry Pi).

    python agent.py --server 192.168.1.10 --token <token shown in NetScope Settings>

What it does
------------
1. Opens a TCP *control channel* to the NetScope server (default port 5600),
   registers itself and waits for test commands.
2. Runs a *data server* on port 5601 (TCP and UDP) so other NetScope nodes can
   run tests against it.
3. When told to, acts as the *client* side of a test and streams results back.

The NetScope server imports this same file, so the server and every agent use
exactly the same test code.

Tests implemented here (no iperf, no external libraries):
  * TCP throughput  - send/receive as fast as possible, Mbps per second
  * UDP test        - numbered, timestamped datagrams at a fixed bitrate;
                      the receiver measures loss, out-of-order and jitter
  * Latency under load - UDP echo RTT while idle vs. while a TCP upload
                      saturates the link (shows bufferbloat)

Every TCP connection starts with one JSON line containing the shared token,
so only NetScope nodes can use the data port.
"""

import argparse
import json
import os
import platform
import socket
import struct
import sys
import threading
import time
import uuid

CONTROL_PORT = 5600
DATA_PORT = 5601
CHUNK = 64 * 1024            # TCP test write size: 64 KB
MAX_TEST_SECONDS = 60

# UDP packet formats
#   Data packet : b'D' | test_id (16 bytes) | sequence (uint64) | send time (double) | padding
#   Echo packet : b'E' | anything  -> receiver sends the same bytes straight back
UDP_HDR = struct.Struct("!c16sQd")


def now() -> float:
    return time.perf_counter()


def wall() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def send_json(sock: socket.socket, obj: dict) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode())


def recv_line(sock: socket.socket, limit: int = 65536) -> str:
    """Read one newline-terminated line from a TCP socket."""
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            break
        if b == b"\n":
            break
        buf += b
        if len(buf) > limit:
            raise ValueError("line too long")
    return buf.decode(errors="replace")


def rtt_stats(rtts):
    """Latency / jitter / loss from a list of RTTs in ms (None = lost probe).

    Same formulas as server/quality.py:
      jitter_mean = mean |RTT[i] - RTT[i-1]| over consecutive replies
      jitter_rfc  = RFC 3550 smoothed jitter, J += (|D| - J) / 16
    """
    sent = len(rtts)
    got = [r for r in rtts if r is not None]
    out = {"sent": sent, "received": len(got),
           "loss_pct": round(100.0 * (sent - len(got)) / sent, 2) if sent else None}
    if not got:
        out.update(min=None, avg=None, max=None, median=None, jitter=None, jitter_rfc=None)
        return out
    s = sorted(got)
    n = len(s)
    median = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
    diffs = [abs(got[i] - got[i - 1]) for i in range(1, len(got))]
    j = 0.0
    for d in diffs:
        j += (d - j) / 16.0
    out.update(min=round(s[0], 3), avg=round(sum(s) / n, 3), max=round(s[-1], 3),
               median=round(median, 3),
               jitter=round(sum(diffs) / len(diffs), 3) if diffs else 0.0,
               jitter_rfc=round(j, 3))
    return out


# ---------------------------------------------------------------------------
# DATA SERVER  (the "receiver" side of every test)
# ---------------------------------------------------------------------------

class UdpStats:
    """Per-test statistics kept by the UDP receiver."""

    def __init__(self):
        self.received = 0
        self.bytes = 0
        self.highest_seq = -1
        self.out_of_order = 0
        self.duplicates = 0
        self.seen = set()
        self.jitter = 0.0          # RFC 3550 smoothed jitter, in seconds
        self.prev_transit = None
        self.first_rx = None
        self.last_rx = None

    def add(self, seq: int, send_ts: float, size: int, rx_ts: float) -> None:
        if seq in self.seen:
            self.duplicates += 1
            return
        self.seen.add(seq)
        self.received += 1
        self.bytes += size
        if seq < self.highest_seq:
            self.out_of_order += 1     # arrived after a later-numbered packet
        else:
            self.highest_seq = seq
        # RFC 3550: transit = arrival - send time. The two clocks differ, but the
        # constant offset cancels out in D = transit_i - transit_(i-1).
        transit = rx_ts - send_ts
        if self.prev_transit is not None:
            d = abs(transit - self.prev_transit)
            self.jitter += (d - self.jitter) / 16.0
        self.prev_transit = transit
        if self.first_rx is None:
            self.first_rx = rx_ts
        self.last_rx = rx_ts

    def summary(self, sent: int) -> dict:
        dur = (self.last_rx - self.first_rx) if self.first_rx and self.last_rx else 0
        expected_by_seq = self.highest_seq + 1
        lost = max(sent - self.received, 0) if sent else max(expected_by_seq - self.received, 0)
        base = sent or expected_by_seq
        return {
            "sent": sent,
            "received": self.received,
            "lost": lost,
            "loss_pct": round(100.0 * lost / base, 3) if base else None,
            "out_of_order": self.out_of_order,
            "duplicates": self.duplicates,
            "jitter_ms": round(self.jitter * 1000, 3),
            "throughput_mbps": round(self.bytes * 8 / dur / 1e6, 3) if dur > 0 else 0.0,
            "receive_seconds": round(dur, 3),
        }


class DataServer:
    """Listens on TCP and UDP <port>. Handles requests from other NetScope nodes."""

    def __init__(self, token: str, port: int = DATA_PORT, host: str = "0.0.0.0", name: str = ""):
        self.token = token
        self.port = port
        self.host = host
        self.name = name or socket.gethostname()
        self.udp_tests = {}            # test_id(bytes) -> UdpStats
        self.lock = threading.Lock()
        self._stop = threading.Event()

    def start(self) -> None:
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((self.host, self.port))
        self.tcp.listen(32)
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
        except OSError:
            pass
        self.udp.bind((self.host, self.port))
        threading.Thread(target=self._tcp_loop, daemon=True).start()
        threading.Thread(target=self._udp_loop, daemon=True).start()

    # --- UDP: echo probes and test datagrams ---------------------------------
    def _udp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(65535)
            except OSError:
                continue
            rx = wall()
            if not data:
                continue
            kind = data[:1]
            if kind == b"E":
                try:
                    self.udp.sendto(data, addr)
                except OSError:
                    pass
            elif kind == b"D" and len(data) >= UDP_HDR.size:
                _, tid, seq, ts = UDP_HDR.unpack_from(data)
                with self.lock:
                    st = self.udp_tests.get(tid)
                    if st is not None:      # unknown test ids are ignored
                        st.add(seq, ts, len(data), rx)

    # --- TCP: one JSON header line, then the requested behaviour -------------
    def _tcp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self.tcp.accept()
            except OSError:
                continue
            threading.Thread(target=self._handle_tcp, args=(conn,), daemon=True).start()

    def _handle_tcp(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            hdr = json.loads(recv_line(conn, 4096) or "{}")
            if hdr.get("token") != self.token:
                send_json(conn, {"error": "bad token"})
                return
            kind = hdr.get("kind")
            if kind == "hello":
                send_json(conn, {"ok": True, "name": self.name})
            elif kind == "tcp_up":
                # Client sends; we count bytes until the client closes its side.
                send_json(conn, {"ok": True})
                conn.settimeout(MAX_TEST_SECONDS + 10)
                total, t0 = 0, None
                while True:
                    b = conn.recv(256 * 1024)
                    if not b:
                        break
                    if t0 is None:
                        t0 = now()
                    total += len(b)
                dt = (now() - t0) if t0 else 0
                send_json(conn, {"bytes": total, "seconds": round(dt, 4)})
            elif kind == "tcp_down":
                # We send as fast as possible for <duration> seconds.
                dur = min(float(hdr.get("duration", 10)), MAX_TEST_SECONDS)
                send_json(conn, {"ok": True})
                payload = os.urandom(CHUNK)
                end = now() + dur
                while now() < end:
                    conn.sendall(payload)
            elif kind == "udp_start":
                tid = bytes.fromhex(hdr["test_id"])
                with self.lock:
                    self.udp_tests[tid] = UdpStats()
                send_json(conn, {"ok": True})
            elif kind == "udp_result":
                tid = bytes.fromhex(hdr["test_id"])
                with self.lock:
                    st = self.udp_tests.pop(tid, None)
                send_json(conn, st.summary(int(hdr.get("sent", 0))) if st else {"error": "unknown test"})
            else:
                send_json(conn, {"error": "unknown kind"})
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# TEST CLIENTS  (the "sender/controller" side of every test)
# ---------------------------------------------------------------------------

def _connect(target: str, port: int, token: str, header: dict, timeout: float = 5) -> socket.socket:
    s = socket.create_connection((target, port), timeout=timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    send_json(s, dict(header, token=token))
    reply = json.loads(recv_line(s) or "{}")
    if not reply.get("ok"):
        s.close()
        raise RuntimeError(reply.get("error", "target refused the test"))
    return s


def check_target(target: str, port: int, token: str) -> dict:
    s = socket.create_connection((target, port), timeout=3)
    send_json(s, {"token": token, "kind": "hello"})
    r = json.loads(recv_line(s) or "{}")
    s.close()
    if not r.get("ok"):
        raise RuntimeError(r.get("error", "no NetScope data server on target"))
    return r


def udp_echo_rtt(target: str, port: int, timeout: float = 1.0, sock=None):
    """One UDP echo probe to a NetScope data server. Returns RTT in ms or None."""
    own = sock is None
    if own:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    probe = b"E" + uuid.uuid4().bytes
    t0 = now()
    try:
        sock.sendto(probe, (target, port))
        while True:
            data, _ = sock.recvfrom(2048)
            if data == probe:
                return (now() - t0) * 1000
    except (socket.timeout, OSError):
        return None
    finally:
        if own:
            sock.close()


class _Counter:
    def __init__(self):
        self.n = 0
        self.lock = threading.Lock()

    def add(self, k):
        with self.lock:
            self.n += k


def _ticker(counter: _Counter, duration: float, on_tick, stop: threading.Event, series: list):
    """Every second, report how many bits moved in that second."""
    start = now()
    last_n, last_t, sec = 0, start, 0
    while not stop.is_set() and sec < duration:
        time.sleep(max(0.0, start + sec + 1 - now()))
        t = now()
        n = counter.n
        mbps = (n - last_n) * 8 / (t - last_t) / 1e6
        sec += 1
        series.append(round(mbps, 3))
        if on_tick:
            on_tick({"second": sec, "mbps": round(mbps, 3)})
        last_n, last_t = n, t


def run_tcp(target, port, token, duration=10, direction="up", streams=1, on_tick=None):
    """TCP throughput test.

    direction="up":   this machine -> target   (we send)
    direction="down": target -> this machine   (target sends)
    """
    duration = max(1, min(float(duration), MAX_TEST_SECONDS))
    streams = max(1, min(int(streams), 4))
    counter, stop, series = _Counter(), threading.Event(), []
    results, errors = [], []
    payload = os.urandom(CHUNK)
    socks = [_connect(target, port, token, {"kind": "tcp_" + direction, "duration": duration})
             for _ in range(streams)]

    def stream(s):
        try:
            s.settimeout(duration + 15)
            end = now() + duration
            if direction == "up":
                while now() < end:
                    s.sendall(payload)
                    counter.add(len(payload))
                s.shutdown(socket.SHUT_WR)          # tell receiver we're done
                results.append(json.loads(recv_line(s) or "{}"))
            else:
                while True:
                    b = s.recv(256 * 1024)
                    if not b:
                        break
                    counter.add(len(b))
        except Exception as e:
            errors.append(str(e))
        finally:
            s.close()

    t0 = now()
    tick = threading.Thread(target=_ticker, args=(counter, duration, on_tick, stop, series), daemon=True)
    tick.start()
    threads = [threading.Thread(target=stream, args=(s,), daemon=True) for s in socks]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    stop.set()
    tick.join(timeout=2)
    elapsed = now() - t0
    if direction == "up" and results:
        # Use what the receiver actually got, over the receiver's own timing.
        total = sum(r.get("bytes", 0) for r in results)
        secs = max(r.get("seconds", 0) for r in results) or elapsed
    else:
        total, secs = counter.n, elapsed
    if errors and not total:
        raise RuntimeError(errors[0])
    return {"bytes": total, "seconds": round(secs, 3),
            "avg_mbps": round(total * 8 / secs / 1e6, 3) if secs else 0,
            "series_mbps": series, "streams": streams, "direction": direction,
            "errors": errors}


def run_udp(target, port, token, duration=10, rate_mbps=10, payload=1200, on_tick=None):
    """UDP test: send numbered, timestamped datagrams at a fixed bitrate.

    UDP has no congestion control, so unlike TCP it will NOT slow down when the
    link is full - packets are simply lost. The receiver counts what arrives.
    """
    duration = max(1, min(float(duration), MAX_TEST_SECONDS))
    rate_mbps = max(0.1, min(float(rate_mbps), 1000))
    payload = max(UDP_HDR.size, min(int(payload), 1472))   # 1472 = 1500 MTU - 20 IP - 8 UDP
    tid = uuid.uuid4().bytes
    ctl = _connect(target, port, token, {"kind": "udp_start", "test_id": tid.hex()})
    ctl.close()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    except OSError:
        pass
    pps = rate_mbps * 1e6 / 8 / payload
    pad = b"\x00" * (payload - UDP_HDR.size)
    counter, stop, series = _Counter(), threading.Event(), []
    tick = threading.Thread(target=_ticker, args=(counter, duration, on_tick, stop, series), daemon=True)
    sent = 0
    t0 = now()
    tick.start()
    while True:
        el = now() - t0
        if el >= duration:
            break
        due = int(el * pps)                      # packets that should have been sent by now
        while sent < due:
            sock.sendto(UDP_HDR.pack(b"D", tid, sent, wall()) + pad, (target, port))
            sent += 1
            counter.add(payload)
        time.sleep(0.0005)
    stop.set()
    tick.join(timeout=2)
    sock.close()
    time.sleep(0.5)                              # let the last packets arrive
    s = socket.create_connection((target, port), timeout=5)
    send_json(s, {"token": token, "kind": "udp_result", "test_id": tid.hex(), "sent": sent})
    res = json.loads(recv_line(s) or "{}")
    s.close()
    if "error" in res:
        raise RuntimeError(res["error"])
    res.update(target_rate_mbps=rate_mbps, payload_bytes=payload,
               send_rate_mbps=round(sent * payload * 8 / duration / 1e6, 3),
               series_mbps=series, seconds=duration)
    return res


def run_latency_under_load(target, port, token, duration=10, idle_seconds=5,
                           streams=2, probe_hz=5, on_tick=None):
    """Measure UDP echo RTT while the link is idle, then while a TCP upload fills it.

    If latency jumps a lot under load, packets are waiting in an oversized
    buffer somewhere on the path - this is called *bufferbloat*.
    """
    idle_rtts, load_rtts, rtt_series = [], [], []
    psock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interval = 1.0 / probe_hz
    t_start = now()

    def probe(store, phase):
        r = udp_echo_rtt(target, port, timeout=1.0, sock=psock)
        store.append(r)
        rtt_series.append({"t": round(now() - t_start, 2), "phase": phase,
                           "rtt_ms": round(r, 3) if r is not None else None})

    end = now() + idle_seconds
    while now() < end:
        probe(idle_rtts, "idle")
        time.sleep(interval)

    box = {}

    def load():
        try:
            box["tcp"] = run_tcp(target, port, token, duration, "up", streams,
                                 on_tick=lambda d: on_tick and on_tick(
                                     dict(d, rtt_ms=_last_rtt(load_rtts))))
        except Exception as e:
            box["error"] = str(e)

    lt = threading.Thread(target=load, daemon=True)
    lt.start()
    time.sleep(0.3)
    while lt.is_alive():
        probe(load_rtts, "loaded")
        time.sleep(interval)
    psock.close()
    if "error" in box:
        raise RuntimeError(box["error"])
    idle, loaded = rtt_stats(idle_rtts), rtt_stats(load_rtts)
    inc = None
    if idle.get("avg") and loaded.get("avg") is not None:
        inc = round(loaded["avg"] - idle["avg"], 3)
    return {"idle": idle, "loaded": loaded, "latency_increase_ms": inc,
            "tcp": box.get("tcp"), "rtt_series": rtt_series,
            "series_mbps": (box.get("tcp") or {}).get("series_mbps", [])}


def _last_rtt(lst):
    for r in reversed(lst):
        if r is not None:
            return round(r, 3)
    return None


def run_test(kind, target, port, token, params, on_tick=None):
    """Single entry point used by both the agent and the server."""
    p = dict(params or {})
    check_target(target, port, token)
    if kind == "tcp":
        return run_tcp(target, port, token, p.get("duration", 10), p.get("direction", "up"),
                       p.get("streams", 1), on_tick)
    if kind == "udp":
        return run_udp(target, port, token, p.get("duration", 10), p.get("rate_mbps", 10),
                       p.get("payload", 1200), on_tick)
    if kind == "lul":
        return run_latency_under_load(target, port, token, p.get("duration", 10),
                                      p.get("idle_seconds", 5), p.get("streams", 2), 5, on_tick)
    raise ValueError("unknown test kind: %s" % kind)


# ---------------------------------------------------------------------------
# CONTROL CHANNEL  (agent <-> NetScope server)
# ---------------------------------------------------------------------------

class AgentClient:
    def __init__(self, server, token, name, control_port=CONTROL_PORT, data_port=DATA_PORT):
        self.server, self.token, self.name = server, token, name
        self.control_port, self.data_port = control_port, data_port
        self.wlock = threading.Lock()
        self.sock = None
        self.busy = False

    def send(self, obj):
        with self.wlock:
            if self.sock:
                send_json(self.sock, obj)

    def run_forever(self):
        delay = 2
        while True:
            try:
                self._session()
                delay = 2
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print("[agent] disconnected: %s (retrying in %ds)" % (e, delay))
            time.sleep(delay)
            delay = min(delay * 2, 30)

    def _session(self):
        s = socket.create_connection((self.server, self.control_port), timeout=10)
        s.settimeout(None)
        self.sock = s
        self.send({"type": "register", "token": self.token, "name": self.name,
                   "hostname": socket.gethostname(), "os": platform.platform(),
                   "data_port": self.data_port, "version": 1})
        f = s.makefile("r", encoding="utf-8")
        first = json.loads(f.readline() or "{}")
        if first.get("type") != "registered":
            raise RuntimeError(first.get("message", "registration refused"))
        print("[agent] registered with %s as '%s'" % (self.server, self.name))
        for line in f:
            msg = json.loads(line)
            t = msg.get("type")
            if t == "ping":
                self.send({"type": "pong"})
            elif t == "run":
                threading.Thread(target=self._run, args=(msg,), daemon=True).start()
        raise RuntimeError("server closed the connection")

    def _run(self, msg):
        tid = msg["test_id"]
        print("[agent] running %s test -> %s" % (msg["kind"], msg["target_ip"]))
        try:
            res = run_test(msg["kind"], msg["target_ip"], int(msg["data_port"]), self.token,
                           msg.get("params"),
                           on_tick=lambda d: self.send(dict(d, type="tick", test_id=tid)))
            self.send({"type": "result", "test_id": tid, "result": res})
        except Exception as e:
            self.send({"type": "error", "test_id": tid, "message": str(e)})


def main():
    ap = argparse.ArgumentParser(description="NetScope agent")
    ap.add_argument("--server", required=True, help="IP address of the NetScope server")
    ap.add_argument("--token", required=True, help="Agent token from NetScope Settings")
    ap.add_argument("--name", default=socket.gethostname(), help="Display name")
    ap.add_argument("--control-port", type=int, default=CONTROL_PORT)
    ap.add_argument("--data-port", type=int, default=DATA_PORT)
    a = ap.parse_args()
    ds = DataServer(a.token, a.data_port, name=a.name)
    ds.start()
    print("[agent] data server listening on TCP+UDP %d" % a.data_port)
    try:
        AgentClient(a.server, a.token, a.name, a.control_port, a.data_port).run_forever()
    except KeyboardInterrupt:
        print("\n[agent] stopped")
        sys.exit(0)


if __name__ == "__main__":
    main()
