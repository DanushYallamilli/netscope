"""
Quality engine: ICMP ping tests and the maths behind every quality metric.

Everything here is a pure function except `ping_host`, so the formulas can be
unit-tested (see tests/test_quality.py).
"""

import platform
import re
import subprocess

# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def compute_stats(rtts):
    """Turn a list of round-trip times (ms, None = no reply) into quality stats.

    latency  : min / avg / max / median of the replies that came back
    loss     : (sent - received) / sent * 100
    jitter   : mean absolute difference between consecutive RTTs
    jitter_rfc : RFC 3550 smoothed jitter, J = J + (|D| - J) / 16,
                 where D is the difference between consecutive RTTs.
                 Each new sample moves J only 1/16 of the way, so one spike
                 doesn't dominate - this is what VoIP/RTP uses.
    """
    sent = len(rtts)
    got = [r for r in rtts if r is not None]
    res = {
        "sent": sent,
        "received": len(got),
        "loss_pct": round(100.0 * (sent - len(got)) / sent, 2) if sent else None,
        "min": None, "avg": None, "max": None, "median": None,
        "jitter": None, "jitter_rfc": None,
    }
    if not got:
        return res
    s = sorted(got)
    n = len(s)
    median = s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2
    diffs = [abs(got[i] - got[i - 1]) for i in range(1, len(got))]
    j = 0.0
    for d in diffs:
        j += (d - j) / 16.0
    res.update(
        min=round(s[0], 3),
        avg=round(sum(s) / n, 3),
        max=round(s[-1], 3),
        median=round(median, 3),
        jitter=round(sum(diffs) / len(diffs), 3) if diffs else 0.0,
        jitter_rfc=round(j, 3),
    )
    return res


def classify(stats, th):
    """green / amber / red / grey for a device's latest ping result.

    th = thresholds dict: green_latency, amber_latency (ms), green_loss, amber_loss (%)
    """
    if not stats or stats.get("received", 0) == 0 or stats.get("avg") is None:
        return "grey"
    lat, loss = stats["avg"], stats.get("loss_pct") or 0
    if lat > th["amber_latency"] or loss > th["amber_loss"]:
        return "red"
    if lat >= th["green_latency"] or loss >= th["green_loss"]:
        return "amber"
    return "green"


def latency_score(avg_ms):
    """100 at <= 20 ms, falling linearly to 0 at 300 ms."""
    if avg_ms is None:
        return 0.0
    if avg_ms <= 20:
        return 100.0
    return max(0.0, 100.0 - (avg_ms - 20) * 100.0 / 280.0)


def loss_score(loss_pct):
    """100 at 0 % loss, 0 at 10 % or more."""
    if loss_pct is None:
        return 0.0
    return max(0.0, 100.0 - loss_pct * 10.0)


def health_score(device_stats, online_count, known_count):
    """Network health 0-100.

    = 40 % latency score + 40 % loss score + 20 % availability
    Latency and loss scores are averaged over devices that answered pings.
    Availability = online devices / known devices.
    """
    measured = [d for d in device_stats if d and d.get("avg") is not None]
    if not measured and not known_count:
        return None
    lat = sum(latency_score(d["avg"]) for d in measured) / len(measured) if measured else 0
    los = sum(loss_score(d.get("loss_pct")) for d in measured) / len(measured) if measured else 0
    avail = 100.0 * online_count / known_count if known_count else 0
    return round(0.4 * lat + 0.4 * los + 0.2 * avail, 1)


# ---------------------------------------------------------------------------
# Sending pings
# ---------------------------------------------------------------------------

_ICMPLIB_MODE = None    # None = not tried yet, True/False = privileged mode that works, "off"


def icmplib_mode():
    """Find out once which icmplib mode works on this computer.

    Returns False (unprivileged ICMP sockets), True (raw sockets, needs admin/root)
    or None (icmplib unusable - fall back to the OS ping command).
    """
    global _ICMPLIB_MODE
    if _ICMPLIB_MODE in (True, False):
        return _ICMPLIB_MODE
    if _ICMPLIB_MODE == "off":
        return None
    try:
        import icmplib
    except ImportError:
        _ICMPLIB_MODE = "off"
        return None
    for priv in (False, True):
        try:
            icmplib.ping("127.0.0.1", count=1, timeout=0.5, privileged=priv)
            _ICMPLIB_MODE = priv
            return priv
        except Exception:
            continue
    _ICMPLIB_MODE = "off"
    return None


def _icmplib_ping(ip, count, interval, timeout):
    """ICMP echo with icmplib. Returns per-packet RTT list (None = lost)."""
    global _ICMPLIB_MODE
    import icmplib
    modes = [_ICMPLIB_MODE] if _ICMPLIB_MODE in (True, False) else [False, True]
    last_err = None
    for priv in modes:
        try:
            h = icmplib.ping(ip, count=count, interval=interval, timeout=timeout, privileged=priv)
            _ICMPLIB_MODE = priv
            rtts = list(h.rtts)
            # icmplib only returns RTTs of replies; pad lost ones as None (order of
            # losses is unknown, so they go at the end - fine for loss/latency)
            return rtts + [None] * (h.packets_sent - len(rtts))
        except Exception as e:     # permission errors etc.
            last_err = e
    _ICMPLIB_MODE = "off"
    raise RuntimeError(last_err)


_RTT_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.I)


def _system_ping(ip, count, interval, timeout):
    """Fallback: run the OS `ping` command and parse 'time=12.3 ms' from each reply."""
    win = platform.system() == "Windows"
    if win:
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), ip]
    elif platform.system() == "Darwin":
        cmd = ["ping", "-c", str(count), "-i", str(max(interval, 0.1)), "-W", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", str(count), "-i", str(max(interval, 0.2)), "-W", str(max(1, int(timeout))), ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=count * (interval + timeout) + 5,
                             creationflags=0x08000000 if win else 0).stdout
    except Exception:
        return [None] * count
    rtts = [float(m) for m in _RTT_RE.findall(out)]
    if win:
        rtts = [r if r > 0 else 0.5 for r in rtts]     # Windows prints "time<1ms"
    return rtts + [None] * max(0, count - len(rtts))


def ping_host(ip, count=20, interval=0.2, timeout=1.0):
    """Send `count` ICMP echo requests and return compute_stats() of the replies."""
    if _ICMPLIB_MODE != "off":
        try:
            return compute_stats(_icmplib_ping(ip, count, interval, timeout))
        except Exception:
            pass
    return compute_stats(_system_ping(ip, count, interval, timeout))


def ping_engine_name():
    if _ICMPLIB_MODE is True:
        return "icmplib (raw socket)"
    if _ICMPLIB_MODE is False:
        return "icmplib (unprivileged)"
    if _ICMPLIB_MODE == "off":
        return "system ping command"
    return "not used yet"
