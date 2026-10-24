"""
DNS benchmark: which DNS resolver is fastest from *your* network?

For every resolver we measure two different things:

* Cached lookups - popular names (google.com, youtube.com...) queried twice.
  The second answer comes straight from the resolver's cache, so this mostly
  measures the network round trip to the resolver.

* Uncached lookups - a random, never-seen name such as
  ns-q7x2kd81.amazon.com. The resolver cannot have it cached, so it must do
  full recursion (root -> .com -> amazon.com's authoritative servers). This is
  exactly the step that failed for millions of users in the 2016 Dyn attack.
"""

import concurrent.futures as cf
import random
import socket
import statistics
import string
import time

from . import dnsclient

PUBLIC_RESOLVERS = [
    ("Cloudflare", "1.1.1.1"),
    ("Google", "8.8.8.8"),
    ("Quad9", "9.9.9.9"),
    ("OpenDNS", "208.67.222.222"),
]

POPULAR = ["google.com", "youtube.com", "facebook.com", "instagram.com", "wikipedia.org", "amazon.com",
           "github.com", "netflix.com", "whatsapp.com", "reddit.com", "linkedin.com", "microsoft.com"]
UNCACHED_BASES = ["google.com", "amazon.com", "microsoft.com", "apple.com", "netflix.com", "github.com"]
GAP = 0.02          # seconds between queries to the same resolver


def resolver_list(system_dns, gateway, extra=None):
    out, seen = [], set()

    def add(name, ip, kind):
        if ip and ip not in seen:
            seen.add(ip)
            out.append({"name": name, "ip": ip, "kind": kind})

    sys_dns = [ip for ip in (system_dns or []) if ip != gateway and not ip.startswith("127.")]
    for ip in system_dns or []:
        if ip == gateway:
            add("Your router", ip, "router")
        elif ip.startswith("127."):
            add("This computer's DNS service", ip, "system")
        else:
            n = sys_dns.index(ip) + 1
            add("Your system DNS" + (" %d" % n if len(sys_dns) > 1 else ""), ip, "system")
    for name, ip in PUBLIC_RESOLVERS:
        add(name, ip, "public")
    for ip in extra or []:
        add("Custom (%s)" % ip, ip, "custom")
    return out


def _rand_label(n=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def _pct(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return round(s[lo] + (s[hi] - s[lo]) * (k - lo), 2)


def summarize(first, cached, uncached, total, answered):
    return {
        "first_ms": _pct(first, 0.5),
        "cached_ms": _pct(cached, 0.5),
        "cached_p90": _pct(cached, 0.9),
        "cached_min": round(min(cached), 2) if cached else None,
        "uncached_ms": _pct(uncached, 0.5),
        "uncached_p90": _pct(uncached, 0.9),
        "answered_pct": round(100.0 * answered / total, 1) if total else None,
        "queries": total,
    }


def bench_resolver(r, on_progress=None, timeout=2.0):
    ip = r["ip"]
    first, cached, uncached, sample = [], [], [], None
    total = answered = 0
    errors = {}

    def ask(name):
        nonlocal total, answered
        total += 1
        try:
            res = dnsclient.query(ip, name, "A", timeout=timeout)
            answered += 1
            return res
        except (socket.timeout, TimeoutError):
            errors["timeout"] = errors.get("timeout", 0) + 1
        except OSError as e:
            errors[str(e)[:60]] = errors.get(str(e)[:60], 0) + 1
        except dnsclient.DNSError as e:
            errors[str(e)] = errors.get(str(e), 0) + 1
        return None

    steps = len(POPULAR) * 2 + len(UNCACHED_BASES)
    done = 0
    for d in POPULAR:
        a = ask(d)
        time.sleep(GAP)
        b = ask(d)
        time.sleep(GAP)
        if a and a["header"]["rcode"] == 0:
            first.append(a["ms"])
        if b and b["header"]["rcode"] == 0:
            cached.append(b["ms"])
        if d == "google.com" and (b or a):
            src = b or a
            sample = {"ips": [x["value"] for x in dnsclient.answers(src, "A")][:4],
                      "ttl": min([x["ttl"] for x in dnsclient.answers(src, "A")] or [0])}
        done += 2
        if on_progress:
            on_progress(r, done, steps)
        if total >= 4 and answered == 0:          # resolver unreachable - don't wait for every timeout
            break
    if answered:
        for base in UNCACHED_BASES:
            res = ask("ns-%s.%s" % (_rand_label(), base))
            time.sleep(GAP)
            # NXDOMAIN ("no such name") is the expected, correct answer here
            if res and res["header"]["rcode"] in (0, 3):
                uncached.append(res["ms"])
            done += 1
            if on_progress:
                on_progress(r, done, steps)
    out = dict(r)
    out.update(summarize(first, cached, uncached, total, answered))
    out.update(google=sample, errors=errors, reachable=answered > 0)
    return out


def run(resolvers, on_progress=None):
    with cf.ThreadPoolExecutor(max(1, len(resolvers))) as ex:
        results = list(ex.map(lambda r: bench_resolver(r, on_progress), resolvers))
    ok = [r for r in results if r["reachable"] and r["cached_ms"] is not None]
    fastest = min(ok, key=lambda r: r["cached_ms"]) if ok else None
    fastest_unc = min([r for r in ok if r["uncached_ms"] is not None],
                      key=lambda r: r["uncached_ms"], default=None)
    return {
        "ts": time.time(),
        "results": results,
        "fastest": fastest["name"] if fastest else None,
        "fastest_uncached": fastest_unc["name"] if fastest_unc else None,
        "popular": POPULAR,
        "uncached_bases": UNCACHED_BASES,
    }


def median(values):
    return statistics.median(values) if values else None
