"""Unit tests for the measurement maths.  Run:  python -m pytest tests"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "agent"))

import pytest  # noqa: E402

import agent  # noqa: E402
from server import discovery, quality  # noqa: E402

TH = {"green_latency": 20, "amber_latency": 100, "green_loss": 1, "amber_loss": 5}


# ---------------------------------------------------------------- latency / loss / jitter
def test_basic_stats():
    s = quality.compute_stats([10, 20, 30, 40])
    assert s["min"] == 10 and s["max"] == 40
    assert s["avg"] == 25
    assert s["median"] == 25
    assert s["loss_pct"] == 0


def test_loss_counts_missing_replies():
    s = quality.compute_stats([10, None, 12, None, 11])
    assert s["sent"] == 5 and s["received"] == 3
    assert s["loss_pct"] == 40.0


def test_all_lost():
    s = quality.compute_stats([None] * 4)
    assert s["loss_pct"] == 100.0 and s["avg"] is None and s["jitter"] is None


def test_mean_jitter():
    # differences: |20-10|=10, |10-20|=10, |30-10|=20  -> mean 13.333
    s = quality.compute_stats([10, 20, 10, 30])
    assert s["jitter"] == pytest.approx(13.333, abs=1e-3)


def test_rfc3550_jitter():
    # J = J + (|D| - J)/16 with D = 10, 10, 20
    j = 0.0
    for d in (10, 10, 20):
        j += (d - j) / 16
    s = quality.compute_stats([10, 20, 10, 30])
    assert s["jitter_rfc"] == pytest.approx(j, abs=1e-3)


def test_constant_latency_has_zero_jitter():
    s = quality.compute_stats([5, 5, 5, 5])
    assert s["jitter"] == 0 and s["jitter_rfc"] == 0


def test_agent_and_server_formulas_match():
    data = [3.1, None, 4.7, 2.2, 9.9, None, 3.3]
    assert agent.rtt_stats(data) == quality.compute_stats(data)


# ---------------------------------------------------------------- classification / health
@pytest.mark.parametrize("avg,loss,expected", [
    (5, 0, "green"), (19.9, 0.5, "green"), (20, 0, "amber"), (50, 0, "amber"),
    (5, 1, "amber"), (5, 3, "amber"), (101, 0, "red"), (5, 6, "red")])
def test_classify(avg, loss, expected):
    assert quality.classify({"avg": avg, "loss_pct": loss, "received": 5}, TH) == expected


def test_classify_no_reply_is_grey():
    assert quality.classify({"avg": None, "loss_pct": 100, "received": 0}, TH) == "grey"
    assert quality.classify(None, TH) == "grey"


def test_scores():
    assert quality.latency_score(10) == 100
    assert quality.latency_score(300) == 0
    assert quality.latency_score(160) == pytest.approx(50)
    assert quality.loss_score(0) == 100
    assert quality.loss_score(5) == 50
    assert quality.loss_score(15) == 0


def test_health_perfect_network():
    devs = [{"avg": 2, "loss_pct": 0}, {"avg": 8, "loss_pct": 0}]
    assert quality.health_score(devs, 2, 2) == 100


def test_health_weights():
    # latency 50, loss 50, availability 50 -> 0.4*50 + 0.4*50 + 0.2*50 = 50
    assert quality.health_score([{"avg": 160, "loss_pct": 5}], 1, 2) == 50


# ---------------------------------------------------------------- UDP receiver statistics
def test_udp_loss_and_out_of_order():
    st = agent.UdpStats()
    t = 1000.0
    for i, seq in enumerate([0, 1, 3, 2, 5, 6]):        # 4 never arrives, 2 arrives late
        st.add(seq, t + seq * 0.01, 1200, t + seq * 0.01 + 0.005)
    r = st.summary(sent=7)
    assert r["received"] == 6
    assert r["lost"] == 1
    assert r["loss_pct"] == pytest.approx(100 / 7, abs=1e-2)
    assert r["out_of_order"] == 1


def test_udp_duplicates_ignored():
    st = agent.UdpStats()
    st.add(0, 1.0, 100, 1.1)
    st.add(0, 1.0, 100, 1.2)
    assert st.received == 1 and st.duplicates == 1


def test_udp_jitter_ignores_clock_offset():
    """A constant clock difference between sender and receiver must not create jitter."""
    st = agent.UdpStats()
    for seq in range(10):
        send = seq * 0.01
        st.add(seq, send, 1200, send + 3600.0 + 0.002)   # receiver clock is 1 h ahead
    assert st.summary(10)["jitter_ms"] == 0


def test_udp_jitter_rfc3550():
    st = agent.UdpStats()
    transits = [0.010, 0.014, 0.010, 0.020]
    for seq, tr in enumerate(transits):
        st.add(seq, seq * 1.0, 1200, seq * 1.0 + tr)
    j = 0.0
    for a, b in zip(transits, transits[1:]):
        j += (abs(b - a) - j) / 16
    assert st.summary(4)["jitter_ms"] == pytest.approx(j * 1000, abs=1e-3)


# ---------------------------------------------------------------- MAC helpers
def test_normalize_mac():
    assert discovery.normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert discovery.normalize_mac("0:1a:2:3:4:5") == "00:1a:02:03:04:05"
    assert discovery.normalize_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert discovery.normalize_mac("ff:ff:ff:ff:ff:ff") is None
    assert discovery.normalize_mac("garbage") is None


@pytest.mark.parametrize("mac,rand", [
    ("da:a1:19:00:00:01", True), ("02:00:00:00:00:01", True), ("a6:00:00:00:00:00", True),
    ("ee:00:00:00:00:00", True), ("b8:27:eb:00:00:01", False), ("00:1a:11:00:00:00", False)])
def test_randomized_mac(mac, rand):
    assert discovery.is_randomized_mac(mac) is rand


# ---------------------------------------------------------------- end-to-end on loopback
def test_tcp_and_udp_loopback():
    ds = agent.DataServer("test-token", port=56901)
    ds.start()
    r = agent.run_test("tcp", "127.0.0.1", 56901, "test-token", {"duration": 1})
    assert r["avg_mbps"] > 0 and r["bytes"] > 0
    u = agent.run_test("udp", "127.0.0.1", 56901, "test-token", {"duration": 1, "rate_mbps": 5})
    assert u["sent"] > 0 and u["received"] > 0
    with pytest.raises(RuntimeError):
        agent.check_target("127.0.0.1", 56901, "wrong-token")
