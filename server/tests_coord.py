"""
Test coordinator.

* Runs the TCP control server (port 5600) that NetScope agents connect to.
* Keeps the list of registered agents.
* Starts throughput tests: tells the *source* node to run the test against the
  *target* node's data server, and relays per-second results to the browser.

The server itself is also a node ("server"), so you can test
server <-> agent as well as agent <-> agent.
"""

import asyncio
import json
import os
import sys
import time
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agent"))
import agent as engine  # noqa: E402  (the same test code the agents run)

from .events import events  # noqa: E402

TEST_KINDS = {"tcp": "TCP throughput", "udp": "UDP (loss / jitter)", "lul": "Latency under load"}


class Coordinator:
    def __init__(self, db, get_info):
        self.db = db
        self.get_info = get_info          # returns current network_info()
        self.agents = {}                  # id -> dict (includes 'writer')
        self.pending = {}                 # test_id -> asyncio.Future (agent-run tests)
        self.busy = set()                 # node ids currently in a test
        self.running = {}                 # test_id -> live info for the UI
        self.server = None

    # ----------------------------------------------------------------- agents
    async def start(self, port):
        self.server = await asyncio.start_server(self._handle, "0.0.0.0", port)
        asyncio.create_task(self._heartbeat())

    def public_agents(self):
        return [{k: v for k, v in a.items() if k != "writer"} for a in self.agents.values()]

    def nodes(self):
        info = self.get_info()
        server = {"id": "server", "name": "NetScope server (this machine)", "ip": info["ip"],
                  "hostname": info["hostname"], "is_server": True,
                  "busy": "server" in self.busy}
        return [server] + [dict(a, busy=a["id"] in self.busy) for a in self.public_agents()]

    async def _send(self, agent_id, obj):
        a = self.agents.get(agent_id)
        if not a:
            raise RuntimeError("agent disconnected")
        a["writer"].write((json.dumps(obj) + "\n").encode())
        await a["writer"].drain()

    async def _handle(self, reader, writer):
        peer_ip = writer.get_extra_info("peername")[0]
        local_ip = writer.get_extra_info("sockname")[0]
        agent_id = None
        try:
            line = await asyncio.wait_for(reader.readline(), 10)
            reg = json.loads(line or b"{}")
            if reg.get("type") != "register" or reg.get("token") != self.db.settings()["token"]:
                writer.write((json.dumps({"type": "error", "message": "bad token"}) + "\n").encode())
                await writer.drain()
                return
            name = (reg.get("name") or reg.get("hostname") or peer_ip)[:40]
            agent_id = "%s@%s" % (name, peer_ip)
            old = self.agents.pop(agent_id, None)
            if old:
                old["writer"].close()
            key = self.db.upsert_agent_device(peer_ip, name, reg.get("hostname"))
            self.agents[agent_id] = {
                "id": agent_id, "name": name, "hostname": reg.get("hostname"), "os": reg.get("os"),
                "ip": peer_ip, "data_port": int(reg.get("data_port") or 5601),
                "server_ip_seen": local_ip, "device_key": key,
                "connected_at": time.time(), "last_seen": time.time(), "writer": writer,
            }
            writer.write((json.dumps({"type": "registered", "agent_id": agent_id}) + "\n").encode())
            await writer.drain()
            events.emit({"type": "agents", "agents": self.nodes()})
            events.emit({"type": "devices_changed"})
            while True:
                line = await reader.readline()
                if not line:
                    break
                msg = json.loads(line)
                self.agents[agent_id]["last_seen"] = time.time()
                t = msg.get("type")
                tid = msg.get("test_id")
                if t == "tick" and tid:
                    self._tick(tid, msg)
                elif t in ("result", "error") and tid in self.pending:
                    fut = self.pending.pop(tid)
                    if not fut.done():
                        if t == "result":
                            fut.set_result(msg["result"])
                        else:
                            fut.set_exception(RuntimeError(msg.get("message", "agent error")))
        except Exception:
            pass
        finally:
            if agent_id and self.agents.get(agent_id, {}).get("writer") is writer:
                a = self.agents.pop(agent_id)
                if not any(x["ip"] == a["ip"] for x in self.agents.values()):
                    self.db.set_agent_flag(a["ip"], False)
                events.emit({"type": "agents", "agents": self.nodes()})
                events.emit({"type": "devices_changed"})
            try:
                writer.close()
            except Exception:
                pass

    async def _heartbeat(self):
        while True:
            await asyncio.sleep(15)
            for aid in list(self.agents):
                try:
                    await self._send(aid, {"type": "ping"})
                except Exception:
                    pass

    # ------------------------------------------------------------------ tests
    def _tick(self, tid, data):
        live = self.running.get(tid)
        if live is not None:
            live["series"].append(data.get("mbps"))
        events.emit({"type": "test_tick", "test_id": tid, "second": data.get("second"),
                     "mbps": data.get("mbps"), "rtt_ms": data.get("rtt_ms")})

    def _node(self, nid):
        if nid == "server":
            return {"id": "server", "ip": self.get_info()["ip"],
                    "data_port": int(self.db.settings()["data_port"])}
        a = self.agents.get(nid)
        if not a:
            raise ValueError("Agent '%s' is not connected" % nid)
        return a

    async def start_test(self, kind, source, target, params):
        if kind not in TEST_KINDS:
            raise ValueError("Unknown test type")
        if source == target:
            raise ValueError("Source and target must be different machines")
        src, dst = self._node(source), self._node(target)
        if source in self.busy or target in self.busy:
            raise ValueError("One of these machines is already running a test")
        # Address the source should use to reach the target
        if target == "server":
            target_ip = src["server_ip_seen"] if source != "server" else self.get_info()["ip"]
        else:
            target_ip = dst["ip"]
        p = {
            "duration": max(1, min(int(params.get("duration", 10)), 60)),
            "direction": "down" if params.get("direction") == "down" else "up",
            "streams": max(1, min(int(params.get("streams", 1)), 4)),
            "rate_mbps": max(0.1, min(float(params.get("rate_mbps", 10)), 1000)),
            "payload": max(64, min(int(params.get("payload", 1200)), 1472)),
            "idle_seconds": max(2, min(int(params.get("idle_seconds", 5)), 30)),
        }
        tid = uuid.uuid4().hex
        test = {
            "id": tid, "ts": time.time(), "kind": kind, "source": source, "target": target,
            "source_ip": src["ip"], "target_ip": target_ip, "params": p,
            "target_device": dst.get("device_key") if target != "server" else None,
        }
        self.db.add_test(test)
        self.busy.update({source, target})
        self.running[tid] = dict(test, series=[])
        events.emit({"type": "test_started", "test": test})
        events.emit({"type": "agents", "agents": self.nodes()})
        asyncio.create_task(self._run(test, dst["data_port"]))
        return test

    async def _run(self, test, port):
        tid = test["id"]
        token = self.db.settings()["token"]
        timeout = test["params"]["duration"] + test["params"]["idle_seconds"] + 30
        try:
            if test["source"] == "server":
                loop = asyncio.get_running_loop()
                result = await asyncio.wait_for(loop.run_in_executor(
                    None, lambda: engine.run_test(test["kind"], test["target_ip"], port, token,
                                                  test["params"], on_tick=lambda d: self._tick(tid, d))),
                    timeout)
            else:
                fut = asyncio.get_running_loop().create_future()
                self.pending[tid] = fut
                await self._send(test["source"], {"type": "run", "test_id": tid, "kind": test["kind"],
                                                  "target_ip": test["target_ip"], "data_port": port,
                                                  "params": test["params"]})
                result = await asyncio.wait_for(fut, timeout)
            self.db.finish_test(tid, "done", result)
            events.emit({"type": "test_done", "test_id": tid, "result": result})
            self._check_drop(test, result)
        except Exception as e:
            msg = str(e) or e.__class__.__name__
            if isinstance(e, asyncio.TimeoutError):
                msg = "Test timed out"
            elif isinstance(e, (ConnectionRefusedError, OSError)) and "refused" in msg.lower():
                msg = "Connection refused - is the target's firewall allowing port %d?" % port
            self.db.finish_test(tid, "error", error=msg)
            events.emit({"type": "test_error", "test_id": tid, "error": msg})
        finally:
            self.pending.pop(tid, None)
            self.running.pop(tid, None)
            self.busy.discard(test["source"])
            self.busy.discard(test["target"])
            events.emit({"type": "agents", "agents": self.nodes()})

    def _check_drop(self, test, result):
        """Alert if TCP throughput fell more than 50 % below this pair's average."""
        if test["kind"] != "tcp":
            return
        prev = [t for t in self.db.tests(200)
                if t["id"] != test["id"] and t["status"] == "done" and t["kind"] == "tcp"
                and t["source"] == test["source"] and t["target"] == test["target"]
                and t["params"].get("direction") == test["params"]["direction"]
                and t["result"] and t["result"].get("avg_mbps")]
        if not prev:
            return
        avg = sum(t["result"]["avg_mbps"] for t in prev) / len(prev)
        now = result.get("avg_mbps") or 0
        if avg > 0 and now < 0.5 * avg:
            a = self.db.add_alert("warning", "throughput_drop",
                                  "TCP throughput %s -> %s dropped to %.1f Mbps (average %.1f Mbps)" % (
                                      test["source"], test["target"], now, avg), test.get("target_device"))
            events.emit({"type": "alert", "alert": a})
