# NetScope: LAN Mapper and Link Quality Tester

NetScope finds every device on your local network, draws a live map of it, and measures how good each link is:

- **Discover**: ARP scan (or ping sweep + ARP table) of your subnet, with MAC vendor, hostname, a few common open ports and a guessed device type.
- **Measure**: latency, jitter and packet loss to every device (ICMP ping), plus TCP throughput, UDP loss/jitter/out-of-order and latency-under-load tests between machines running the NetScope agent.
- **Visualise**: map links coloured green/amber/red by quality and drawn thicker for higher throughput, history graphs, a health score, alerts and an exportable report.
- **Trace paths**: a traceroute map of every router between you and a website, with the networks (autonomous systems) the packets cross.
- **Benchmark DNS**: compare your router, Cloudflare, Google, Quad9 and OpenDNS on cached vs uncached lookups, and inspect a DNS packet byte by byte.
- **Watch this computer**: live bandwidth, a protocol breakdown from packet capture (like a mini Wireshark), and the TCP state machine with live connection counts.

Every measurement has an (i) button in the app explaining the networking behind it.

---

## 1. Requirements

- Python 3.9 or newer on every machine.
- The NetScope server needs the packages in `requirements.txt`.
- An agent needs **only Python**, nothing else.
- Everything runs offline: the map and chart libraries, font and MAC vendor database are bundled.

## 2. Start the server

**Windows**
1. Install Python from python.org (tick "Add Python to PATH").
2. Optional, for ARP scanning: install [Npcap](https://npcap.com) with "WinPcap API-compatible mode" ticked.
3. Right-click `start-windows.bat` and choose **Run as administrator** (or double-click it for the no-admin fallback).

**macOS / Linux**
```bash
chmod +x start-mac-linux.sh
sudo ./start-mac-linux.sh        # with ARP scanning
./start-mac-linux.sh             # without admin: ping sweep + ARP table
```

**Manual**
```bash
pip install -r requirements.txt
python run.py                    # dashboard at http://localhost:8000
python run.py --host 0.0.0.0     # also let other devices on the LAN open the dashboard
```

Open **http://localhost:8000** and press **Scan network**. The first time, you'll be asked to confirm you have permission to scan the network.

The terminal prints the exact command to start an agent, including your token. The token is also shown on the **Tests** page and in **Settings**.

## 3. Add a second machine (agent)

Copy the single file `agent/agent.py` to a teammate's laptop on the same Wi-Fi/LAN and run:

```bash
python agent.py --server <server IP> --token <token> --name "Riya-laptop"
```

It appears on the map with an **Agent** badge, and you can run throughput tests from the **Tests** page in either direction: server to agent, agent to server, or agent to agent.

**Firewall:** allow TCP 5600, TCP 5601 and UDP 5601 on both machines.
- Windows: when the "Windows Defender Firewall has blocked some features" box appears, tick **Private networks** and click Allow. Otherwise: Windows Security → Firewall → Allow an app → Python.
- macOS: System Settings → Network → Firewall → Options → allow incoming connections for Python.
- Linux (ufw): `sudo ufw allow 5600:5601/tcp && sudo ufw allow 5601/udp`

## 4. Pages

| Page | What it shows |
|---|---|
| Dashboard | Your network (IP, mask, gateway, DNS, interface), health score, device counts, map preview, weakest links, alerts |
| Map | Star topology around the gateway; star / grid / force layouts; click a device for details, live ping test, history and rename; export PNG |
| Devices | Sortable, filterable table; CSV download; printable HTML report (print it to PDF) |
| Tests | TCP throughput (1–4 streams, upload/download), UDP at a chosen bitrate, latency under load; live per-second graph; past results |
| History | Latency, jitter or loss over the last hour, day or week, for one device or all of them |
| Paths | Traceroute to any site: each hop's IP, hostname, network (AS) and 3 probe times; colour changes where the path enters a new network; biggest latency jump; latency-by-hop chart |
| DNS | Benchmark of DNS servers (cached and uncached medians, reliability, which google.com address each returns); lookup inspector with decoded flags, records and an annotated hex dump of the query |
| Traffic | Live download/upload for this computer; Start capture for a per-protocol breakdown (HTTPS, QUIC, DNS, mDNS, ARP…) with OSI layer, and who the computer is talking to |
| Connections | The TCP state machine drawn live with how many connections are in each state; every TCP connection with program and remote host; listening ports and whether other devices can reach them |
| Settings | Scan interval, background ping interval, quality thresholds, token, ports, history retention |

## 5. How each measurement works (viva notes)

| Measurement | Method |
|---|---|
| Device discovery | ARP who-has broadcast for every address in the subnet (scapy). Fallback: ICMP echo to every address, then read the OS ARP cache. |
| Vendor | First 3 bytes of the MAC (OUI) looked up in Wireshark's manuf database. A set locally-administered bit (2nd hex digit 2, 6, A, E) means a private/randomised MAC. |
| Hostname | Reverse DNS (PTR), then a NetBIOS node-status query on UDP 137. |
| Open ports | TCP connect() to 22, 53, 80, 443, 445, 554, 631, 8080 only, 300 ms timeout. |
| Latency | ICMP Echo Request/Reply RTT: min, avg, median, max over 20 pings (5 for background checks). |
| Loss | (sent − received) / sent × 100. |
| Jitter | Mean of \|RTT[i] − RTT[i−1]\|, plus RFC 3550 smoothed jitter J = J + (\|D\| − J)/16. |
| TCP throughput | 64 KB writes for T seconds; Mbps per second; final figure uses the receiver's byte count. |
| UDP test | Numbered, timestamped datagrams paced to a target bitrate. The receiver counts sequence gaps (loss), late arrivals (out of order) and RFC 3550 jitter from transit times. Clock offset between the machines cancels out. |
| Latency under load | UDP echo probes 5×/s on an idle link, then during a multi-stream TCP upload. The increase is bufferbloat. |
| Quality colour | Green under 20 ms and under 1% loss; red over 100 ms or over 5% loss; amber in between (editable in Settings). |
| Health score | 40% latency score (100 at ≤20 ms, 0 at 300 ms) + 40% loss score (100 at 0%, 0 at 10%) + 20% availability (online / known). |
| Alerts | New device, device offline, 3 bad background checks in a row, TCP throughput below 50% of that path's average. |

**Internet and this-computer features**

| Feature | Method |
|---|---|
| Traceroute | ICMP Echo Requests with TTL 1, 2, 3…; each router that drops a packet at TTL 0 replies with ICMP Time Exceeded (type 11) from its own address. 3 probes per hop, 1 s timeout, up to 30 hops. On Windows NetScope runs `tracert -d` and parses it (reliable through Windows Firewall); on macOS/Linux with sudo it uses its own raw-socket loop in `server/traceroute.py`. |
| Network (AS) per hop | DNS TXT query to Team Cymru: `<reversed IP>.origin.asn.cymru.com` gives the AS number, `AS<n>.asn.cymru.com` gives its name. 100.64.0.0/10 is shown as ISP carrier-grade NAT. |
| DNS client | Written from scratch (`server/dnsclient.py`): builds the 12-byte header and length-prefixed QNAME, sends over UDP 53, matches the 16-bit ID, follows compression pointers, retries over TCP if the TC flag is set. |
| DNS benchmark | Per server: 12 popular names asked twice (second answer = cached), plus 6 random never-seen names (forces full recursion: root, then TLD, then authoritative). Medians and 90th percentiles reported. |
| Bandwidth | OS per-interface byte/packet counters sampled every second. No admin needed. |
| Protocol breakdown | scapy capture (libpcap/Npcap) in non-promiscuous mode; packets sorted by layer 2 type, IP protocol and well-known ports. Headers only; nothing written to disk. DNS answers to this computer label remote IPs with the names that were looked up. |
| TCP connections | The OS connection table (what `netstat -ano` shows) via psutil, refreshed every 2 s and mapped onto the RFC 9293 state machine. |

The formulas are in `server/quality.py` and `agent/agent.py` (class `UdpStats`), and are covered by unit tests:

```bash
python -m pytest tests
```

## 6. Demo plan that works well

1. Scan the network and walk through the map: gateway in the centre, device types, vendors, a phone with a private MAC.
2. Click a device and run a ping test. Explain RTT, jitter and loss with the (i) buttons.
3. Start an agent on a second laptop. Run TCP throughput, then 4 parallel streams.
4. Run the UDP test at 10 Mbps (no loss), then at 500 Mbps: UDP keeps sending and loss climbs, while TCP would have backed off.
5. Run latency under load over Wi-Fi to show bufferbloat.
6. Walk away from the router with one laptop: the link turns amber/red on the map and an alert fires.
7. **Paths:** trace google.com and point out your router, the ISP's carrier-grade NAT, where the path enters Google's network, and the biggest latency jump.
8. **DNS:** run the benchmark and explain cached vs uncached (link it to the Dyn 2016 case study). Open the lookup inspector and walk through the hex dump: header, length-prefixed labels, type and class.
9. **Traffic:** start a capture and play a YouTube video. QUIC (UDP 443) usually dominates, which shows HTTP/3 running over UDP.
10. **Connections:** run a 4-stream TCP test from the Tests page and watch 4 connections appear in ESTABLISHED, then move to TIME_WAIT when it ends.
11. Open the printable report (it now includes the latest traceroute and DNS benchmark).

## 7. Safety limits built in

- Only the subnet this machine is on is scanned. Public IP ranges are refused, and anything larger than /22 is narrowed to this machine's /24.
- A one-time confirmation is required before the first scan.
- Port checks use a fixed list of 8 ports with a small delay between probes.
- Throughput tests only run between NetScope machines that share the token.
- The dashboard listens on localhost only unless you start it with `--host 0.0.0.0`.
- Packet capture only runs when you press **Start capture**, only sees this computer's own traffic (non-promiscuous), reads headers only, keeps counts in memory, and stops by itself after 15 minutes. It does show which domains this computer contacts, so don't leave it running on a shared screen if that matters to you.

Only scan networks you own or have permission to scan. On a college network, ask the network admin first, or use a phone hotspot or home router for the demo.

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| Discovery says "Ping sweep + ARP table" | You're not running as admin/root (or Npcap is missing on Windows). It still works, but devices that block ping may be missed. |
| A device shows "No ping reply" | It blocks ICMP (Windows firewall does by default, phones do when asleep). It's still online because it answered ARP. |
| Agent says "bad token" | The token was changed in Settings; restart the agent with the new one. |
| Test fails with "connection refused" or times out | Firewall on the target machine: allow TCP 5601 and UDP 5601. |
| Throughput looks low on Wi-Fi | Normal. Wi-Fi is half-duplex and shared; try a wired connection or 2–4 streams. |
| Port 8000 in use | `python run.py --port 8080` |
| "Packet capture needs NetScope to run as administrator" | Start NetScope as administrator (Windows) or with sudo. On Windows also install Npcap. Bandwidth works without it. |
| Traceroute shows only * * * after your router | Some networks (colleges, offices) block traceroute. Try a phone hotspot. |
| DNS benchmark: public servers "didn't answer" | The network blocks outside DNS servers on port 53. Common on college Wi-Fi. |
| Connections page shows few programs on macOS | Run with sudo to see every program's connections. |

## 9. Project structure

```
netscope/
  run.py                 start the server
  server/
    main.py              FastAPI app: REST API, WebSocket, scheduler, alerts, reports
    discovery.py         network info, ARP scan, ping sweep, ARP table, vendor, hostname, ports, device type
    quality.py           ping, latency/jitter/loss maths, quality colours, health score
    traceroute.py        TTL-based traceroute, tracert/traceroute parsing, AS lookups
    dnsclient.py         DNS client written from scratch (RFC 1035)
    dnsbench.py          DNS server benchmark (cached vs uncached)
    traffic.py           live bandwidth and packet-capture protocol breakdown
    connections.py       TCP connection table and listening ports
    tests_coord.py       agent control channel (TCP 5600) and throughput test coordination
    db.py                SQLite storage (devices, pings, tests, alerts, settings)
    events.py            live updates to the browser
  agent/agent.py         standalone agent + the TCP/UDP test engine (server uses it too)
  web/                   dashboard (HTML/CSS/JS, no build step) with bundled Cytoscape.js, Chart.js, font
  tests/                 unit tests
```

Data is stored in `netscope.db` in the project folder. Delete it to start fresh.
