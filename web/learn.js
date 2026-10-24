// Short explanations of the networking behind every measurement, for the (i) buttons.
window.LEARN = {
  arp: {
    title: "ARP: finding devices on the LAN",
    body: [
      "On an Ethernet or Wi-Fi LAN, devices are addressed by MAC address, not IP address. Before sending an IP packet to a neighbour, a host broadcasts an ARP request: \"Who has 192.168.1.23? Tell 192.168.1.10.\" The owner replies with its MAC address.",
      "NetScope's ARP scan sends one of these requests for every address in the subnet. Every device must answer ARP to receive traffic at all, so this finds devices even when they block ping.",
      "ARP needs raw access to the network card, which is why it requires admin/root (and Npcap on Windows). Without it, NetScope falls back to a ping sweep and then reads the operating system's ARP cache, which the sweep has just filled."
    ]
  },
  rtt: {
    title: "Latency and ICMP echo (ping)",
    body: [
      "Ping sends an ICMP Echo Request (type 8) and the target answers with an Echo Reply (type 0). The round-trip time (RTT) is the time between sending the request and receiving the reply.",
      "RTT = transmission delay + propagation delay + processing delay + queueing delay, in both directions. On a quiet wired LAN it is usually under 1 ms; Wi-Fi adds a few ms and much more variation.",
      "NetScope sends 20 pings for a manual test (5 for background checks) and reports the minimum, average, median and maximum. Some devices, especially Windows PCs and phones, block ICMP and show as \"No ping reply\" while still being online."
    ]
  },
  jitter: {
    title: "Jitter",
    body: [
      "Jitter is how much the delay varies from packet to packet. A link with a steady 40 ms RTT feels smoother for calls than one that swings between 5 ms and 80 ms.",
      "NetScope shows two versions. Mean jitter is the average of |RTT[i] − RTT[i−1]| over consecutive replies. RFC 3550 jitter (used by RTP for voice and video) is smoothed: J = J + (|D| − J) / 16, so each new sample moves the estimate only 1/16 of the way and one spike doesn't dominate.",
      "In the UDP test the receiver uses the RFC 3550 method on one-way transit times. The sender's and receiver's clocks differ, but that constant offset cancels out because only differences between consecutive transit times are used."
    ]
  },
  loss: {
    title: "Packet loss",
    body: [
      "Loss % = (packets sent − packets received) / packets sent × 100.",
      "Packets are lost when a queue in a router, switch or access point is full and new arrivals are dropped (drop-tail), when Wi-Fi frames are corrupted by interference and exhaust their retries, or when a device is asleep or blocking ICMP.",
      "Even 1–2% loss hurts TCP, because TCP treats loss as a sign of congestion and cuts its sending rate."
    ]
  },
  tcp: {
    title: "TCP throughput",
    body: [
      "The sender writes 64 KB blocks into a TCP socket as fast as it can for the chosen time, and the receiver counts the bytes. Mbps = bytes × 8 / seconds / 1,000,000.",
      "TCP is reliable and has congestion control: it grows its congestion window until packets start getting lost or delayed, then backs off. The result is roughly the fair share of the bottleneck link's capacity.",
      "Parallel streams let several TCP connections share the link. That helps when one connection is limited by its window size or by Wi-Fi retries, and shows how TCP flows share bandwidth."
    ]
  },
  udp: {
    title: "UDP test: loss, jitter and out-of-order",
    body: [
      "UDP has no handshake, no acknowledgements and no congestion control. The sender transmits numbered, timestamped datagrams at the bitrate you choose, whether or not the network can carry them.",
      "The receiver tracks the sequence numbers: missing numbers are lost packets, and a packet arriving after a higher-numbered one is out of order. It computes RFC 3550 jitter from the timestamps.",
      "Set the bitrate above the link's capacity and you'll see UDP keep sending while loss rises. TCP would have slowed down instead. This is why voice and video apps, which use UDP, need their own rate control."
    ]
  },
  congestion: {
    title: "Why TCP backs off and UDP doesn't",
    body: [
      "TCP assumes a lost packet means a queue somewhere overflowed, so it shrinks its congestion window (for example halving it in Reno/CUBIC) and then slowly probes upward again. This keeps the network from collapsing when many users share it.",
      "UDP is just IP plus port numbers and a checksum. It never learns that packets are being lost, so it keeps sending at the same rate and can push TCP traffic aside on a congested link.",
      "That difference is also why UDP floods are such an effective denial-of-service technique."
    ]
  },
  bufferbloat: {
    title: "Latency under load (bufferbloat)",
    body: [
      "This test measures round-trip time with small UDP echo probes, first on an idle link, then while a TCP upload saturates it.",
      "TCP fills the link until packets are dropped. If a router or access point has a very large buffer, packets sit in the queue for a long time before any are dropped, so everything sharing the link, including calls and games, gets delayed. This is bufferbloat.",
      "A small increase (a few ms) means the queues are well managed. An increase of 100 ms or more means oversized buffers. Smart queue management such as fq_codel or CAKE fixes this."
    ]
  },
  health: {
    title: "How the health score is calculated",
    body: [
      "Health = 40% latency score + 40% loss score + 20% availability.",
      "Latency score: 100 when the average RTT is 20 ms or less, falling linearly to 0 at 300 ms. Loss score: 100 at 0% loss, falling to 0 at 10% loss. Both are averaged over the devices that answered the latest background ping check.",
      "Availability is online devices divided by all known devices. Devices that block ping still count as online if they answered ARP during the last scan."
    ]
  },
  mac: {
    title: "MAC addresses, vendors and private MACs",
    body: [
      "A MAC address is 48 bits written as six bytes. The first three bytes are the OUI (Organisationally Unique Identifier) assigned by the IEEE to the manufacturer, which is how NetScope looks up the vendor offline.",
      "Bit 1 of the first byte is the \"locally administered\" bit. When it's set, so the second hex digit is 2, 6, A or E, the address was made up by the device rather than burned in by the manufacturer.",
      "Modern phones and laptops use these private, randomised MACs on each Wi-Fi network to avoid being tracked, so their vendor can't be identified."
    ]
  },
  agent: {
    title: "Agents",
    body: [
      "Ping can test any device, but throughput needs software on both ends. A NetScope agent is one Python file using only the standard library.",
      "Each agent keeps a TCP control connection to the server on port 5600 and runs a data server on port 5601 (TCP and UDP). To run a test, the server tells the source machine to send to the target's data port, and per-second results flow back over the control connection.",
      "Every test connection starts with the shared token, so the data port only works for NetScope machines."
    ]
  },
  ports: {
    title: "Open ports",
    body: [
      "NetScope tries a TCP connect() to a short fixed list of ports: 22 SSH, 53 DNS, 80 HTTP, 443 HTTPS, 445 SMB file sharing, 554 RTSP video streams, 631 IPP printing and 8080 alternative HTTP.",
      "If the three-way handshake completes (SYN, SYN-ACK, ACK) the port is open; NetScope then closes the connection immediately. These hints are used to guess the device type, for example 631 means a printer and 554 often means a camera."
    ]
  }
};
