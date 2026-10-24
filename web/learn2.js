// Explanations for the Paths, DNS, Traffic and Connections pages.
Object.assign(window.LEARN, {
  traceroute: {
    title: "How traceroute works",
    body: [
      "Every IP packet carries a TTL (time to live) field. Each router that forwards the packet subtracts 1, and the router that brings it to 0 drops the packet and sends back an ICMP Time Exceeded message (type 11) from its own address.",
      "Traceroute sends pings with TTL 1, then 2, then 3 and so on. The first router answers the TTL 1 probe, the second router answers TTL 2, and so on, until the destination itself answers with an ordinary Echo Reply. Three probes are sent per hop and each is timed.",
      "A hop shown as * * * didn't reply in time. Many routers are set not to send Time Exceeded messages, or to send them at low priority, but they still forward traffic normally. That's also why one hop can show a higher latency than the hops after it."
    ]
  },
  asn: {
    title: "Networks on the path (autonomous systems)",
    body: [
      "The internet is roughly 75,000 independently run networks called autonomous systems (AS): ISPs like Jio or Airtel, cloud providers like Google and Amazon, universities and so on. Each has an AS number, and they exchange routes with each other using BGP.",
      "For each public router on the path, NetScope asks Team Cymru's free IP-to-ASN service which AS owns that address, using a DNS TXT query. The coloured bar beside the hops changes colour where your packets cross from one AS to the next.",
      "Private addresses (192.168.x.x, 10.x.x.x, 172.16-31.x.x) belong to your home network or the inside of your ISP. Addresses in 100.64.0.0/10 are carrier-grade NAT: your ISP shares one public address between many customers."
    ]
  },
  dns: {
    title: "DNS resolution and caching",
    body: [
      "Before your browser can connect to github.com it needs its IP address. It asks a recursive resolver (your router, your ISP, or a public one like 1.1.1.1). If the resolver doesn't have the answer cached, it asks a root server, then the .com servers, then github.com's own authoritative servers.",
      "Each answer comes with a TTL (time to live) in seconds. The resolver keeps it in its cache for that long, so the next person asking gets an instant answer.",
      "The benchmark measures both cases. Cached lookups ask for popular names twice, so the second answer comes from cache and mostly measures the round trip to the resolver. Uncached lookups ask for a random name that can't be in any cache, which forces full recursion. This is the step that failed for millions of users in the 2016 Dyn attack: the authoritative servers were flooded, so once cached answers expired, sites like Twitter couldn't be resolved."
    ]
  },
  dnspacket: {
    title: "Inside a DNS query packet",
    body: [
      "NetScope builds DNS packets byte by byte (see server/dnsclient.py) instead of using a library, so you can see exactly what's sent over UDP port 53.",
      "The 12-byte header holds a random 16-bit ID (the reply must carry the same ID, which also makes spoofed replies harder), the flags (RD = recursion desired), and four counts: questions, answers, authority records and additional records.",
      "The question encodes the name as length-prefixed labels: www.example.com becomes 03 'www' 07 'example' 03 'com' 00. Then come 2 bytes of type (1 = A, 28 = AAAA, 15 = MX...) and 2 bytes of class (1 = IN, the internet).",
      "Answers use name compression: a byte starting with binary 11 is a pointer back to a name already in the packet, which keeps responses small. If an answer won't fit in a UDP datagram the server sets the TC flag and the client retries over TCP."
    ]
  },
  capture: {
    title: "How the traffic monitor works",
    body: [
      "Bandwidth comes from the operating system's per-interface byte and packet counters, sampled once a second. That works without admin rights.",
      "The protocol breakdown captures packets on this computer's network interface with scapy (the same libpcap/Npcap capture that Wireshark uses), in non-promiscuous mode, so it only sees this computer's own traffic and broadcasts. Each packet is sorted into a protocol using only its headers: the layer 2 type, the IP protocol number and the TCP or UDP port numbers.",
      "Payloads are never stored. The one exception is DNS answers sent to this computer, which are read to label IP addresses with the name that was looked up (for example youtube.com instead of 142.250.x.x). Everything is kept in memory only and cleared when a new capture starts."
    ]
  },
  layers: {
    title: "Protocols and OSI layers",
    body: [
      "Layer 2 (data link): ARP lives here. It maps IP addresses to MAC addresses on the local network.",
      "Layer 3 (network): IP routes packets between networks. ICMP carries control messages such as ping and Time Exceeded.",
      "Layer 4 (transport): TCP gives a reliable, ordered byte stream with congestion control. UDP just sends datagrams.",
      "Layer 7 (application): DNS, HTTP, HTTPS, QUIC, mDNS and so on, identified here by their well-known port numbers."
    ]
  },
  quic: {
    title: "QUIC and HTTP/3",
    body: [
      "Most web traffic is HTTPS: HTTP inside TLS encryption, carried over TCP port 443.",
      "QUIC is a newer transport, built on UDP port 443, that browsers use for HTTP/3 with Google, YouTube, Cloudflare-hosted sites and others. It does its own reliability and congestion control in user space and builds TLS 1.3 into its handshake, so a connection can start sending data after one round trip instead of two or three.",
      "Because it runs over UDP, QUIC shows up as UDP 443 in the capture. A large QUIC share usually means YouTube or Google services are in use."
    ]
  },
  tcpstates: {
    title: "The TCP state machine",
    body: [
      "Every TCP connection moves through a fixed set of states (RFC 9293). Opening uses the three-way handshake: the client sends SYN (SYN_SENT), the server replies SYN+ACK (SYN_RECV), and the client's ACK puts both sides in ESTABLISHED.",
      "Closing takes four messages, because each direction closes separately with its own FIN. The side that closes first goes FIN_WAIT_1, then FIN_WAIT_2, then TIME_WAIT. The other side goes CLOSE_WAIT and then LAST_ACK.",
      "The numbers on the diagram are read live from this computer's connection table (what netstat shows). Run a throughput test with 4 streams and watch 4 connections appear in ESTABLISHED, then move to TIME_WAIT when the test ends."
    ]
  },
  timewait: {
    title: "TIME_WAIT and CLOSE_WAIT",
    body: [
      "TIME_WAIT: the side that closed first waits 2 × MSL (maximum segment lifetime; about 30–120 seconds depending on the OS) before forgetting the connection. This lets the final ACK be resent if it was lost, and stops delayed packets from an old connection being mistaken for a new one on the same ports. Lots of TIME_WAIT entries are normal on a busy machine.",
      "CLOSE_WAIT: the other side has closed, and TCP is waiting for the program on this computer to close its socket too. Many connections stuck in CLOSE_WAIT usually mean a program isn't closing its connections properly."
    ]
  },
  listen: {
    title: "Listening ports and who can reach them",
    body: [
      "A program that accepts connections listens on a port. The address it binds to decides who can connect.",
      "0.0.0.0 (or :: for IPv6) means all interfaces: any device that can reach this computer over the network can try to connect, subject to the firewall. 127.0.0.1 means this computer only, which is how NetScope's own dashboard runs by default.",
      "Checking this list is a basic part of network hygiene: every service listening on all interfaces is something another device on the Wi-Fi could reach."
    ]
  }
});
