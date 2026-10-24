"""
Discovery engine.

1. Work out which network we are on (interface, IP, mask, gateway, DNS).
2. Find live devices:
     * ARP scan with scapy  - needs admin/root (and Npcap on Windows)
     * fallback: ICMP ping sweep + read the operating system's ARP table
3. Enrich each device: MAC vendor (offline OUI database), randomised-MAC flag,
   hostname (reverse DNS, then NetBIOS), a few common open TCP ports,
   and a guessed device type.

Safety: only the local subnet is ever scanned. Public address ranges are
refused, and anything bigger than /22 is narrowed to the host's own /24.
"""

import concurrent.futures as cf
import ipaddress
import os
import platform
import re
import socket
import struct
import subprocess
import time

import psutil

SYSTEM = platform.system()
WIN = SYSTEM == "Windows"

# Fixed list of ports we check - nothing else is ever probed.
COMMON_PORTS = {
    22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 554: "RTSP", 631: "IPP", 8080: "HTTP-alt",
}
PORT_TIMEOUT = 0.3
PORT_DELAY = 0.02
MAX_PREFIX = 22          # refuse anything larger (i.e. prefix length smaller) than /22


def _run(cmd, timeout=8):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              creationflags=0x08000000 if WIN else 0).stdout
    except Exception:
        return ""


def is_admin():
    try:
        if WIN:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def normalize_mac(mac):
    if not mac:
        return None
    parts = re.split(r"[:\-.]", mac.strip())
    if len(parts) == 3:                       # Cisco style aabb.ccdd.eeff
        parts = [p[i:i + 2] for p in parts for i in (0, 2)]
    if len(parts) != 6:
        return None
    try:
        mac = ":".join("%02x" % int(p, 16) for p in parts)
    except ValueError:
        return None
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return mac


def is_randomized_mac(mac):
    """Locally-administered bit (0x02 of the first byte) set => second hex digit is 2, 6, A or E.
    Phones and laptops use these 'private' MACs to avoid being tracked between networks."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 1. Our own network
# ---------------------------------------------------------------------------

def local_ip():
    """The IP of the interface used for outbound traffic. A UDP 'connect' only picks a
    route - no packet is actually sent."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def default_gateway():
    # a) scapy's routing table (works on all OSes when scapy is installed)
    try:
        from scapy.all import conf
        gw = conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    # b) Linux kernel routing table
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                p = line.split()
                if p[1] == "00000000" and int(p[3], 16) & 2:
                    return socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
    except Exception:
        pass
    # c) OS commands
    if WIN:
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", _run(["route", "print", "-4", "0.0.0.0"]))
        if m:
            return m.group(1)
    else:
        m = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", _run(["route", "-n", "get", "default"]))
        if m:
            return m.group(1)
        m = re.search(r"^(?:default|0\.0\.0\.0)\s+(\d+\.\d+\.\d+\.\d+)", _run(["netstat", "-rn"]), re.M)
        if m:
            return m.group(1)
    return None


def dns_servers():
    found = []
    if WIN:
        out = _run(["ipconfig", "/all"])
        grab = False
        for line in out.splitlines():
            if "DNS Servers" in line:
                grab = True
                line = line.split(":", 1)[1]
            elif grab and not line.startswith(" " * 20):
                grab = False
            if grab:
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                if m:
                    found.append(m.group(1))
    else:
        if SYSTEM == "Darwin":
            found += re.findall(r"nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)", _run(["scutil", "--dns"]))
        try:
            with open("/etc/resolv.conf") as f:
                found += re.findall(r"^nameserver\s+(\d+\.\d+\.\d+\.\d+)", f.read(), re.M)
        except OSError:
            pass
    out = []
    for d in found:
        if d not in out:
            out.append(d)
    return out[:4]


def network_info():
    """Everything shown in the 'Your network' panel, plus the subnet we are allowed to scan."""
    ip = local_ip()
    iface, mask, mac = None, None, None
    for name, addrs in psutil.net_if_addrs().items():
        if any(a.family == socket.AF_INET and a.address == ip for a in addrs):
            iface = name
            for a in addrs:
                if a.family == socket.AF_INET and a.address == ip:
                    mask = a.netmask
                if a.family == psutil.AF_LINK:
                    mac = normalize_mac(a.address)
    mask = mask or "255.255.255.0"
    net = ipaddress.ip_network("%s/%s" % (ip, mask), strict=False)
    addr = ipaddress.ip_address(ip)
    scan_net, note, allowed = net, None, True
    if not addr.is_private:
        allowed, note = False, "This machine has a public IP address. NetScope only scans private LANs."
    elif net.prefixlen < MAX_PREFIX:
        scan_net = ipaddress.ip_network("%s/24" % ip, strict=False)
        note = "Subnet %s is larger than /%d, so only %s (this machine's /24) will be scanned." % (
            net, MAX_PREFIX, scan_net)
    elif net.prefixlen > 30:
        allowed, note = False, "Subnet is too small to scan."
    stats = psutil.net_if_stats().get(iface) if iface else None
    return {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "interface": iface,
        "ip": ip,
        "mac": mac,
        "netmask": mask,
        "subnet": str(net),
        "prefixlen": net.prefixlen,
        "scan_subnet": str(scan_net),
        "scan_hosts": scan_net.num_addresses - 2 if scan_net.prefixlen < 31 else 0,
        "scan_allowed": allowed,
        "scan_note": note,
        "gateway": default_gateway(),
        "dns": dns_servers(),
        "link_speed_mbps": stats.speed if stats and stats.speed else None,
        "mtu": stats.mtu if stats else None,
        "is_admin": is_admin(),
    }


# ---------------------------------------------------------------------------
# 2. Finding devices
# ---------------------------------------------------------------------------

def arp_scan(cidr, iface=None, timeout=2.0):
    """Broadcast an ARP 'who-has' for every address in the subnet.
    Every device on the LAN must answer ARP to receive IP packets, so this finds
    devices even when they block ping. Needs raw-socket access (admin/root)."""
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    kw = {"iface": iface} if iface else {}
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr), timeout=timeout, retry=1, **kw)
    found = {}
    for _, r in ans:
        found[r.psrc] = normalize_mac(r.hwsrc)
    return found


def _sys_ping_once(ip):
    if WIN:
        out = _run(["ping", "-n", "1", "-w", "800", ip], 4)
    else:
        out = _run(["ping", "-c", "1", "-W", "1", ip], 4)
    return bool(re.search(r"time[=<]\s*[\d.]+\s*ms", out, re.I))


def ping_sweep(hosts):
    """Send one ICMP echo to every host; return the set that replied."""
    from .quality import icmplib_mode
    alive = set()
    mode = icmplib_mode()
    if mode is not None:
        try:
            import icmplib
            res = icmplib.multiping(hosts, count=1, timeout=1, concurrent_tasks=64, privileged=mode)
            return {h.address for h in res if h.is_alive}
        except Exception:
            pass
    with cf.ThreadPoolExecutor(64) as ex:
        for ip, ok in zip(hosts, ex.map(_sys_ping_once, hosts)):
            if ok:
                alive.add(ip)
    return alive


def read_arp_table():
    """The OS ARP cache: IP -> MAC for every device we recently talked to."""
    table = {}
    if SYSTEM == "Linux":
        try:
            with open("/proc/net/arp") as f:
                for line in f.readlines()[1:]:
                    p = line.split()
                    if len(p) >= 4 and p[2] != "0x0":
                        mac = normalize_mac(p[3])
                        if mac:
                            table[p[0]] = mac
            return table
        except OSError:
            pass
    out = _run(["arp", "-a"])
    for line in out.splitlines():
        ip = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        mac = re.search(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
        if ip and mac:
            m = normalize_mac(mac.group(1))
            if m:
                table[ip.group(1)] = m
    return table


# ---------------------------------------------------------------------------
# 3. Enrichment
# ---------------------------------------------------------------------------

_manuf = None


def vendor_of(mac):
    """Look up the manufacturer from the first 3 bytes of the MAC (the OUI),
    using scapy's bundled copy of Wireshark's manuf database (no internet needed)."""
    global _manuf
    if not mac:
        return None
    if is_randomized_mac(mac):
        return "Private/randomised MAC"
    try:
        if _manuf is None:
            from scapy.all import conf
            _manuf = conf.manufdb
        name = _manuf._get_manuf(mac)
        if name and normalize_mac(name) is None and name.lower() != mac.lower():
            return name
    except Exception:
        pass
    return None


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def netbios_name(ip, timeout=0.8):
    """Ask a Windows/Samba machine for its name with a NetBIOS Node Status query (UDP 137)."""
    enc = b"".join(bytes([0x41 + (b >> 4), 0x41 + (b & 0xF)]) for b in b"*" + b"\x00" * 15)
    pkt = struct.pack("!HHHHHH", 0x4E53, 0, 1, 0, 0, 0) + b"\x20" + enc + b"\x00" + struct.pack("!HH", 0x21, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, 137))
        data, _ = s.recvfrom(2048)
        n = data[56]
        for i in range(n):
            off = 57 + i * 18
            name = data[off:off + 15].decode(errors="ignore").strip()
            suffix, flags = data[off + 15], struct.unpack("!H", data[off + 16:off + 18])[0]
            if suffix == 0 and not flags & 0x8000 and name:
                return name
    except Exception:
        return None
    finally:
        s.close()
    return None


def hostname_of(ip):
    name = reverse_dns(ip)
    if name and not name.startswith(ip):
        return name
    return netbios_name(ip)


def open_ports(ip):
    """TCP connect() check of the fixed COMMON_PORTS list only."""
    found = []
    for port in COMMON_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(PORT_TIMEOUT)
        try:
            if s.connect_ex((ip, port)) == 0:
                found.append(port)
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(PORT_DELAY)
    return found


_CAMERA = ("hikvision", "dahua", "axis", "reolink", "wyze", "amcrest", "hanwha", "uniview", "ezviz", "imou")
_PRINTER = ("canon", "epson", "brother", "xerox", "kyocera", "lexmark", "ricoh", "konica")
_PHONE = ("samsung", "xiaomi", "oneplus", "oppo", "vivo", "realme", "motorola", "huawei", "honor", "nothing", "google")
_NET = ("tp-link", "tplink", "netgear", "ubiquiti", "mikrotik", "cisco", "juniper", "aruba", "d-link",
        "dlink", "tenda", "zte", "linksys", "asustek", "fortinet", "ruckus", "sagemcom", "technicolor")
_IOT = ("espressif", "tuya", "raspberry", "amazon", "sonos", "roku", "shelly", "nest", "philips",
        "lifx", "broadlink", "arduino", "particle")
_PC = ("intel", "dell", "lenovo", "micro-star", "msi", "gigabyte", "realtek", "hewlett", "hp ",
       "apple", "asrock", "liteon", "azurewave", "microsoft", "vmware", "parallels")


def guess_type(dev, gateway, self_ip):
    v = (dev.get("vendor") or "").lower()
    ports = set(dev.get("ports") or [])
    if dev["ip"] == gateway:
        return "router"
    if dev["ip"] == self_ip:
        return "pc"
    if any(k in v for k in _CAMERA) or 554 in ports:
        return "camera"
    if 631 in ports or any(k in v for k in _PRINTER):
        return "printer"
    if any(k in v for k in _NET) and (53 in ports or 80 in ports or 443 in ports):
        return "network"
    if any(k in v for k in _IOT):
        return "iot"
    if 445 in ports or 22 in ports:
        return "pc"
    if any(k in v for k in _PC):
        return "pc"
    if any(k in v for k in _PHONE) or v.startswith("private"):
        return "phone"
    if any(k in v for k in _NET):
        return "network"
    return "unknown"


# ---------------------------------------------------------------------------
# Full scan
# ---------------------------------------------------------------------------

def scan(info=None, progress=None, check_ports=True):
    """Run a full discovery scan of the local subnet.

    Returns (devices, method) where devices is a list of dicts.
    `progress(stage, pct, message)` is called as the scan moves along.
    """
    info = info or network_info()
    if not info["scan_allowed"]:
        raise PermissionError(info["scan_note"] or "Scanning is not allowed on this network")

    def report(stage, pct, msg):
        if progress:
            progress(stage, pct, msg)

    net = ipaddress.ip_network(info["scan_subnet"])
    hosts = [str(h) for h in net.hosts()]
    found, method = {}, None
    report("discover", 5, "Sending ARP requests to %d addresses..." % len(hosts))
    if info["is_admin"]:
        try:
            found = arp_scan(info["scan_subnet"], info["interface"])
            method = "ARP scan"
        except Exception as e:
            report("discover", 10, "ARP scan unavailable (%s) - falling back to ping sweep" % e)
    if not method:
        report("discover", 10, "Ping sweep of %d addresses (no admin rights, using fallback)..." % len(hosts))
        alive = ping_sweep(hosts)
        table = read_arp_table()
        found = {ip: table.get(ip) for ip in alive}
        for ip, mac in table.items():               # ARP entries for devices that ignore ping
            if ipaddress.ip_address(ip) in net and ip not in found:
                found[ip] = mac
        method = "Ping sweep + ARP table"

    # Make sure we and the gateway are in the list.
    found.setdefault(info["ip"], info["mac"])
    gw = info.get("gateway")
    if gw and ipaddress.ip_address(gw) in net:
        if gw not in found:
            found[gw] = read_arp_table().get(gw)

    devices = [{"ip": ip, "mac": mac} for ip, mac in found.items()]
    report("enrich", 40, "Found %d devices. Looking up names and vendors..." % len(devices))

    for d in devices:
        d["vendor"] = vendor_of(d["mac"])
        d["randomized_mac"] = bool(d["mac"] and is_randomized_mac(d["mac"]))

    with cf.ThreadPoolExecutor(32) as ex:
        names = dict(zip([d["ip"] for d in devices], ex.map(hostname_of, [d["ip"] for d in devices])))
    for d in devices:
        d["hostname"] = names.get(d["ip"])
    if info["ip"] in names and not names[info["ip"]]:
        for d in devices:
            if d["ip"] == info["ip"]:
                d["hostname"] = info["hostname"]

    if check_ports:
        report("ports", 65, "Checking %d common ports on each device..." % len(COMMON_PORTS))
        with cf.ThreadPoolExecutor(32) as ex:
            ports = dict(zip([d["ip"] for d in devices], ex.map(open_ports, [d["ip"] for d in devices])))
        for d in devices:
            d["ports"] = ports.get(d["ip"], [])
    else:
        for d in devices:
            d["ports"] = []

    for d in devices:
        d["type"] = guess_type(d, gw, info["ip"])
        d["is_self"] = d["ip"] == info["ip"]
        d["is_gateway"] = d["ip"] == gw
    devices.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    report("done", 100, "Scan complete: %d devices (%s)" % (len(devices), method))
    return devices, method
