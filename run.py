#!/usr/bin/env python3
"""Start NetScope:  python run.py   (use sudo / "Run as administrator" for ARP scanning)."""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    ap = argparse.ArgumentParser(description="NetScope - LAN mapper and link quality tester")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Dashboard address (default 127.0.0.1 = this computer only; "
                         "use 0.0.0.0 to open it to other devices on the LAN)")
    ap.add_argument("--port", type=int, default=8000, help="Dashboard port (default 8000)")
    a = ap.parse_args()

    import uvicorn
    from server import discovery
    from server.db import DB

    info = discovery.network_info()
    s = DB().settings()
    print()
    print("  NetScope")
    print("  --------")
    print("  Dashboard : http://%s:%d" % ("localhost" if a.host == "127.0.0.1" else info["ip"], a.port))
    print("  Network   : %s  (this machine %s, gateway %s)" % (info["subnet"], info["ip"], info["gateway"]))
    print("  Admin     : %s" % ("yes - ARP scanning enabled" if info["is_admin"]
                                 else "no - using ping sweep + ARP table fallback"))
    print("  Agents    : on another machine run")
    print("              python agent.py --server %s --token %s" % (info["ip"], s["token"]))
    print()
    uvicorn.run("server.main:app", host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
