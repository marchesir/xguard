#!/usr/bin/env python3
import sys

DEFAULT_IFACE = "lo"

def block_ipv4(ip4: str, iface: str = DEFAULT_IFACE):
    """Block traffic for a specific IPv4 address."""
    print(f"[xguard] (TODO) Blocking IPv4 {ip4} on {iface}")

def block_all(iface: str = DEFAULT_IFACE):
    """Block all traffic (IPv4 + IPv6) on an interface."""
    print(f"[xguard] (TODO) Blocking ALL traffic on {iface}")

def help():
    print("""
xguard — Minimal eBPF/XDP realtime firewall.

Usage:
  xguard block-ipv4 <ip4> [--iface <iface>]
  xguard block-all [--iface <iface>]
""")

def main():
    if len(sys.argv) < 2:
        help()
        return

    cmd = sys.argv[1]
    args = sys.argv[2:]

    iface = DEFAULT_IFACE
    ip4 = None

    # Simple manual arg parsing
    if "--iface" in args:
        idx = args.index("--iface")
        if idx + 1 < len(args):
            iface = args[idx + 1]
            del args[idx:idx + 2]

    if cmd == "block-ipv4":
        if not args:
            print("Error: missing IPv4 address\n")
            help()
            return
        ip4 = args[0]
        block_ipv4(ip4, iface)
    elif cmd == "block-all":
        block_all(iface)
    else:
        print(f"Unknown command: {cmd}\n")
        help()

if __name__ == "__main__":
    main()
