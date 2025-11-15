#!/usr/bin/env python3
from bcc import BPF
import sys
import time
import socket
import struct


# Convert eth_type to human-readable string (e.g., IPv4, IPv6, etc.)
def eth_type_to_str(eth_type: int) -> str:
    if eth_type == 0x0800:  # IPv4
        return "IPv4"
    elif eth_type == 0x86DD:  # IPv6
        return "IPv6"
    else:
        return f"Unknown eth_type (0x{eth_type:x})"


# Convert protocol to human-readable string (TCP, UDP, ICMP.)
def protocol_to_str(protocol: int) -> str:
    if protocol == 6:
        return "TCP"
    elif protocol == 17:
        return "UDP"
    elif protocol == 1:
        return "ICMP"
    else:
        return f"Unknown protocol (0x{protocol:x})"


# Convert IP to a human-readable string based on eth_type.
def ip_to_str(ip: int, eth_type: int) -> str:
    if eth_type == 0x0800:  # IPv4
        # Convert ip (32-bit integer) to IPv4 address string.
        return socket.inet_ntoa(struct.pack("!I", ip))
    elif eth_type == 0x86DD:  # IPv6
        # Convert it to a 128-bit representation (IPv6).  Split into two 64-bit integers and pack as 128-bit.
        ip_bytes = struct.pack("!QQ", ip >> 64, ip & ((1 << 64) - 1))
        # Convert bytes to IPv6 string
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    else:
        return f"Unknown IP (non-standard eth_type 0x{eth_type:x})"


# Traces network packets and filters them based on inputs.
# Note: The filtering happens in user space with no packets dropped.
def run_trace(iface: str, tcp: str, udp: str, icmp: str, kernel_trace: str):
    print(f"[run_trace] Interface: {iface}")
    print(f"[run_trace] TCP: {tcp}")
    print(f"[run_trace] UDP: {udp}")
    print(f"[run_trace] UDP: {icmp}")
    print(f"[run_trace] kernel_trace: {kernel_trace}")
    # Load eBPF program into kernel and attach the function as XDP on iface.
    b = BPF(src_file="bpf/xguard.bpf.c")
    fn = b.load_func("trace_with_filters", BPF.XDP)
    b.attach_xdp(iface, fn, 0)
    # Read eBPF shared map.
    hit_count = b["hit_count"]

    # Communicate with Kernal eBPF/XDP program.
    try:
        print(f"[xguard] Attached XDP on interface {iface}: Press Ctrl+C to stop.")
        # Keep track of the last key printed.
        prev_key: tuple[str, str, str] | None = None
        # Iterate over map entries.
        while True:
            for key, value in hit_count.items():
                # Convert values
                eth_type_str = eth_type_to_str(key.eth_type)
                protocol_str = protocol_to_str(key.protocol)
                ip_str = ip_to_str(key.src_ip, key.eth_type)

                # Create a tuple representing the key.
                current_key = (eth_type_str, ip_str, protocol_str)
                output = f"eth_type={eth_type_str}, src_ip={ip_str}, protocol={protocol_str}, hits={value.value}"

                if current_key == prev_key:
                    # Same key: overwrite the line.
                    print(output, end="\r", flush=True)
                else:
                    # New key: print on a new line
                    if prev_key is not None:
                        print()  # move to the next line for previous key
                    print(output, end="\r", flush=True)
                    prev_key = current_key

            # Sleep to give CPU time to process data.
            time.sleep(1)
        # b.trace_print()
    except KeyboardInterrupt:
        print("[xguard] Detaching XDP on interface {iface}.")
        b.remove_xdp(iface, 0)
        print("[xguard] Detached XDP on interface {iface}.")


def help():
    print("""
    xGuard — Lightweight eBPF/XDP tool for tracing and blocking live ingress traffic.

    Usage:
      xguard [command] [options] --interface <IFACE>

    Commands:
      trace           View live packets (default: all IPv4 packets).

    Required:
      --interface <IFACE>     Network interface to attach (e.g. eth0).

    Options:
      --tcp | --udp | --icmp  Filter on transport protocol (only one).
      --kernel-trace          Enable kernel-level tracing.
    """)


# Main function to parse command-line arguments and execute commands.
def main():
    if len(sys.argv) < 2:
        help()
        return

    cmd = sys.argv[1]
    args = sys.argv[2:]

    # Defaults
    iface = None
    tcp, udp, icmp = False, False, False
    protocol_set = False
    kernel_trace = False

    # Simple manual arg parsing.
    while args:
        arg = args.pop(0)
        if arg == "--interface":
            if args:
                iface = args.pop(0)
            else:
                print("Error: --interface requires a value.\n")
                help()
                return
        elif arg in ("--tcp", "--udp", "--icmp"):
            if protocol_set:
                print("Error: Only one protocol can be specified.\n")
                help()
                return
            tcp, udp, icmp = False, False, False  # Reset all
            if arg == "--tcp":
                tcp = True
            elif arg == "--udp":
                udp = True
            elif arg == "--icmp":
                icmp = True
            protocol_set = True
        elif arg == "--kernel-trace":
            kernel_trace = True
        else:
            print(f"Unknown option: {arg}\n")
            help()
            return

    if cmd == "trace":
        if not iface:
            print("Error: --interface is required\n")
            help()
            return
        run_trace(iface, tcp, udp, icmp, kernel_trace)
    else:
        print(f"Unknown command: {cmd}\n")
        help()


# Main entry point.
if __name__ == "__main__":
    main()
