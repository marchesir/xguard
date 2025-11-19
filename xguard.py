#!/usr/bin/env python3
from bcc import BPF
import sys
import time
import socket
import struct

# Convert eth_type to human-readable string: supported types are IPv4 and IPv6.
# The eth_type was converted from Big-endian to Little-endian, this is needed for coorect usage in user space.
def eth_type_to_str(eth_type: int) -> str | None:
    if eth_type == 0x0800:  # IPv4
        return "IPv4"
    elif eth_type == 0x86DD:  # IPv6
        return "IPv6"
    else:
        return None

# Convert protocol to human-readable string: supported protocols are TCP, UDP, ICMP.
# The prodocol is still the raw Big-endian 32-bit value, but these values are the same in both endians.
def protocol_to_str(protocol: int) -> str | None:
    if protocol == 6:
        return "TCP"
    elif protocol == 17:
        return "UDP"
    elif protocol == 1:
        return "ICMP"
    else:
        return None

# Convert IP to a human-readable string based on converted eth_type: supported types are IPv4 and IPv6.
# The IP is still in the raw Big-endian 32-bit, but fro conversion we dont need to change endianness.
def ip_to_str(ip: int, eth_type: str) -> str | None:
    if eth_type == "IPv4":
        # Convert ip (32-bit Big-endian) to IPv4 string.
        return socket.inet_ntoa(struct.pack("!I", ip))
    elif eth_type == "IPv6":
        # TODO: Currenty the eBPF program assumes IPv4-mapped 32-bit addresses only.
        # IPv6 will contain 32-bit garbage. We need to extend the eBPF program to handle full 128-bit IPv6 addresses.
        # Thus we will return None for now if the IP is less than 2^32.
        if ip < (1 << 32):
            return None
        # Convert ip to a 128-bit representation (IPv6) and split into two 64-bit integers and pack as 128-bit.
        ip_bytes = struct.pack("!QQ", ip >> 64, ip & ((1 << 64) - 1))
        # Convert bytes to IPv6 string.
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    else:
        return None

# Traces network packets and filters them based on inputs.
# Note: The filtering happens in user space with no packets dropped.
def run_trace(iface: str, userspace_trace: bool, tcp: bool, udp: bool, icmp: bool, kernel_trace: bool) -> None:
    print(f"[run_trace] Interface: {iface}")
    print(f"[run_trace] Userspace Trace: {userspace_trace}")
    print(f"[run_trace] TCP: {tcp}")
    print(f"[run_trace] UDP: {udp}")
    print(f"[run_trace] UDP: {icmp}")
    print(f"[run_trace] kernel Trace: {kernel_trace}")

    # Load eBPF program into kernel and attach the function as XDP on iface.
    b = BPF(src_file="bpf/xguard.bpf.c")
    fn = b.load_func("trace_with_filters", BPF.XDP)
    b.attach_xdp(iface, fn, 0)
    # Read eBPF shared map.
    hit_count = b["hit_count"]

    # Communicate with Kernal eBPF/XDP program.
    try:
        print(f"[xguard] Attached XDP on interface {iface}: Press Ctrl+C to stop.")
        while True:
            if kernel_trace:
                # Invoke kernel trace.
                b.trace_print()
            elif userspace_trace:
                # Invoke userspace trace.    
                # Iterate over eBPF shared map.
                for key, value in hit_count.items():
                    eth_type_str = eth_type_to_str(key.eth_type)
                    protocol_str = protocol_to_str(key.protocol)
                    ip_str = ip_to_str(key.src_ip, eth_type_str)
                    # Ignore errors.
                    if None in (eth_type_str, protocol_str, ip_str):
                        continue
                    # Apply protocol filters.
                    elif tcp and protocol_str != "TCP":
                        continue
                    elif udp and protocol_str != "UDP":
                        continue
                    elif icmp and protocol_str != "ICMP":
                        continue
                    print(f"eth_type={eth_type_str}, src_ip={ip_str}, protocol={protocol_str}, hits={value.value}")
                # Sleep to give CPU time to process data.
                time.sleep(1)
    except KeyboardInterrupt:
        print("[xguard] Detaching XDP on interface {iface}.")
        b.remove_xdp(iface, 0)
        print("[xguard] Detached XDP on interface {iface}.")

# Display usage information.
def usage() -> None:
    print("""
xGuard — Lightweight eBPF/XDP tool for tracing live ingress traffic.

Usage:
    xguard --interface <iface> --kernel-trace | --userspace-trace [--tcp | --udp | --icmp]

Required:
    --interface <iface>                 Network interface to monitor (e.g., eth0).
    --kernel-trace | --userspace-trace  One of these options must be selected: Tracing mode (kernel or userspace).

Optional (only available with --userspace-trace):
    --tcp                               Trace only TCP traffic.
    --udp                               Trace only UDP traffic.
    --icmp                              Trace only ICMP traffic.
""")

# Main function to parse command-line arguments and execute commands.
def main():
    if len(sys.argv) < 2:
        usage()
        return

    args = sys.argv[1:]

    # Defaults
    iface = None
    tcp, udp, icmp = False, False, False
    protocol_set = False
    kernel_trace = False
    userspace_trace = False

    # Parse command-line arguments.
    while args:
        arg = args.pop(0)
        if arg == "--interface":
            if args:
                iface = args.pop(0)
            else:
                print("Error: --interface requires a value.\n")
                usage
                return
        elif arg == "--kernel-trace":
            kernel_trace = True
            userspace_trace = False  # If kernel-trace is set, ignore userspace-trace.
        elif arg == "--userspace-trace":
            userspace_trace = True
            kernel_trace = False  # If userspace-trace is set, ignore kernel-trace.
        elif arg in ("--tcp", "--udp", "--icmp"):
            if not userspace_trace:
                print("Error: Protocol flags (--tcp, --udp, --icmp) are only allowed with --userspace-trace.\n")
                usage
                return
            if protocol_set:
                print("Error: Only one protocol can be specified.\n")
                usage
                return
            tcp, udp, icmp = False, False, False  # Reset all.
            if arg == "--tcp":
                tcp = True
            elif arg == "--udp":
                udp = True
            elif arg == "--icmp":
                icmp = True
            protocol_set = True
        else:
            print(f"Unknown option: {arg}\n")
            usage()
            return

    if not iface:
        print("Error: --interface is required\n")
        usage()
        return

    if not kernel_trace and not userspace_trace:
        print("Error: One of --kernel-trace or --userspace-trace is required.\n")
        usage()
        return
    # Run the trace with the parsed args.
    run_trace(iface, userspace_trace, tcp, udp, icmp, kernel_trace)

# Main entry point.
if __name__ == "__main__":
    main()