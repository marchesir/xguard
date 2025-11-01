#!/usr/bin/env python3
from bcc import BPF
import sys


# Traces network packets and filters them based on inputs.
# Note: The filtering happens in user space with no packets dropped.
def run_trace(iface, tcp, udp, icmp, kernel_trace):
    print(f"[run_trace] Interface: {iface}")
    print(f"[run_trace] TCP: {tcp}")
    print(f"[run_trace] UDP: {udp}")
    print(f"[run_trace] UDP: {icmp}")
    print(f"[run_trace] kernel_trace: {kernel_trace}")
    # Load eBPF program into kernel and attach the function as XDP on iface.
    b = BPF(src_file="bpf/xguard.bpf.c")
    fn = b.load_func("trace_with_filters ", BPF.XDP)
    b.attach_xdp(iface, fn, 0)

    # Communicate with Kernal eBPF/XDP program.
    try:
        print(f"[xguard] Attached XDP on interface {iface}: Press Ctrl+C to stop.")
        b.trace_print()
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
