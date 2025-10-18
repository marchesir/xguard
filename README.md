# 🔒 xguard

**Minimal real-time eBPF/XDP firewall (L3/L4)** — built for the [eBPF Summit 2025 Devpost](https://ebpf-summit-2025.devpost.com).


## 📖 Overview

**xguard** is a minimal firewall that uses **eBPF/XDP** to block IPv4 traffic at the earliest point in the Linux network stack. It is designed primarily as a **learning project** to explore:

- How **XDP programs** operate inside the kernel
- Basic **eBPF map** usage
- Low-level **L3/L4 packet filtering**

The current implementation uses **Python** for quick prototyping and simplicity. Future iterations may include:

- A full **C-based eBPF + userspace** version
- A **Go-based userspace** implementation
- More advanced filtering (e.g., ports, IPv6, connection tracking)

## 🧰 CLI Usage

```
xguard block-ipv4 <ip4> [--iface <iface>]
xguard block-ipv4 [--iface <iface>]
```

Blocks IPv4 traffic using eBPF/XDP.

- If `<ip4>` is provided, only that specific IPv4 address is blocked.
- If no IP is specified, **all IPv4 traffic** will be blocked.
- By default, the block is applied to the `lo` (loopback) interface.
- Use `--iface <iface>` to apply the rule to a specific interface.


## ⚡ How It Works
flowchart TD
    subgraph "🧱 Kernel Space"
        NIC["📡 Network Interface (NIC)"]
        XDP["⚡ xguard.bpf.c<br>eBPF Program (XDP)"]
        KernelStack["🧠 Kernel Networking Stack<br>(TCP/IP, Sockets)"]
    end

    subgraph "👨‍💻 User Space"
        App["xguard.py<br>Userspace CLI & Controller"]
    end

    NIC --> XDP
    XDP -- "XDP_PASS<br>Allow Packet" --> KernelStack
    XDP -- "XDP_DROP<br>Drop Packet" --> Drop["❌ Packet Dropped"]

    KernelStack --> App
