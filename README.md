# L4 Load Balancer in DPDK and eBPF (Coursework)

A simple Layer 4 connection load balancer, implemented twice: once with DPDK (kernel-bypass, userspace) and once with eBPF/XDP (in-kernel).

The load balancer listens on `10.0.0.10` and sits between a client (`10.0.0.1`) and two backend servers (`10.0.0.2`, `10.0.0.3`) running in Linux network namespaces on a shared bridge.

- **Client → backend:** for each TCP packet, the 5-tuple is hashed to pick a backend. The load balancer then rewrites the source IP to `10.0.0.10`, rewrites the destination IP/MAC to the chosen backend, and forwards the packet.
- **Backend → client:** it rewrites the IP/MAC addresses and forwards the reply back to `10.0.0.1`.

## Files

- `net.c` — DPDK load balancer (the FIXME sections of the provided skeleton)
- `xdp_lb.bpf.c` — eBPF/XDP load balancer program
