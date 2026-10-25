# Aethon

**An inline intrusion prevention system and TLS-terminating reverse proxy built on eBPF/XDP and AF_XDP, with its own userspace TCP stack.**

Aethon sits in front of your web services on a single Linux host. XDP steers traffic for the ports you protect into userspace through AF_XDP sockets; everything else (SSH, DNS, IPv6, UDP) goes straight to the kernel untouched. In userspace, Aethon terminates TCP and TLS itself, inspects the plaintext with Hyperscan in streaming mode, enforces SNI policy, and proxies clean traffic to your backends on loopback.

![C++20](https://img.shields.io/badge/C%2B%2B-20-blue) ![Linux](https://img.shields.io/badge/platform-Linux-lightgrey) ![eBPF/XDP](https://img.shields.io/badge/eBPF-XDP%20%2B%20AF__XDP-orange) ![License: MIT](https://img.shields.io/badge/license-MIT-green)

> **Status:** research / portfolio project under active development. It passes an end-to-end test suite with real clients (curl, wrk, browsers) through nginx and Node.js, including transfers under packet loss, but it has not been hardened for production. See [Known limitations](#known-limitations).

---

## Contents
- [Why](#why)
- [Architecture](#architecture)
- [Features](#features)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Testing](#testing)
- [Measured results](#measured-results)
- [Known limitations](#known-limitations)
- [Project layout](#project-layout)
- [Roadmap](#roadmap)
- [Contributing, security and conduct](#contributing-security-and-conduct)
- [References](#references)
- [License](#license)

---

## Why

A classic single-server setup for inspecting web traffic is several separate systems: the kernel TCP stack, an IDS such as Suricata (often copying every packet to userspace through NFQUEUE), a TLS terminator, and a WAF in the web server. Aethon explores doing this in **one process on the packet path**:

- **Early drops in the driver:** XDP can discard unwanted traffic before the kernel allocates anything for it.
- **Kernel bypass for protected ports:** packets arrive in userspace through shared-memory rings, without a syscall or an `sk_buff` per packet.
- **Inspection of encrypted traffic:** Aethon terminates TLS, so rules run on the decrypted HTTP payload, across packet and TLS-record boundaries.
- **Full control on a small VPS:** one binary, plain-text config files, no cluster.

## Architecture

```
                         Internet / client
                                │
                        NIC driver (eth0 / veth0)
                                │
  ┌─────────────────────────────▼─────────────────────────────────────┐
  │ XDP program (src/main/ebpf/xdp_kern_prog.c)                        │
  │  • TCP to a managed port (aethon_services_map) → AF_XDP socket     │
  │  • TCP fragments → XDP_DROP                                        │
  │  • everything else (SSH, DNS, UDP, IPv6, ARP) → XDP_PASS → kernel  │
  └─────────────────────────────┬─────────────────────────────────────┘
                                │ AF_XDP RX ring (UMEM, one socket per queue)
  ┌─────────────────────────────▼─────────────────────────────────────┐
  │ Userspace engine (src/main/afxdp_control.cpp), one pinned worker   │
  │ per NIC queue, each with its own session table                     │
  │                                                                    │
  │  IPv4 validation → TCP state machine (transport/)                  │
  │     handshake · reassembly · overlap-evasion check · flow control  │
  │     RFC 6298 RTO · Reno congestion control · fast retransmit       │
  │                         │                                          │
  │  TLS (tls/): ClientHello parsing (SNI, JA3) → SNI blocklist        │
  │     → OpenSSL termination with memory BIOs                         │
  │                         │                                          │
  │  DPI (dpi/): Hyperscan streaming scan of plaintext                 │
  │     (Snort/Suricata `content` rules)                               │
  │                         │ clean                     │ match        │
  │                         ▼                           ▼              │
  │          epoll-driven loopback socket          RST to client       │
  │          to the backend service                                    │
  └─────────────────────────────┬─────────────────────────────────────┘
                                │ AF_XDP TX ring (responses, ACKs, RSTs)
                                ▼
                             client
```

Responses from the backend are read through epoll, encrypted if the session is TLS, segmented to the client's MSS and sent through the AF_XDP TX ring with Aethon's own sequence numbers, retransmission timers and congestion window.

## Features

### Data plane (eBPF/XDP)
- Port-based steering: only TCP ports listed in `rules/services.conf` reach userspace; all other traffic is passed to the kernel.
- TCP fragment dropping (fragmented TCP is a classic evasion technique).
- Multi-queue: one AF_XDP socket and one worker thread per NIC queue, pinned to its own core.
- Zero-copy bind attempted first (`XDP_ZEROCOPY`), with automatic fallback to copy mode.

### Userspace TCP stack
- Three-way handshake with SipHash-2-4 initial sequence numbers (RFC 6528) and an MSS option.
- Reassembly of out-of-order data in a 64 KB ring buffer with a byte-level bitmap.
- **Overlap evasion detection:** a retransmission whose bytes disagree with data already buffered kills the session (Ptacek & Newsham, 1998).
- Duplicate ACKs on reordering, flow control in both directions with real window advertisement and backpressure to and from the backend, window updates.
- RFC 6298 retransmission timer (SRTT/RTTVAR, Karn's rule, exponential backoff), Reno congestion control (RFC 5681) with fast retransmit, go-back-N on timeout.
- Graceful close in both directions, half-close (client FIN while the response is still being sent), FIN retransmission, RST handling, challenge ACKs for in-window SYNs (RFC 5961), RST/ACK for packets of unknown sessions.

### TLS
- ClientHello reassembly across segments (large post-quantum ClientHellos from modern browsers).
- SNI policy: domains listed in `rules/blocked_domains.txt`, and their subdomains, are reset.
- JA3 fingerprint extraction from the ClientHello. A per-fingerprint rate limiter exists in `tcp_pipeline.h` but is commented out (see Known limitations).
- TLS termination through OpenSSL memory BIOs, routed to a backend by SNI or by destination IP:port.

### Deep packet inspection
- Hyperscan **streaming mode**: patterns split across packets or TLS records are still detected.
- Loads Snort/Suricata-style rules (`content`, `nocase`, `sid`, `msg`).

## Quick start

### Requirements
- Linux with XDP and AF_XDP support (developed on kernel 6.x/7.x, x86_64)
- A C++20 compiler (GCC 13+ or Clang 16+), CMake ≥ 3.20, clang/LLVM for the BPF program
- Libraries: libxdp, libbpf, Hyperscan (libhs), OpenSSL 3, liburing

```bash
sudo apt install -y build-essential cmake clang llvm pkg-config \
    libxdp-dev libbpf-dev libhyperscan-dev libssl-dev liburing-dev
```

### Build
```bash
git clone https://github.com/programmingGod-byte/AETHON.git aethon
cd aethon
./build.sh --release          # or: cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
```

### Run in a safe sandbox (veth + network namespace)
Never try Aethon first on the interface you use for SSH. The repository includes a virtual test network:

```bash
sudo ./veth0.bash                                  # veth0 (192.168.50.1) <-> client_ns (192.168.50.2)
sudo ./build/src/afxdp_control veth0               # attach and start the workers

# from the client namespace:
sudo ip netns exec client_ns curl -v http://192.168.50.1/
```

For a complete setup with nginx and a Node.js app behind Aethon, see [`tests/web_app_test/`](tests/web_app_test/README.md).

To detach XDP: `sudo ip link set dev veth0 xdp off`

## Configuration

All configuration lives in `rules/` and is read at startup.

| File | Purpose | Format |
|---|---|---|
| `rules/services.conf` | Protected services and their backends | `<domain or ip:port> <cert or none> <key or none> <backend_port>` |
| `rules/blocked_domains.txt` | SNI blocklist (subdomains included) | one domain per line, `#` comments |
| `rules/test_rules.rules` | DPI signatures | Snort/Suricata rules with `content`, `nocase`, `sid`, `msg` |

Example `services.conf`:
```
192.168.50.1:443 certs/server.crt certs/server.key 8080   # TLS on :443, terminated, proxied to 127.0.0.1:8080
192.168.50.1:80  none none 8080                           # plain HTTP on :80 → 127.0.0.1:8080
api.example.com  certs/api.crt certs/api.key 5000         # TLS routed by SNI
```

Backends must listen on **127.0.0.1**. If they listen on `0.0.0.0`, clients can reach them directly on their own port and bypass Aethon.

## Testing

| Suite | Needs root | What it covers |
|---|---|---|
| `build/src/test_tcp_reassembly` | no | Targeted regression tests: resegmented retransmissions, overlap evasion, partial hole fills, ring wrap-around, SNI policy |
| `build/src/test_tcp_fuzz [seeds] [bytes]` | no | Randomized reassembly under loss, reordering, duplicates, stale replays, out-of-window junk and tiny segments; the output stream must match byte for byte |
| `tests/web_app_test/test.sh` | yes | Real clients through Aethon → nginx → Node.js: pages, APIs, keep-alive, sha256 of 5 MB downloads and 20 MB uploads over HTTP and HTTPS, DPI (plain and inside TLS), SNI blocking, bypass check; `--netem` adds delay and loss, `--load` runs wrk |
| `tests/web_app_test/torture.sh` | yes | Network chaos in both directions (reorder, duplicates, jitter, burst loss, corruption, bandwidth caps), concurrency, connection churn with a leak check, protocol edge cases, adversarial clients (split-payload evasion, slowloris, aborted transfers, handshake floods, SYN floods) |
| `tests/run_tests.sh` | yes | Older raw-packet scenarios: floods, fragmentation attacks, RST injection, JA3 rate limiting (option 16 needs the JA3 limiter re-enabled) |

```bash
cmake --build build -j && ./build/src/test_tcp_reassembly && ./build/src/test_tcp_fuzz
cd tests/web_app_test && ./start.sh        # then start Aethon, then:
./test.sh && ./test.sh --netem && ./torture.sh --quick
```

Step-by-step instructions: [`tests/web_app_test/test.txt`](tests/web_app_test/test.txt).

## Measured results

Measured on a laptop over veth in generic XDP mode, with wrk and nginx on the same machine. These numbers show behavior, not production performance; a real NIC in native zero-copy mode is a different environment.

| Test | Result |
|---|---|
| End-to-end suite (`test.sh`) | 18/18 pass, also with 50 ms delay and 2% loss in the client's direction |
| Static page through Aethon (wrk, 100 connections) | ~110k req/s, 1.9 ms average latency |
| Same page from nginx directly | ~104k req/s, 1.0 ms average latency |
| API request through Aethon → nginx → Node.js | ~54k req/s, 3.5 ms average latency |
| Aethon resident memory after the load test | ~111 MB |

The nginx-direct baseline ran wrk on the host competing with nginx for the same cores, so read the comparison as "Aethon was not the bottleneck at ~100k req/s", not as Aethon being faster than nginx.

## Known limitations

Being explicit about these is part of the project.

- **IPv4 only.** IPv6 is passed to the kernel uninspected.
- **TCP checksums are not verified**, only the IPv4 header checksum. Corrupted segments can reach the backend.
- **No window scaling or SACK.** At most 64 KB in flight, so throughput over long, lossy paths is far below Linux.
- **No SYN cookies.** A spoofed SYN flood can fill the session table.
- **Established sessions expire after 30 s idle**, shorter than typical browser and nginx keep-alive timeouts.
- **No global memory budget.** Per-session buffers are capped, but a slow-read attack across many connections can still exhaust memory.
- **Flows must stay on one RX queue.** Sessions live in per-worker tables; real NICs guarantee this through RSS, while multi-queue veth setups need `net.core.txrehash=0` on the client.
- **JA3 rate limiting is disabled** (commented out, kept for later). Before re-enabling it: its table is shared between worker threads without locking, the limit is global per fingerprint (all clients of one TLS library share a JA3), and each entry holds a 256 KB array.
- **The XDP rate limiter and IP blocklist are implemented but disabled** in the BPF program.
- **TLS handshakes and logging run on the packet threads**, so handshake floods and log floods slow down packet processing.
- **ICMP is handled in userspace** (echo only); other ICMP types are dropped, which can break path MTU discovery.

## Project layout

```
aethon/                 lock-free queues, hash maps, small containers, allocation helpers
src/main/afxdp_control.cpp   entry point: setup, AF_XDP RX/TX loop, workers, stats
src/main/ebpf/          XDP program and maps
src/main/transport/     TCP reassembly, pipeline, congestion control, UDP reassembly
src/main/tls/           ClientHello/JA3 parser, OpenSSL engine, SNI blocklist, service registry
src/main/dpi/           Hyperscan engine and Snort/Suricata rule parser
src/main/net/           packet construction (SYN-ACK, data, ACK, FIN, RST)
src/af_xdp_header.h     AF_XDP engine: UMEM, rings, socket setup
rules/                  configuration and signature files
tests/                  unit, fuzz, end-to-end and torture tests
benchmarks/             microbenchmarks for the container library
docs/                   design notes and the project website
```

## Roadmap

1. TCP checksum verification, SYN cookies, longer idle timeout with keep-alive handling.
2. Global memory budget with backpressure, fail-open (detach XDP if the process dies).
3. Asynchronous logging: per-worker lock-free rings, a logger thread, rate-limited events.
4. Window scaling and SACK.
5. Native-mode benchmarks on a real NIC; comparison with Suricata + nginx.

## Contributing, security and conduct

- [CONTRIBUTING.md](CONTRIBUTING.md): build, test and pull request guidelines
- [SECURITY.md](SECURITY.md): how to report a vulnerability privately
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): expectations for everyone in the project
- [ACCESSIBILITY.md](ACCESSIBILITY.md): accessibility commitment and known barriers

## References

- Ptacek & Newsham, [Insertion, Evasion, and Denial of Service: Eluding Network Intrusion Detection](https://users.ece.cmu.edu/~adrian/731-sp04/readings/Ptacek-Newsham-ids98.pdf), 1998
- Jeong et al., [mTCP: a Highly Scalable User-level TCP Stack for Multicore Systems](https://www.usenix.org/system/files/conference/nsdi14/nsdi14-paper-jeong.pdf), NSDI 2014
- Jamshed et al., [Kargus: A Highly-Scalable Software-based Intrusion Detection System](https://dl.acm.org/doi/pdf/10.1145/2382196.2382232), ACM CCS 2012
- Cloudflare, [Unimog: Cloudflare's edge load balancer](https://blog.cloudflare.com/unimog-cloudflares-edge-load-balancer/)
- RFC 5681 (congestion control), RFC 6298 (retransmission timer), RFC 6528 (ISN generation), RFC 5961 (blind in-window attacks)

## License

Aethon is released under the [MIT License](LICENSE), except:
- `src/main/ebpf/xdp_kern_prog.c` is licensed under GPL-2.0, as declared to the kernel in the program itself;
- third-party rule sets in `rules/` keep their own licenses (see the license files in that directory).
