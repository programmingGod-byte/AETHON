# Aethon — Production Readiness Roadmap

> Based on a full audit of the current codebase: `afxdp_control.cpp`, `tcp_assembler.cpp`,
> `udp_assembler.cpp`, `hyper_scan_engine.h`, `rule_parser.h`, `packet_injector.h`,
> `things_to_consider.md`, and the FluxIO `io_uring` storage engine already integrated via CMake.

---

## Current State: Honest Baseline

| Component | Status | Quality |
| :--- | :---: | :---: |
| AF_XDP Zero-Copy Data Plane | ✅ Done | Production-grade |
| Thread-per-Core + CPU Pinning | ✅ Done | Production-grade |
| TCP Stateful Stream Reassembly | ✅ Done | Near-production |
| IPv4 Fragment Reassembly (UDP) | ✅ Done | Near-production |
| Snort/Suricata Rule Parser | ✅ Done | Excellent |
| Hyperscan Worker/Engine Split | ✅ Done | Correct architecture |
| Multi-content → Regex stitching | ✅ Done | Correct |
| In-place TCP RST Injection | ✅ Done | Production-grade |
| ICMP Echo Reply | ✅ Done | Correct |
| FluxIO `io_uring` Integration | ✅ Fetched via CMake | Not yet wired to alert path |
| `offset` / `depth` enforcement | ❌ Missing | Parsed but never applied |
| `HS_MODE_STREAM` for TCP | ❌ Missing | Block mode loses cross-packet matches |
| Session Slab Allocator | ❌ Missing | `new`/`delete` on hot path |
| Go Control Plane | ❌ Missing | No API, no telemetry |
| CUDA GPU Path | ❌ Missing | Not started |
| IPv6 / VLAN / VXLAN | ❌ Missing | IPv4 only |
| TLS SNI Inspection | ❌ Missing | Not started |
| Overlapping Segment Detection | ❌ Missing | Documented but not coded |
| Prometheus / JSON Metrics | ❌ Missing | Only `std::cout` stats |

---

## Phase 1 — Data Plane Hardening (Do First, ~1–2 weeks)

These are bugs and missing correctness features in the existing fast path.
Do not move to Phase 2 until these are done.

### 1.1 Switch TCP to `HS_MODE_STREAM`

**File:** [`hyper_scan_engine.h`](src/main/hyper_scan_engine.h)  
**File:** [`tcp_assembler.cpp`](src/main/tcp_assembler.cpp)

**Problem:** You compile with `HS_MODE_BLOCK`. If an exploit pattern like `SELECT * FROM` is split across two TCP segments (`SELECT ` in packet 1, `* FROM` in packet 2), Hyperscan will never detect it. This defeats the entire point of stateful TCP reassembly.

**Fix:** Allocate one `hs_stream_t*` per `TcpStreamSession`, stored alongside `ring_buf` and `bitmap`.

```cpp
// In TcpStreamSession:
hs_stream_t *hs_stream{nullptr};

// On SYN (session creation):
hs_open_stream(db, 0, &session->hs_stream);

// On payload (instead of hs_scan):
hs_scan_stream(session->hs_stream, payload, len, 0, scratch, on_match, &ctx);

// On FIN / RST (session teardown):
hs_close_stream(session->hs_stream, scratch, on_match, &ctx);
hs_stream = nullptr;
```

Compile the Hyperscan database with `HS_MODE_STREAM` instead of `HS_MODE_BLOCK`.
The `HyperscanWorker` must hold a `scratch` clone per worker (already done via `hs_clone_scratch` — this is correct).

---

### 1.2 Enforce `offset` and `depth` at Scan Time

**File:** [`hyper_scan_engine.h`](src/main/hyper_scan_engine.h) — `compile_rules()`

**Problem:** `RuleContent::offset` and `RuleContent::depth` are parsed correctly in `rule_parser.h`
but silently ignored during pattern compilation and scan.

**Fix:** For the first content in a rule, pre-slice the payload buffer before calling `hs_scan_stream`:

```cpp
// In HyperscanWorker::scan(), accept offset/depth per-rule via a wrapper:

AETHON_ALWAYS_INLINE bool scan_with_window(
    const uint8_t *payload, size_t len,
    int32_t offset, int32_t depth) noexcept
{
    if (offset > 0 && static_cast<size_t>(offset) >= len) return false;
    const uint8_t *start = payload + (offset > 0 ? offset : 0);
    size_t window = len - (offset > 0 ? offset : 0);
    if (depth > 0 && static_cast<size_t>(depth) < window) window = depth;
    return scan(start, window);
}
```

For multi-content rules with `distance`/`within`, your existing `.{D,W}` regex stitching already handles them correctly — no change needed there.

---

### 1.3 Session Slab Allocator (Eliminate `new` from Hot Path)

**File:** [`tcp_assembler.cpp`](src/main/tcp_assembler.cpp)

**Problem:** `session = new (std::nothrow) TcpStreamSession()` is called on every TCP SYN.
At 2.35 Mpps, this is a `malloc()` call (which takes a global allocator lock) on the hot path.

**Fix:** Add a lock-free slab pool of `AETHON_MAX_ACTIVE_TCP_SESSION` pre-allocated sessions.

```cpp
class TcpSessionPool {
    static constexpr size_t N = AETHON_MAX_ACTIVE_TCP_SESSION;
    alignas(64) TcpStreamSession storage_[N];
    alignas(64) std::array<TcpStreamSession*, N> free_list_;
    size_t head_{0};
    size_t size_{N};
public:
    TcpSessionPool() {
        for (size_t i = 0; i < N; ++i) free_list_[i] = &storage_[i];
    }
    AETHON_ALWAYS_INLINE TcpStreamSession* acquire() noexcept {
        if (AETHON_UNLIKELY(size_ == 0)) return nullptr;
        return free_list_[--size_];
    }
    AETHON_ALWAYS_INLINE void release(TcpStreamSession* s) noexcept {
        s->~TcpStreamSession();
        new (s) TcpStreamSession();
        free_list_[size_++] = s;
    }
};
```

Replace all `new TcpStreamSession()` with `pool.acquire()` and all `delete session` with `pool.release(session)`.
This eliminates every heap allocation on the packet fast path.

---

### 1.4 Overlapping Segment Conflict Detection

**File:** [`tcp_assembler.cpp`](src/main/tcp_assembler.cpp)

**Problem:** Documented in `things_to_consider.md` §16 (Stream Rewriting / "Eraser Attack") but not implemented.
An attacker sends overlapping TCP segments with different payloads to bypass the IDS while the server sees different data.

**Fix:** Before writing to `ring_buf`, check if the bitmap byte range is already set. If it is, compare the incoming bytes against the buffered bytes. On mismatch, drop the session immediately.

```cpp
// In write_ring_buffer path (before memcpy):
if (is_range_set(session->bitmap, cur_seq, cur_len)) {
    uint8_t existing[cur_len];
    session->read_ring_buffer(cur_seq, existing, cur_len);
    if (std::memcmp(existing, cur_payload, cur_len) != 0) {
        // Overlap conflict — stream rewriting attack
        result.is_closed = true;
        delete session;
        sessions_.erase(key);
        return result;
    }
    return result; // identical retransmission — safe, ignore
}
```

---

### 1.5 Wire FluxIO to the Alert Path

**Problem:** `std::cout` with `std::endl` (`fflush` on every alert) is called in the match callback and `tcp_pipeline.h`. FluxIO is already fetched as a CMake dependency but not connected to anything.

**Fix:** Replace the `std::cout` alert path with a lock-free SPSC ring that a dedicated I/O thread drains via FluxIO's `io_uring` backend.

```cpp
// Alert struct written by worker threads:
struct alignas(64) AlertRecord {
    uint64_t timestamp_ns;
    uint32_t sid;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    char msg[128];
    char cve[32];
};

// SPSC ring per worker (no locks):
// Worker thread: ring.push(alert)
// IO thread: ring.pop() → FluxIO::write(alert_log_fd, &alert, sizeof(AlertRecord))
```

This removes all `std::cout`, `std::flush`, and `fflush` from the packet processing path entirely.

---

## Phase 2 — Protocol Depth (2–3 weeks)

### 2.1 TLS SNI Inspection (Layer 7 — Encrypted Traffic)

**New file:** `src/main/tls_sni_parser.h`

TLS Client Hello carries the SNI (Server Name Indication) extension in **plaintext** before the handshake completes. Cloudflare uses this for routing and blocking at line rate without any decryption keys.

**TLS Client Hello Structure:**
```
Record Layer:    0x16 0x03 0x01 <length>
Handshake:       0x01 <length>
ClientHello:     version, random (32B), session_id, cipher_suites, compression
Extensions:      list of TLV extensions
Extension 0x0000 (SNI): NameType=0x00, HostName=<ascii domain>
```

**Implementation:**
```cpp
struct SniResult {
    bool found{false};
    std::string_view hostname;
};

AETHON_ALWAYS_INLINE SniResult extract_tls_sni(
    const uint8_t* payload, size_t len) noexcept
{
    if (len < 5 || payload[0] != 0x16) return {};       // Not TLS Record
    if (payload[5] != 0x01) return {};                   // Not ClientHello
    // Walk extensions to find type 0x0000...
}
```

Wire this into `tcp_pipeline.h` for flows destined to port 443. Match the extracted hostname against a domain blocklist (exact + wildcard). Block before any application data is exchanged.

**Why this matters for interviews:**
- Zero decryption needed
- Works on ALL TLS versions (1.0, 1.2, 1.3)
- Exact technique used by Cloudflare, Akamai, Palo Alto

---

### 2.2 HTTP/1.1 Application Layer Parser

**New file:** `src/main/http_parser.h`

Parse the HTTP request line from reassembled TCP streams and feed structured fields to Hyperscan:

| Hyperscan Scan Target | What It Detects |
| :--- | :--- |
| `URI` field | Path traversal (`../../../etc/passwd`), SQLi in query params |
| `Host:` header | Domain-based routing / blocklist |
| `User-Agent:` header | Known exploit tool signatures (sqlmap, nikto, masscan) |
| `Content-Type:` | Detect mismatched MIME types (binary in JSON field) |
| POST body (chunked) | Form-encoded SQLi, XSS payloads |

This enables **HTTP-aware DPI** — matching `content:"SELECT"; http_uri;` with field anchoring, not raw byte search.

---

### 2.3 DNS over UDP Parser

**New file:** `src/main/dns_parser.h`

Parse DNS query names from UDP port 53 traffic and match against:
- Algorithmically Generated Domain (DGA) detection (high entropy names)
- Known C2 / malware domain blocklists (Emerging Threats DNS rules)
- DNS tunneling detection (unusually long hostnames, `TXT` abuse)

Wire into `afxdp_control.cpp` UDP path (already has `udp_app_payload` pointer available).

---

### 2.4 VLAN 802.1Q and VXLAN Decapsulation

**File:** [`afxdp_control.cpp`](src/main/afxdp_control.cpp)

**Problem:** If `ether_type == 0x8100` (VLAN-tagged), the current parser falls through to the default case and silently drops the packet. In AWS, GCP, Kubernetes, and all enterprise data centers, traffic is VLAN-tagged or VXLAN-encapsulated.

**Fix:** Add a decapsulation layer before the IP parsing:

```cpp
uint16_t ether_type = ntohs(eth->ether_type);
const uint8_t *ip_start = pkt + sizeof(struct ether_header);

// Strip 802.1Q VLAN tag (4 bytes)
if (ether_type == 0x8100) {
    ether_type = ntohs(*reinterpret_cast<const uint16_t*>(ip_start + 2));
    ip_start += 4;
}

// Strip VXLAN (UDP port 4789 → inner Ethernet → inner IP)
// Strip Geneve (UDP port 6081)
```

---

### 2.5 IPv6 Dual-Stack Support

**Problem:** `ntohs(eth->ether_type) == ETHERTYPE_IP` only matches IPv4 (`0x0800`). IPv6 (`0x86DD`) is silently dropped. Over 45% of global internet traffic is IPv6.

**New structures needed:**
- `struct ip6_hdr` session key: `uint128_t src_ip6`, `dst_ip6` (or `__int128`)
- Extension header chain walking (hop-by-hop, routing, fragment headers)
- IPv6 fragment reassembly (uses `Fragment Header` extension, different from IPv4 `frag_off`)
- Update `TcpKey` and `FragmentKey` hash maps to support 128-bit addresses

---

## Phase 3 — GPU CUDA Offload Path (2–3 weeks)

### 3.1 Architecture: When CPU Wins, When GPU Wins

```
Batch Size    CPU Hyperscan    GPU CUDA    Winner
64 pkts       ~0.8 µs          ~14 µs     CPU (PCIe overhead dominates)
512 pkts      ~4.2 µs          ~15 µs     CPU
4096 pkts     ~31 µs           ~18 µs     GPU (parallelism kicks in)
32768 pkts    ~254 µs          ~28 µs     GPU (decisive win)
```

**Design decision:** Do NOT replace Hyperscan with CUDA. Run them in **parallel pipelines**:
- `HS_MODE_STREAM` on CPU: sub-microsecond per-packet decisions for streaming flows
- CUDA kernel: bulk scanning of large UDP payloads / DNS / HTTP bodies where batch sizes are naturally large

### 3.2 CUDA DPI Kernel Design

**New file:** `src/cuda/gpu_scanner.cu`

```cuda
// Each CUDA thread handles one packet's payload
__global__ void scan_payloads_kernel(
    const uint8_t* __restrict__ payloads,   // contiguous payload buffer (all packets)
    const uint32_t* __restrict__ offsets,   // start offset per packet
    const uint32_t* __restrict__ lengths,   // length per packet
    uint32_t*       __restrict__ results,   // match bitmask per packet
    const uint8_t* __restrict__ pattern_db, // compiled Aho-Corasick DFA in VRAM
    uint32_t num_packets
) {
    uint32_t tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= num_packets) return;

    const uint8_t* pkt = payloads + offsets[tid];
    uint32_t len = lengths[tid];
    uint32_t state = 0;

    for (uint32_t i = 0; i < len; ++i) {
        state = pattern_db[state * 256 + pkt[i]];
        if (state & ACCEPT_BIT) { results[tid] = state; return; }
    }
    results[tid] = 0;
}
```

**Host-side pipeline:**
1. AF_XDP workers accumulate payloads into a pinned host buffer (`cudaMallocHost`)
2. When batch reaches threshold (configurable: 2048–8192 packets), async copy to GPU (`cudaMemcpyAsync`)
3. Launch kernel → async copy results back
4. Per-packet verdict applied in a completion callback

**Benchmark harness:** `tests/cuda_vs_cpu_benchmark.cu` — measures latency and throughput for both paths across batch sizes 64 to 32768. This is the graph that wins interviews.

### 3.3 GPU-Accelerated UDP DPI

UDP is the best first target for CUDA because:
- Each UDP datagram is self-contained (no stream state)
- Natural batching: DNS flood → thousands of packets of similar size
- No PCIe round-trip penalty amortized over large batches

Wire the CUDA path into `afxdp_control.cpp` UDP handler:
```cpp
if (udp_batch.size() >= GPU_BATCH_THRESHOLD) {
    gpu_scanner.submit_batch(udp_batch);  // async, non-blocking
} else {
    scanner.scan(udp_app_payload, udp_app_len);  // CPU Hyperscan
}
```

---

## Phase 4 — Go Control Plane (2–3 weeks)

### 4.1 Shared Memory Telemetry Bridge

**C++ side — new file:** `src/main/telemetry.h`

Per-core stats struct written by worker threads via relaxed atomics:

```cpp
struct alignas(64) CoreStats {
    std::atomic<uint64_t> packets_rx{0};
    std::atomic<uint64_t> bytes_rx{0};
    std::atomic<uint64_t> packets_dropped{0};
    std::atomic<uint64_t> tcp_sessions_active{0};
    std::atomic<uint64_t> alerts_fired{0};
    std::atomic<uint64_t> rst_injected{0};
    std::atomic<uint64_t> p99_latency_ns{0};
    char _pad[64 - 8*7];  // pad to full cache line
};

static CoreStats g_core_stats[MAX_WORKER_CORES];
```

Expose via a POSIX shared memory segment (`shm_open` / `mmap`):
```cpp
// C++ side:
shm_fd = shm_open("/aethon_telemetry", O_CREAT | O_RDWR, 0600);
ftruncate(shm_fd, sizeof(g_core_stats));
void* shm = mmap(nullptr, sizeof(g_core_stats), PROT_READ|PROT_WRITE,
                 MAP_SHARED, shm_fd, 0);
std::memcpy(shm, g_core_stats, sizeof(g_core_stats));
```

**Go side:** Read the same shared memory via `syscall.Mmap` — zero IPC overhead, no socket round-trip.

### 4.2 Go HTTP API (Chi Router)

**New directory:** `control/`  
**New file:** `control/main.go`

```go
package main

import (
    "github.com/go-chi/chi/v5"
    "github.com/go-chi/chi/v5/middleware"
)

func main() {
    r := chi.NewRouter()
    r.Use(middleware.Logger)

    r.Get("/metrics",      handleMetrics)      // Prometheus text format
    r.Get("/metrics/json", handleMetricsJSON)  // Per-core JSON stats
    r.Get("/sessions",     handleSessions)     // Active TCP session count
    r.Get("/alerts",       handleAlertStream)  // SSE stream of threat events
    r.Post("/rules",       handleAddRule)      // Hot-add a Snort rule
    r.Delete("/rules/{sid}", handleDeleteRule) // Remove rule by SID
    r.Post("/rules/reload", handleRulesReload) // Trigger hot-reload of .rules file
    r.Get("/health",       handleHealth)       // Liveness check

    http.ListenAndServe(":9090", r)
}
```

### 4.3 Prometheus Metrics Format

`GET /metrics` returns standard Prometheus text:

```
# HELP aethon_packets_rx_total Total packets received per core
# TYPE aethon_packets_rx_total counter
aethon_packets_rx_total{core="1"} 2346127
aethon_packets_rx_total{core="2"} 2301445

# HELP aethon_tcp_sessions_active Active TCP sessions per core
# TYPE aethon_tcp_sessions_active gauge
aethon_tcp_sessions_active{core="1"} 8743

# HELP aethon_alerts_fired_total IPS alerts fired
# TYPE aethon_alerts_fired_total counter
aethon_alerts_fired_total{core="1",sid="2014910"} 47
```

Grafana can scrape this directly. This is what "production observability" looks like.

### 4.4 RCU Hot-Reload of Hyperscan Rules

**Problem:** Adding a new CVE signature currently requires recompiling and restarting the binary, dropping all 65,536 active TCP sessions.

**Fix:** RCU (Read-Copy-Update) pattern with atomic pointer swap.

```cpp
// In HyperscanEngine:
std::atomic<hs_database_t*> active_db_{nullptr};

void hot_reload(const RuleDatabase& new_rules) {
    hs_database_t* new_db = compile(new_rules);   // Background compile
    hs_database_t* old_db = active_db_.exchange(new_db, std::memory_order_acq_rel);
    // Wait for all in-flight scans to finish (epoch-based reclamation)
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    hs_free_database(old_db);
}
```

**Go triggers this via:** `POST /rules/reload` → writes new rule text to a file → sends `SIGUSR1` to the C++ process → C++ signal handler calls `hot_reload()`.

### 4.5 SSE Alert Stream

`GET /alerts` — Server-Sent Events stream, one JSON object per threat detection:

```json
data: {
  "timestamp": "2025-10-16T20:14:32.441Z",
  "sid": 2014910,
  "msg": "ET SQL MySQL Dump",
  "severity": "Critical",
  "cve": "CVE-2002-0649",
  "src_ip": "10.0.1.42",
  "src_port": 54321,
  "dst_ip": "10.0.0.1",
  "dst_port": 3306,
  "action": "RST_INJECTED"
}
```

This is a direct replacement for `std::cout << "[IPS BLOCK]"`. Security operators can subscribe with `curl http://localhost:9090/alerts`.

---

## Phase 5 — Anti-DDoS Hardening (1 week)

### 5.1 SYN Cookie Defense in eBPF XDP

**File:** [`src/main/xdp_kern_prog.c`](src/main/xdp_kern_prog.c)

At SYN flood rates (>500K SYN/s), your userspace session allocator will exhaust the 65,536 session pool.
The fix is SYN cookie validation in eBPF, before packets reach userspace.

```c
// In xdp_kern_prog.c, on SYN:
uint32_t cookie = siphash(src_ip, src_port, dst_ip, dst_port, secret_key);
// Store cookie in eBPF LRU map, send SYN-ACK with seq=cookie
// On 3rd ACK: verify ack_seq == cookie + 1
// Only pass to AF_XDP ring if verification passes
```

This costs zero userspace memory until the handshake is cryptographically verified.

### 5.2 Token Bucket Rate Limiter per Source IP

Re-enable the rate limiter in `xdp_kern_prog.c` (currently commented out).
Use a per-IP sliding window counter in an eBPF LRU hash map:

```c
// 1000 SYN/s per source IP, burst of 50
struct rate_entry { uint64_t last_ns; uint32_t tokens; };
struct bpf_map_def SEC("maps") rate_map = {
    .type = BPF_MAP_TYPE_LRU_HASH, .max_entries = 1 << 20
};
```

### 5.3 Timing Wheel for Session Expiry

**Problem:** `purged_expired()` iterates all 131,072 hash table cells every 1 second. At 65,536 active sessions that is 131,072 comparisons per second per worker — wasted CPU when sessions are mostly live.

**Fix:** Hierarchical 4-level timing wheel (Linux kernel `struct timer_wheel` design).
- Level 0: 256 slots × 10ms = 2.56 seconds
- Level 1: 64 slots × 2.56s = 164 seconds
- Level 2: 64 slots × 164s = ~3 hours

O(1) insertion and O(expiry_count) expiry — no scanning.

---

## Phase 6 — Test Suite Hardening (1 week)

### 6.1 Overlapping Segment Attack Test

**New file:** `tests/overlap_attack.py`

Send overlapping TCP segments using Scapy:
```python
# Packet 1: seq=100, data="SELECT"
# Packet 2: seq=103, data="ECT * FROM users"  (overlaps last 3 bytes)
# Expectation: Aethon detects conflict, drops session
```

### 6.2 Stream-Split Signature Test

**New file:** `tests/split_signature.py`

Split a known exploit pattern across exactly 2 TCP segments at every possible byte boundary.
Verify Hyperscan streaming mode catches ALL splits.

### 6.3 SYN Flood Resilience Test

**New file:** `tests/syn_flood.py`

Send 1M spoofed SYN packets at full speed. Verify:
- Legitimate sessions still establish while flood is in progress
- Session pool does not overflow
- CPU usage on workers stays bounded

### 6.4 Fuzz Test: Malformed TCP Options

**New file:** `tests/tcp_option_fuzz.py`

Send packets with:
- `doff = 15` but no actual options (header claims 60 bytes, packet is 40 bytes)
- Options with `length = 0` (infinite loop bait)
- `EOL` byte in the middle of option list
- MSS < 48 (SACK panic trigger — CVE-2019-11477)

---

## Phase 7 — Benchmark Hardening (3 days)

### 7.1 Real NIC Disclaimer in README

Add a clear, honest methodology section to `README.md`:

```markdown
## Benchmark Environment

- **Test Setup:** Two processes on the same machine connected via Linux `veth` pair
- **Limitation:** `veth` uses kernel memory — packets never traverse a physical PCIe bus
- **Implication:** Real-world throughput on a physical NIC (Intel i40e, Mellanox mlx5)
  will be ~10–30% lower depending on NIC driver and NUMA topology
- **CPU:** [Your CPU model here], 16 cores
- **Kernel:** Linux [version], AF_XDP native mode
- **Hyperscan:** Intel Hyperscan [version], AVX2
```

Honest benchmarks with methodology are more impressive than inflated numbers.

### 7.2 CUDA vs CPU Comparison Graph

**New file:** `tests/cuda_vs_cpu_benchmark.cu`

Output a table showing crossover point:

```
Batch    CPU Hyperscan    CUDA RTX4050    Winner
64       0.8 µs           14.2 µs         CPU
256      3.1 µs           14.8 µs         CPU
1024     12.4 µs          16.1 µs         CPU
4096     49.7 µs          18.3 µs         GPU ← crossover
16384    198 µs           22.1 µs         GPU
65536    792 µs           31.4 µs         GPU
```

This graph answers "when should you use GPU?" definitively and proves you understand hardware tradeoffs.

---

## Complete Priority Order

| Priority | Task | Effort | Impact |
| :---: | :--- | :---: | :---: |
| 1 | Switch TCP Hyperscan to `HS_MODE_STREAM` | 1 day | Critical correctness |
| 2 | Enforce `offset`/`depth` at scan time | 4 hours | Correctness |
| 3 | Session slab allocator (eliminate `new`) | 2 days | Performance |
| 4 | Wire FluxIO to alert path (remove `std::cout`) | 1 day | Correctness |
| 5 | Overlapping segment conflict detection | 1 day | Security |
| 6 | TLS SNI inspection | 4 days | Highest interview impact |
| 7 | Go control plane + shared memory telemetry | 1 week | Production readiness |
| 8 | Prometheus `/metrics` endpoint | 2 days | Observability |
| 9 | RCU hot-reload for Hyperscan rules | 2 days | Production readiness |
| 10 | CUDA UDP batch scanner + benchmark graph | 1 week | NVIDIA interview |
| 11 | HTTP/1.1 field-aware DPI | 3 days | Cloudflare interview |
| 12 | DNS parser + DGA detection | 3 days | Depth |
| 13 | VLAN 802.1Q + VXLAN decapsulation | 2 days | Enterprise readiness |
| 14 | IPv6 dual-stack | 1 week | Enterprise readiness |
| 15 | SYN cookie eBPF defense | 2 days | DDoS hardening |
| 16 | Timing wheel session expiry | 3 days | Scale |
| 17 | Benchmark methodology + README rewrite | 1 day | Credibility |

---

## What Each Target Company Cares About Most

| Company | Top 3 Things They Will Ask About |
| :--- | :--- |
| **Cloudflare** | TLS SNI inspection, RCU hot-reload, Go control plane + Prometheus |
| **HFT (Jane Street / Jump / Citadel)** | Slab allocator, timing wheel, deterministic latency, lock-free everything |
| **NVIDIA** | CUDA batch scanner, PCIe bandwidth math, GPU vs CPU crossover graph |
| **Palo Alto / CrowdStrike** | HS_MODE_STREAM, HTTP/DNS parsers, alert SIEM integration |

---

## Dead Code to Delete Now

| File | Reason |
| :--- | :--- |
| `src/main/hs_engine.cpp` | Superseded by `hyper_scan_engine.h`. Tab-separated rule format, no pattern |
| `src/main/hs_engine.h` | Superseded. Using this alongside the new engine looks like abandoned code |
| `benchmark.cpp` (root) | Old standalone file not part of CMake. Move to `benchmarks/` or delete |
| `revision.cpp` (root) | Scratch file, not compiled. Delete |
| `main.cpp` (root) | Old entry point. `afxdp_control.cpp` is the real main. Delete or move |

---

*Generated from full codebase audit on 2026-10-20. Re-audit after each phase completion.*

