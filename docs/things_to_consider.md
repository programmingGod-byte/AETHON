# Aethon Implementation Architecture & Security Considerations

## 1. TCB (Transmission Control Block) Creation
**Rule:** Only create a full TCB block (memory allocation) when the 3-way handshake is fully completed.
* **Why:** Prevents SYN flood memory exhaustion and forged data desynchronization.

```cpp
struct TcpConnection {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t expected_seq;
    std::string http_payload_buffer;
};
```

## 2. Production Conntrack (eBPF State Machine)
* **Canonical Flow Key:** Normalize the 4-tuple (e.g., `min(ip_a, ip_b)`) so both `client->server` and `server->client` hit the exact same map entry.
* **Validate Sequence & ACK Numbers:** Track `client_isn` and `server_isn`. 
* **Distinguish the 3rd ACK:** Only transition state from `SYNACK_SEEN` to `ESTABLISHED` if `ack_seq == server_isn + 1`.
* **Timestamps & Timeouts:** Do not rely on LRU eviction for TCP timeouts. Store `last_seen_ns` using `bpf_ktime_get_ns()` and actively reap dead connections (e.g., idle > 300s).
* **FIN/RST Teardown:** Handle TCP connection closure gracefully to free memory buffers.

## 3. TCP Option Exploits & Protections
* **Finding the Payload:** Never hardcode 20 bytes. The TCP payload always starts at: `payload = (const char*)tcp + (tcp->doff * 4);`
* **Verify Doff Bounds:** Ensure `tcp->doff >= 5` (header >= 20 bytes) and `tcp->doff <= 15` (header <= 60 bytes).
* **Prevent Infinite Loops:** Ensure option parsing loops verify that the option length `len >= 2`.
* **Prevent Buffer Over-reads:** Ensure `opt_ptr + len <= (tcp + tcp->doff * 4)`.
* **SACK Panic (CVE-2019-11477):** If a packet requests a tiny MSS (e.g., `< 48` or `< 64` bytes), drop it instantly to prevent kernel panic / CPU exhaustion.

## 4. Evasion Techniques & Defenses
* **Payload in SYN Packet:** Attackers can put malicious data in a `SYN` packet (TCP Fast Open). If `payload_len > 0` on a SYN packet, you MUST inspect the payload with Hyperscan or drop the packet.
* **Overlapping TCP Fragments (Ptacek & Newsham 1998):** If a packet arrives with the same sequence number as an existing buffer but with *different* data, it's an evasion attack. Drop the connection immediately.
* **Fake RST (Desynchronization):** Attackers send an RST with a bad checksum. If your IDS doesn't check checksums, it clears the connection but the Linux server keeps it open. 
* **Checksum Verification:** You MUST calculate and verify IPv4 and TCP checksums in software (C++ or eBPF). Do not blindly trust the NIC's hardware checksum offload.
* **TTL Evasion (Ghost Packets):** Attackers send malicious packets with a low TTL that die before reaching the backend server. *(Advantage: Because Aethon runs on the host NIC via AF_XDP, it natively defeats this because the hop count is identically zero).*

## 5. Connection Limiting & NAT
* **The NAT Problem:** Basic IP limits (e.g., max 10 connections) will accidentally block legitimate corporate offices or universities behind NAT gateways.
* **The Solution:** Combine a high hard-limit (e.g., 1000-2000 connections per IP) to prevent RAM exhaustion, with an **EWMA (Exponentially Weighted Moving Average)** to detect malicious *spikes* in `SYN` packet rates.

## 6. eBPF / C++ Division of Labor
* **Kernel (eBPF / XDP):** Stateless drops, IP blacklisting, SYN limiting, and 3-way handshake state validation (Conntrack).
* **User-Space (C++ / AF_XDP):** TCP reassembly, Checksum verification, and Heavy Regex inspection (Intel Hyperscan) / GPU Offloading.
## 7. Overcoming the 1998 IDS Evasion Dilemmas (Passive vs. Inline)
* **TCB Poisoning (Fake Handshakes):** Traditional passive sniffers can be tricked by an attacker spoofing the server's `SYN-ACK`. Because Aethon is an **Active Inline Gatekeeper** on the host NIC, an attacker cannot spoof the backend server's response without physically compromising the server itself.
* **PAWS (TCP Timestamps):** Passive IDSs missing the handshake don't know if timestamps were negotiated, risking overlapping fragment attacks. Aethon's eBPF LRU maps strictly drop unverified data packets, preventing this desynchronization.
* **Restart Blindness:** When a passive IDS restarts, it becomes "blind" to mid-stream connections. Because Aethon actively controls the flow, restarting it securely drops the state. This forces legitimate clients to naturally re-send a `SYN` (automatically restoring 100% verified state tracking) instead of leaving the firewall vulnerable to mid-stream TCP injections.

## 8. Out-of-Order Packets vs. PAWS Attacks
* **Out-of-Order Packets (Normal Traffic - DO NOT DROP):** If Packet 2 arrives after Packets 3 and 4 due to network congestion, PAWS does **not** drop it. The sequence numbers have not wrapped around. In C++, store Packets 3 and 4 in a bounded "waiting room" (reassembly buffer) and assemble `1, 2, 3, 4` when the missing Packet 2 arrives.
* **The "Time Travel" Attack (PAWS Freeze - DROP):** Attackers send packets with timestamps set far into the future (e.g., Year 2099) to trick the receiver into freezing and dropping all legitimate packets. In C++/eBPF, drop any packet whose timestamp jumps forward by an unrealistic delta (e.g., > 60 seconds), and never enforce timestamps on connections that didn't negotiate them in the 3-Way Handshake.

## 9. Streaming Inspection vs. The "RAM Death Trap"
* **Never Buffer the Whole Message:** Do NOT wait for an entire HTTP request or multi-megabyte file upload before inspecting. Buffering whole requests creates an easy Out-Of-Memory (OOM) crash attack.
* **Streaming Inspection:** Inspect each continuous, in-order packet chunk immediately upon arrival and forward it to the server.
* **Cross-Packet Matches (Intel Hyperscan):** If an attack string (e.g., `SELECT`) is split across packet boundaries (`SEL` in Packet 1, `ECT` in Packet 2), use Hyperscan's Streaming Mode (`hs_scan_stream`). Hyperscan maintains a tiny ~32-byte stream context per connection to catch split patterns across packets without needing to keep past packets buffered in RAM.

## 10. Idle Connection Reaper (Garbage Collection & Slowloris Defense)
* **The Necessity:** Half-open connections (e.g., cell phones dying, lost connectivity) never send `FIN` or `RST` packets, and Slowloris attackers intentionally send 1 byte every 15 seconds to exhaust sockets.
* **The Reaper Mechanism:** Run a lightweight C++ background thread waking up every 1–2 seconds. Check `now - conn.last_seen_timestamp`. If timed out:
  1. Forge and inject a `TCP RST` to the backend server via AF_XDP TX Ring to free server kernel RAM immediately.
  2. Remove the flow from the C++ connection map and the eBPF tracking map.
* **Stage-Based Timeouts:**
  * **Handshake Phase (`SYN_SEEN`):** 5–10 seconds max (drops abandoned SYN floods).
  * **Established Phase (`ESTABLISHED`):** 30–60 seconds of complete silence.
  * **Closed Phase (`FIN_WAIT` / `TIME_WAIT`):** 5 seconds to clear remaining buffers.

## 11. Inside/Outside Filtering & Anti-Spoofing (Directional Trust)
* **Never Trust by Flag Alone:** Do NOT assume a `SYN-ACK` packet is a legitimate server response just because it has the flag. External attackers can forge `SYN-ACK` packets to trick naive firewalls into opening/desynchronizing state or attack internal clients.
* **Trust Based on Source IP & Physical Direction:** Trust state transitions only based on the packet's verified source address and whether it came from behind a real anti-spoofing boundary.
* **Ingress Anti-Spoofing (eBPF XDP):** If a packet arrives on the public-facing interface (`eth0`) with a source IP claiming to be `127.0.0.1`, the server's own IP, or private RFC1918 subnets (`10.0.0.0/8`, `192.168.0.0/16`), `XDP_DROP` it immediately. It is 100% spoofed.
* **Directional Conntrack:** Only promote a flow to `SYNACK_SEEN` if the `SYN-ACK` packet is verified leaving the local machine on **Egress** (via the eBPF TC hook), never when arriving from the untrusted external wire.

## 12. Full vs. Partial Handshake (The Two-Tier Solution)

### The Dilemma
* **Requiring Full 3WH (`SYN -> SYN-ACK -> ACK`):** In 1998, sniffers used `libpcap` which dropped 10–20% of packets under high load. If an IDS required seeing all 3 packets before tracking, missing *a single packet* caused the IDS to go completely blind to the entire subsequent connection!
* **Allowing Partial Handshake (`SYN` or `SYN-ACK` only):** If the IDS opens full tracking memory early, an attacker can launch a **SYN Flood** or **Phantom Connection Attack**, forcing the firewall to allocate megabytes of memory for connections that will never exist.

### The Aethon Two-Tier Architecture
Because Aethon uses **eBPF in the kernel** and **AF_XDP in user-space**, we resolve this dilemma by decoupling handshake tracking from memory allocation:

```text
[ CLIENT ]                      [ AETHON eBPF ]                   [ AETHON C++ ]
    │                                  │                                 │
    ├── 1. Inbound SYN ───────────────>│                                 │
    │                                  │ Updates eBPF map:               │
    │                                  │ state = SYN_SEEN                │
    │                                  │ (Cost: 16 bytes kernel RAM,     │
    │                                  │  0 bytes C++ user-space RAM!)   │
    │                                  │                                 │
    │<── 2. Outbound SYN-ACK (from TC) │                                 │
    │                                  │ Updates eBPF map:               │
    │                                  │ state = SYNACK_SEEN             │
    │                                  │                                 │
    ├── 3. Inbound 3rd ACK ───────────>│                                 │
    │                                  │ Validates:                      │
    │                                  │ ack_seq == server_isn + 1       │
    │                                  │ state = ESTABLISHED             │
    │                                  │                                 │
    │                                  ├────── Pass to AF_XDP Ring ─────>│
    │                                  │                                 │ Allocates full
    │                                  │                                 │ TcpConnection struct
    │                                  │                                 │ & Hyperscan stream!
```

* **Tier 1 (eBPF Kernel Map):** Records lightweight 16-byte state flags (`SYN_SEEN` $\rightarrow$ `SYNACK_SEEN`). Zero C++ user-space memory is allocated. If the attacker abandons the handshake, the eBPF LRU map expires the entry harmlessly.
* **Tier 2 (C++ User-space Allocation):** Heavy memory allocation (HTTP reassembly buffers, Hyperscan stream contexts) **only occurs when the verified 3rd ACK arrives**.

---

## 13. "Synching on Data" Traps & The Poison SYN Attack

### What is "Synching on Data" (Mid-Stream Pickup)?
To recover from dropped handshakes, primitive IDSs attempted to "guess" connection state from arbitrary data packets (`ACK` + payload) without seeing the handshake. The paper proves this is fatally flawed.

### Attack 1: The Pre-Pollution Attack
1. **Attacker sends fake data packet:** An attacker sends a forged packet with a random sequence number: `Seq = 999999`, Payload = `"JUNK"`.
2. **Naive IDS falls for it:** The IDS opens a TCB and sets its expected sequence number to `999999 + 4 = 1000003`.
3. **Attacker sends the real attack:** The attacker sends the actual exploit: `Seq = 100`, Payload = `"GET /shell.php HTTP/1.1"`.
4. **The Blindness:** The naive IDS looks at `Seq = 100`, compares it to `1000003`, assumes it is ancient out-of-order garbage, and **ignores it without inspecting!**
5. **Server gets hacked:** The backend server (which never processed the fake packet) receives `Seq = 100` and executes the attack.

### Attack 2: The Poison SYN Attack (Mid-Stream Reset)
Some IDSs tried to fix Attack 1 by saying: *"If I see a new SYN packet on an active connection, I will reset my sequence tracker to match it."*
1. A legitimate user is actively transferring data on an established connection (`Seq = 50000`).
2. An attacker injects a spoofed `SYN` packet with `Seq = 1`.
3. The naive IDS sees the `SYN`, resets its brain, and now expects all packets to start from `Seq = 1`.
4. The real user continues sending valid packets with `Seq = 50001, 50002...`
5. The IDS drops or ignores all legitimate packets because their sequence numbers do not match `Seq = 1`. The IDS is permanently desynchronized!

### The Aethon Invariants:
1. **NEVER Synch on Data:** If an incoming packet carries payload (`payload_len > 0`), but the eBPF map does not show `state == STATE_ESTABLISHED`, execute `XDP_DROP` immediately.
2. **Reject Mid-Stream SYNs:** If a connection is in `STATE_ESTABLISHED` and a packet arrives with `tcp->syn == 1`, execute `XDP_DROP` immediately as an anomaly (RFC 5961 violation).

---

## 14. TCP Stream Reassembly & The "Eavesdropper's Curse"

### The 1998 Sniffer's Dilemma
The paper describes passive sniffers as cursed eavesdroppers:
* When a Client and Server talk, they actively cooperate. If a packet drops on the wire, the Server doesn't send an ACK, and the Client automatically retransmits it.
* A **passive sniffer** sits on the side. If the sniffer experiences a CPU spike and drops a packet from its internal capture buffer:
  * It **cannot** request a retransmission from the client.
  * It has no way of knowing if the missing packet was just delayed or dropped forever.
  * It permanently loses sequence tracking, turning the rest of the conversation into meaningless gibberish.

### Why Aethon's Inline AF_XDP Architecture Solves This
Aethon is **NOT a passive eavesdropper**; Aethon is an **Active Inline Gatekeeper**:

```text
[ Remote Client ] ════════> [ Aethon / AF_XDP Engine ] ════════> [ Linux Server ]
                                      │
                         (If Aethon drops a packet)
                                      │
                                      ▼
                      Server NEVER receives the packet!
                                      │
                                      ▼
                      Server NEVER sends an ACK!
                                      │
                                      ▼
             Client TCP stack automatically retransmits the
             missing packet straight back into Aethon's socket!
```

Because Aethon sits directly on the wire before the kernel, **any packet Aethon drops is also dropped for the server**. Standard TCP retransmission guarantees that the client will naturally re-send the missing packet directly into Aethon's AF_XDP RX ring for free!

---

## 15. GPU (NVIDIA CUDA / Kargus) vs. CPU (Intel Hyperscan) Inspection

### The Hardware Reality: The PCIe Latency Penalty
* **CPU (Intel Hyperscan):** The CPU inspects packets in **nanoseconds** because packets sit directly in local L1/L2/L3 cache memory.
* **GPU (NVIDIA CUDA):** A GPU has thousands of cores, but it sits across the **PCIe bus**. Transferring a single 1,500-byte packet across PCIe takes **5 to 10 microseconds** of latency. If you send packets one-by-one to a GPU, it is 100x *slower* than a CPU!

### The Kargus Flow-Parallel Batching Architecture
To make GPUs viable for DPI, the **Kargus (ACM CCS '12)** architecture uses batched parallel execution:

```text
[ User-space C++ Engine ]
Collects a batch of 1,024 packets across 200 different flows
                     │
                     ▼ (Single High-Speed PCIe DMA Transfer)
[ NVIDIA GPU VRAM ]
┌────────────────────────────────────────────────────────┐
│ Global State Array: uint32_t gpu_flow_state[MAX_FLOWS] │
├────────────────────────────────────────────────────────┤
│ GPU Thread 1 ──> Scans Flow A (Loads State_A)          │
│ GPU Thread 2 ──> Scans Flow B (Loads State_B)          │
│ GPU Thread 3 ──> Scans Flow C (Loads State_C)          │
│ ...                                                    │
│ Each thread transitions: state = DFA[state][byte]      │
│ Writes updated state back to VRAM                      │
└────────────────────────────────────────────────────────┘
                     │
                     ▼ (Single Alert Bitmask copied back to CPU)
[ C++ Engine drops flagged flows via AF_XDP ]
```

### Architectural Decision for Aethon:
* **Current Engine (Phase 1):** Use **Intel Hyperscan on CPU**. It provides sub-microsecond latency, uses streaming mode (`hs_scan_stream`), and runs on any commodity server without needing an expensive NVIDIA card.
* **Enterprise Scaling (Phase 2):** Introduce GPU batching (Kargus model) only when scaling to **40–100 Gbps line rates** where you must scan **50,000+ complex Snort/Suricata rules** simultaneously across thousands of cores.

---

## 16. Stream Rewriting ("The Eraser Attack") & Pathological Testing

### The Mechanics of the "Eraser" Attack
An attacker exploits differences in how operating systems reassemble overlapping TCP segments to rewrite data on the server:

```text
Step 1: Attacker sends Packet 1 (Seq 1-4): "USER"
Step 2: Attacker sends Packet 2 (Seq 5-10): " ADMIN"
        Firewall reads: "USER ADMIN" (Looks safe! Passed through.)

Step 3: Attacker sends overlapping Packet 3 (Seq 1-4): "KILL"
        (Targets the exact same sequence numbers as Packet 1!)

                    ┌────────────────────────────────────────┐
                    ▼                                        ▼
           [ Linux Server ]                         [ Windows NT Server ]
        Favors NEW Data:                         Favors OLD Data:
        Overwrites "USER" with "KILL"            Ignores "KILL", keeps "USER"
        Result: "KILL ADMIN" (ATTACK!)           Result: "USER ADMIN" (SAFE)
```

If a passive firewall favors old data while protecting a Linux server, the firewall sees `"USER ADMIN"` while the server executes `"KILL ADMIN"`.

### The Operating System Overlap Reference
* **Favors NEW Data (Overwrites):** Linux, FreeBSD, Solaris, AIX, Irix, HP-UX.
* **Favors OLD Data (Preserves):** Windows NT, older Windows stacks.

### The "Happy Path" Trap & Fuzz Testing
* **The Trap:** Normal everyday traffic (browsing, curl, downloading files) always arrives politely in order. Testing with normal traffic creates a false sense of security that reassembly works.
* **The Hacker's Reality:** Attackers use tools like Python's `Scapy` to create pathological packets: 1-byte out-of-order chunks, overlapping sequences with conflicting text, and corrupted options.
* **Aethon Invariant (Drop on Conflicting Overlap):**
  ```cpp
  // In C++ TCP Reassembly:
  if (segment_overlaps_existing(seg)) {
      if (memcmp(buffered_data, seg.data, overlap_len) != 0) {
          // Mismatch detected! This is a stream-rewriting attempt!
          drop_connection_and_ban_ip(flow_key);
          return;
      }
      // If bytes match identically, it's a standard WiFi retransmission. Allow.
  }
  ```

---

## 17. TCB Teardown Policies (Premature Teardown vs. Ghost TCB)

### The Two Sided Dilemma

```text
       [ TEAR DOWN TOO FAST ]                               [ TEAR DOWN TOO SLOW ]
       Premature Teardown Attack                            Ghost TCB / Port Reuse Blindness
                  │                                                        │
Attacker sends "cat /etc/",                               Connection closes, but firewall
injects fake RST with bad checksum.                       holds state in RAM for minutes.
Firewall purges memory prematurely.                       Client reuses same 4-tuple with
Server ignores bad RST and keeps socket open.             new Initial Sequence Numbers.
Attacker sends "passwd".                                  Firewall drops new valid packets
Server executes "cat /etc/passwd" uninspected!            thinking they are out-of-window duplicates!
```

### Aethon's Production Teardown Rules:

1. **Strict `RST` Validation:**
   Never delete connection state on an `RST` packet unless it satisfies **both** conditions:
   * **Valid Checksum:** TCP checksum is mathematically verified.
   * **In-Window Sequence:** `rst_packet.seq == conn.expected_seq` (must match the current receive window exactly, rejecting blind reset spoofing).
2. **Graceful `FIN` Teardown:**
   * When a `FIN` packet arrives, move state to `STATE_FIN_WAIT`.
   * Wait for the corresponding `ACK` from the peer.
   * Once both sides send `FIN/ACK`, start a **5-second lingering timer** before wiping the C++ struct, ensuring lingering retransmissions don't get misidentified as new connections.
3. **Port Reuse Override (`SYN` on Closing Sockets):**
   * If an incoming packet has a pure **`SYN` flag** matching an entry currently in `TIME_WAIT` or `FIN_WAIT`:
   * **Immediately purge the old TCB and cleanly initialize the new connection!**
   * This guarantees that when modern operating systems rapidly reuse ephemeral ports, Aethon never blinds itself to the new conversation.


---

## 18. The 4 Teardown Mechanisms & The Active "Whacking" Race

Ptacek & Newsham detail 4 specific options for terminating a connection TCB. Each has subtle traps that must be accounted for in Aethon:

### 1. Tearing Down on `FIN` (The "Half-Closed" Trap)
* **The 4-Way FIN Handshake:**
  1. Client sends `FIN` (*"I have no more data to send"*).
  2. Server responds with `ACK` (*"Acknowledged"*).
  3. Server sends its own `FIN` (*"I have no more data to send either"*).
  4. Client responds with `ACK` (*"Goodbye"*).
* **The Fatal Trap (The Half-Closed State):**
  * A naive firewall deletes the TCB when it sees the first `FIN` from the client.
  * In standard TCP, after sending a `FIN`, the client enters `FIN_WAIT_1` / `FIN_WAIT_2`, and the server enters `CLOSE_WAIT`. **The server can still send megabytes of data back to the client!** (e.g., in HTTP, a client sends `GET /data.zip` and immediately sends `FIN`; the server then streams the entire 50MB file).
  * If the firewall terminates the TCB on the client's `FIN`, it becomes **completely blind** to all outbound server data (which could contain leaked passwords, exfiltrated files, or reverse shell output).
* **Aethon Rule:** Maintain directional state. When a client sends `FIN`, mark client-to-server as closed, but **keep server-to-client inspection active** until the server sends its own `FIN` and the final `ACK` is exchanged.

### 2. Tearing Down on `RST` (Blind Reset Injection & RFC 5961)
* **The Danger:** An `RST` packet immediately aborts a connection without a handshake. If a firewall destroys its TCB whenever it sees an `RST`, an outside attacker can spray fake `RST` packets into the network to blind the firewall while the server ignores the malformed packet.
* **Aethon Rule (RFC 5961):**
  * An incoming `RST` is only accepted if its sequence number is **an exact match** with the expected sequence number (`rst.seq == expected_seq`).
  * If `rst.seq` is merely "inside the window" but not an exact match, the Linux kernel ignores it or sends a Challenge ACK; Aethon must do the same.

### 3. Synthetic Timeouts (The Dormant Connection Dilemma)
* **The Protocol Flaw:** TCP has no implicit timeout mechanism. An established connection (like an idle SSH shell or persistent database pool) can sit completely dormant for weeks without sending a single packet.
* **The Dilemma:** Waiting forever allows an attacker to exhaust server memory with 100,000 dormant connections. Setting an aggressive 5-minute timeout kills legitimate idle connections.
* **Aethon Rule (Application-Aware Dynamic Timeouts):**
  * **Incomplete Handshake (`SYN_SEEN`):** 10 seconds max.
  * **HTTP / Web Traffic (`ESTABLISHED`):** 60 seconds of complete silence (web requests should never be idle).
  * **Long-Lived Protocol Connections (e.g., SSH/DB):** 15–30 minutes, or require TCP Keep-Alives.

### 4. Active Teardown ("Whacking" & The Microsecond Race Condition)
* **What is "Whacking"?** When the IDS detects a malicious payload (e.g., SQL Injection), the IDS actively terminates the connection by forging and injecting a `TCP RST` packet to the server and client.
* **The 1998 Passive Sniffer Flaw (The Race Condition):**
  ```text
  [ Attacker ] ─── Exploit Packet ─────────> [ Server ]  <── Compromised!
                          │                        ▲
               (Sniffer detects exploit)           │
                          │                        │ (RST arrives too late!)
                          └───── Forged RST ───────┘
  ```
  In a passive setup, the sniffer must race against the exploit packet. Because the exploit packet is already traveling on the wire toward the server, the sniffer's forged `RST` almost always **loses the race**. The server executes the exploit before the `RST` arrives.
* **Why Aethon's Inline AF_XDP Wins 100% of the Time:**
  ```text
  [ Attacker ] ─── Exploit Packet ───> [ AETHON / AF_XDP ] ─── (BLOCKED!)
                                               │
                                       Executes XDP_DROP
                                 (Packet NEVER reaches server!)
                                               │
                                  Injects TCP RST via TX Ring
                                               │
                                               ▼
                                        [ Linux Server ]
                                  (Socket cleanly freed!)
  ```
  Because Aethon sits directly in the driver before the server kernel, Aethon **drops the exploit packet instantly**. The exploit never reaches the application layer. Aethon then injects an `RST` via the AF_XDP TX Ring to cleanly free the server's socket memory. There is zero race condition!
