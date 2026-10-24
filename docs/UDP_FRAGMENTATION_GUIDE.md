# Complete Guide: UDP Packet Structure, IPv4 Fragmentation, and IDS Reassembly

This document explains:
1. The anatomy of UDP and IPv4 packet headers.
2. How IPv4 packet fragmentation works at the byte level.
3. Why fragmentation breaks Intrusion Detection Systems (IDS) and Hyperscan pattern matching.
4. How to build an in-memory reassembly engine with timeout management.

---

## 1. Anatomy of an Unfragmented UDP Packet

Every packet traversing an Ethernet network has layered headers:

```
+-------------------+--------------------+--------------------+-----------------------+
|  Ethernet Header  |    IPv4 Header     |     UDP Header     |    UDP Application    |
|     (14 bytes)    |  (20 to 60 bytes)  |     (8 bytes)      |        Payload        |
+-------------------+--------------------+--------------------+-----------------------+
```

### The IPv4 Header (RFC 791)
Standard length without options is **20 bytes**:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|          Total Length         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Identification        |Flags|      Fragment Offset    |  <-- FRAGMENTATION FIELDS
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Time to Live |    Protocol   |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Source Address                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

#### Key Fields for Fragmentation:
1. **Identification (`16 bits`)**: A unique integer assigned by the sender to group all fragments of the same original datagram.
2. **Flags (`3 bits`)**:
   - `Bit 0`: Reserved (must be 0).
   - `Bit 1` — **DF (Don't Fragment)**: If 1, routers drop the packet instead of fragmenting it if it exceeds MTU.
   - `Bit 2` — **MF (More Fragments)**:
     - `1` = More fragments follow this packet.
     - `0` = This is the **last** fragment (or the packet is not fragmented).
3. **Fragment Offset (`13 bits`)**:
   - Indicates where this fragment's data belongs in the original unfragmented payload.
   - **Crucial**: The offset is measured in units of **8-byte blocks** (64 bits), not individual bytes.
   - To get the actual byte offset: `byte_offset = fragment_offset * 8`.

### The UDP Header (RFC 768)
The UDP header is fixed at **8 bytes**:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 2. Why and How Does Fragmentation Happen?

### The Maximum Transmission Unit (MTU)
The standard Ethernet MTU is **1500 bytes**.
This means the maximum payload an Ethernet frame can carry (IP header + data) is 1500 bytes.

Suppose an application wants to send a **3000-byte UDP payload**:
- Total UDP datagram = `8 bytes (UDP Header) + 3000 bytes (Payload) = 3008 bytes`.
- With IPv4 header (20 bytes), total IP packet = `3028 bytes`.
- Since `3028 > 1500`, the IP layer must **split (fragment)** it across multiple Ethernet frames.

### Visualizing the Split

Each fragment gets its own Ethernet and IPv4 header, but **only the first fragment has the UDP header**:

```
Original Datagram:
[IP: 20B][UDP: 8B][ ------------------ 3000 Bytes Payload ------------------ ]

Packet 1 (Fragment 0):
[Eth: 14B][IP: 20B (ID=55, MF=1, Offset=0)][UDP: 8B][First 1472B of Payload]
   - Total IP Length: 20 + 8 + 1472 = 1500 bytes
   - IP payload size: 1480 bytes (8B UDP + 1472B data)
   - Offset: 0 * 8 = 0

Packet 2 (Fragment 1):
[Eth: 14B][IP: 20B (ID=55, MF=1, Offset=185)][Next 1480B of Payload]
   - Notice: NO UDP HEADER! Data starts immediately after IPv4 header.
   - Total IP Length: 20 + 1480 = 1500 bytes
   - Offset: 185 * 8 = 1480 bytes into the original payload!

Packet 3 (Fragment 2 - Final):
[Eth: 14B][IP: 20B (ID=55, MF=0, Offset=370)][Final 48B of Payload]
   - Total IP Length: 20 + 48 = 68 bytes
   - Offset: 370 * 8 = 2960 bytes
   - MF = 0 tells us: "This is the final piece!"
```

---

## 3. The Security & IDS Problem (Why Hyperscan Fails Without Reassembly)

Hyperscan searches for signatures using a Deterministic Finite Automaton (DFA).
Suppose you have an attack signature rule:
```
pattern: "ATTACK_SIGNATURE_HEX_CODE"
```

If the attacker crafts a fragmented packet where:
- Fragment 1 ends with: `"...ATTACK_"`
- Fragment 2 begins with: `"SIGNATURE_HEX_CODE..."`

### What happens in an IDS without reassembly:
1. Fragment 1 arrives $\to$ Hyperscan scans Fragment 1 $\to$ **No match**.
2. Fragment 2 arrives $\to$ Hyperscan scans Fragment 2 $\to$ **No match**.
3. Target host receives both, reassembles them, and executes the attack payload!

This is known as **IP Fragmentation Evasion**. To reliably detect attacks, an IDS **must** reconstruct the full byte stream before calling `hs_scan()`.

---

## 4. How to Detect Fragments in C++ / eBPF

To check if a packet is fragmented using the `iphdr` struct:

```cpp
#include <netinet/ip.h>
#include <arpa/inet.h>

bool is_fragmented(const struct iphdr *iph, uint16_t &out_offset, bool &out_mf) {
    uint16_t frag_field = ntohs(iph->frag_off);
    
    // Bit 13: More Fragments (MF) flag (0x2000 in host order)
    out_mf = (frag_field & IP_MF) != 0;
    
    // Bits 0-12: Fragment Offset in 8-byte units (0x1FFF mask)
    out_offset = (frag_field & IP_OFFMASK) * 8; // Converted to bytes

    // If MF is set OR offset is non-zero, the packet is fragmented!
    return out_mf || (out_offset > 0);
}
```

- **Unfragmented packet**: `out_mf == false` AND `out_offset == 0`.
- **First fragment**: `out_mf == true` AND `out_offset == 0`.
- **Middle fragment**: `out_mf == true` AND `out_offset > 0`.
- **Last fragment**: `out_mf == false` AND `out_offset > 0`.

---

## 5. Designing the Userspace Reassembly Engine

### Step A: The Session Key
All fragments belonging to the same packet share:
- `src_ip`
- `dst_ip`
- `ip_id` (from `iph->id`)
- `protocol` (e.g. `IPPROTO_UDP`)

```cpp
struct FragmentKey {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t ip_id;
    uint8_t  protocol;

    bool operator==(const FragmentKey &o) const {
        return src_ip == o.src_ip &&
               dst_ip == o.dst_ip &&
               ip_id == o.ip_id &&
               protocol == o.protocol;
    }
};

// Custom hash function for std::unordered_map
struct FragmentKeyHash {
    std::size_t operator()(const FragmentKey &k) const {
        std::size_t h = 0;
        h ^= std::hash<uint32_t>{}(k.src_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>{}(k.dst_ip) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.ip_id) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t>{}(k.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};
```

### Step B: Tracking Pieces and Reassembling

```cpp
struct FragmentPiece {
    uint16_t offset;            // Byte offset from original IP payload
    std::vector<uint8_t> data;  // Actual chunk data
};

struct ReassemblyEntry {
    std::chrono::steady_clock::time_point created_at;
    uint32_t total_expected_bytes = 0; // Known when MF == 0 arrives
    bool saw_last_fragment = false;
    uint32_t current_received_bytes = 0;
    std::vector<FragmentPiece> pieces;
};
```

### Step C: The Reassembly Algorithm

When a fragment arrives:
1. Lookup or create `ReassemblyEntry` in an `unordered_map<FragmentKey, ReassemblyEntry, FragmentKeyHash>`.
2. Save chunk: `pieces.push_back({offset, data})`.
3. If `MF == 0`:
   - `saw_last_fragment = true`
   - `total_expected_bytes = offset + data.size()`.
4. Update `current_received_bytes += data.size()`.
5. **Check if complete**:
   - If `saw_last_fragment && (current_received_bytes >= total_expected_bytes)`:
     - Sort pieces by `offset`.
     - Allocate a single buffer of `total_expected_bytes`.
     - Copy pieces into the buffer at their respective offsets.
     - **If UDP**: The first 8 bytes of the reassembled payload are the UDP header! Extract UDP ports, skip the 8 bytes, and pass the remaining payload to Hyperscan (`hs_scan`).
     - Remove entry from map.

### Step D: The 10-Second Expiration Guard (DDoS Defense)
To prevent memory exhaustion (an attacker sending 1 fragment and holding memory forever):
```cpp
void purge_expired_sessions() {
    auto now = std::chrono::steady_clock::now();
    for (auto it = map.begin(); it != map.end(); ) {
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.created_at).count();
        if (elapsed > 10) {
            it = map.erase(it); // Drop incomplete fragment
        } else {
            ++it;
        }
    }
}
```

---

## 6. Summary: Fast Path vs. Fragment Path

```
                    [ Packet Arrives via AF_XDP ]
                                 |
                     Is (frag_off & 0x3FFF) == 0?
                                / \
                              YES  NO (Fragmented)
                              /     \
    [ FAST PATH: Zero-Copy ]         [ FRAGMENT REASSEMBLY ]
    - Extract UDP header directly     - Extract FragmentKey (IP ID + IPs)
    - Pass payload to Hyperscan       - Insert piece into ReassemblyEntry
    - Complete in < 1 microsecond!    - All pieces arrived?
                                            / \
                                          YES  NO -> Wait next frag / Timeout
                                          /
                                  Stitch full buffer
                                  Pass to Hyperscan
```
