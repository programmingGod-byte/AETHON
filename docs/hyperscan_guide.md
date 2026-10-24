# Intel Hyperscan & HTTP Rule Processing Reference Guide for Aethon

---

## 1. What is Intel Hyperscan & Why Aethon Uses It

**Intel Hyperscan** is the world's highest-performance regular expression matching engine, developed specifically for Deep Packet Inspection (DPI) and Network Intrusion Prevention Systems (IPS).

### Why Standard Regex Engines (PCRE, `std::regex`) Fail in DPI:
* If you have 5,000 attack rules and test them one-by-one using `std::regex_search()`:
  $$5,000 \text{ rules} \times 1,500 \text{ bytes per packet} = 7,500,000 \text{ operations PER PACKET!}$$
  Your firewall would choke and drop 99% of network traffic.

### How Hyperscan Achieves Line-Rate Speed (10–40 Gbps):
1. **Multi-Pattern Compilation (DFA/NFA Graph):** Hyperscan compiles all 5,000 regexes **together into a single combined state machine**. When a packet arrives, Hyperscan reads each byte **only once**, evaluating all 5,000 rules simultaneously.
2. **Hardware SIMD Acceleration:** Extensively utilizes x86 **AVX2 and AVX-512 vector instructions** to scan 32 to 64 bytes in a single CPU clock cycle.
3. **Stream Mode (`HS_MODE_STREAM`):** Maintains a tiny 32-byte state context per connection to catch attack signatures split across packet boundaries without buffering raw packets in RAM.

---

## 2. Hyperscan Core C/C++ API Essentials

Hyperscan operates in two phases: **Compilation** (offline or at startup) and **Scanning** (inside the hot packet loop).

```text
[ Rules Array ] ──> hs_compile_multi() ──> [ Compiled hs_database_t ]
                                                      │
                                                      ▼
[ Inbound Packet ] ──> hs_scan() / hs_scan_stream() ──> Matches ──> on_match() Callback
```

### 1. Compilation: `hs_compile_multi()`
```c
hs_error_t hs_compile_multi(
    const char *const *expressions,  // Array of null-terminated regex strings
    const unsigned int *flags,       // Array of flag bitmasks (e.g. HS_FLAG_CASELESS)
    const unsigned int *ids,         // Array of unique rule IDs (e.g. 942140)
    unsigned int elements,           // Total number of rules
    unsigned int mode,               // HS_MODE_BLOCK or HS_MODE_STREAM
    const hs_platform_info_t *plat,  // NULL for current host CPU
    hs_database_t **db,              // Output pointer to compiled database
    hs_compile_error_t **compile_err // Error details if compilation fails
);
```

### 2. Scratch Space Allocation: `hs_alloc_scratch()`
Hyperscan requires a temporary working memory buffer called "scratch space". 
* **Thread-Safety Rule:** Scratch space is **NOT thread-safe**. Each worker thread pinned to a CPU core must have its own private `hs_scratch_t*`.
* The compiled database (`hs_database_t*`) is read-only and **CAN be safely shared** across all CPU cores.

```c
hs_scratch_t *scratch = NULL;
hs_alloc_scratch(database, &scratch);
```

### 3. The Match Callback Function
Whenever Hyperscan detects a pattern, it immediately invokes this callback:
```c
static int on_match_callback(
    unsigned int id,                // The Rule ID that matched (e.g., 942140)
    unsigned long long from,        // Start byte offset of match (if SOM enabled)
    unsigned long long to,          // End byte offset of match
    unsigned int flags,
    void *context                   // User-defined pointer (e.g., flow metadata)
) {
    // Return 0 to continue scanning, or non-zero to halt scanning immediately
    return 1; 
}
```

### 4. Scanning: `hs_scan()` vs `hs_scan_stream()`
* **Block Mode (`hs_scan`):** Used when the full data buffer is self-contained (e.g., scanning a complete URL or User-Agent header).
* **Stream Mode (`hs_scan_stream`):** Used when inspecting long-running TCP streams across multiple continuous packets.

---

## 3. Anatomy of an HTTP Request (The 7 Target Variables)

In modern firewalls (like OWASP ModSecurity / Coraza), an HTTP request is split into **7 distinct inspection targets**:

```text
POST /search/products?query=laptop&category=tech HTTP/1.1    <── (1) REQUEST_METHOD
│    └──────────────┘ └─────────────────────────┘ └──────┘   <── (2) REQUEST_URI / PATH
│           │                     │                   │      <── (3) ARGS_GET (Query String)
│           │                     │                   └───────── PROTOCOL (HTTP/1.1)
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0)                    <── (4) REQUEST_HEADERS:User-Agent
Referer: https://google.com                                  <── (4) REQUEST_HEADERS:Referer
Cookie: session_id=98765; role=admin                         <── (5) REQUEST_COOKIES
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

username=admin&action=login                                  <── (6) REQUEST_BODY / ARGS_POST
[ File Payload: webshell.php ]                               <── (7) FILES (Multipart Attachments)
```

### Target Definitions:
1. **`REQUEST_METHOD`:** The HTTP verb (`GET`, `POST`, `PUT`, `DELETE`). Used to block illegal methods.
2. **`REQUEST_URI`:** The path requested (`/search/products`). Primary target for **Path Traversal / LFI** (`/../../etc/passwd`).
3. **`ARGS_GET`:** Parameters encoded in the URL query string (`?id=10&page=2`).
4. **`REQUEST_HEADERS`:** Key-value metadata blocks (`User-Agent`, `Referer`, `Host`). Primary target for **Scanner Detection** (`sqlmap`, `nikto`).
5. **`REQUEST_COOKIES`:** Session identifiers. Target for **Session Fixation and Cookie Injection**.
6. **`ARGS_POST` / `REQUEST_BODY`:** Data sent in POST requests (Form data, JSON payloads). Primary target for **SQLi and XSS**.
7. **`FILES`:** Uploaded attachments and multipart filenames. Target for **Web-shell uploads**.

> [!NOTE]
> **The `ARGS` Shortcut:** In OWASP CRS, `ARGS` represents both `ARGS_GET` and `ARGS_POST` combined. When a rule targets `ARGS`, the engine must scan both URL query parameters and POST body fields.

---

## 4. How to Read & Decipher Attack Rules

### A. Suricata / Snort Rule Format (`rules/*.rules`)
Used for network-layer and transport-layer inspection (Emerging Threats database).

```snort
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS 80 (
    msg:"ET EXPLOIT Possible SQL Injection UNION SELECT";
    flow:established,to_server;
    content:"union"; nocase;
    content:"select"; nocase; distance:0;
    sid:2001234; rev:2;
)
```
* **`alert tcp ... -> ... 80`:** Action, protocol, and endpoints (External internet to web server port 80).
* **`msg:"..."`:** Human-readable log alert.
* **`flow:established,to_server`:** Only inspect packets after the 3-Way Handshake has been completed, traveling inbound toward the server.
* **`content:"union"; nocase;`:** Exact byte sequence to find (case-insensitive).
* **`distance:0;`:** Look for `"select"` anywhere after `"union"`.
* **`sid:2001234`:** Unique international Signature ID.

---

### B. OWASP ModSecurity Rule Format (`owasp-rules/*.conf`)
Used for application-layer HTTP web attacks.

```apache
SecRule ARGS|REQUEST_COOKIES|REQUEST_HEADERS:User-Agent "@rx (?i)\b(?:information_schema|mysql\.db)\b" \
    "id:942140,\
    phase:2,\
    block,\
    msg:'SQL Injection Attack: Common DB Names Detected',\
    severity:'CRITICAL'"
```
* **`SecRule [VARIABLES]`:** Specifies which of the 7 HTTP targets to inspect (`ARGS`, `COOKIES`, `User-Agent`).
* **`@rx [REGEX]`:** The regular expression to evaluate:
  * `(?i)`: Case-insensitive flag.
  * `\b`: Word boundary (matches standalone words, avoiding false positives).
  * `(?:...|...)`: Non-capturing alternation group of sensitive database table names.
* **`id:942140`:** Unique Rule ID.
* **`block`:** Action to take on match (`XDP_DROP` in eBPF, TCP `RST` injection to server).

---

## 5. Offline Pre-Processing: Extracting Rules for Hyperscan

Because parsing multiline Apache `.conf` files directly in C++ is slow and error-prone, modern firewalls use an offline Python script to parse the rules into a flat, optimized schema:

### Flat Schema: `ID | TARGET | FLAGS | REGEX`
```text
942140|ARGS|CASELESS|\b(?:information_schema|mysql\.db)\b
941100|ARGS|CASELESS|<script[^>]*>
920100|HEADERS|CASELESS|\b(sqlmap|nikto|nmap)\b
930100|URI|CASELESS|\.\./\.\./etc/passwd
```

### Python Pre-Processor Script (`extract_rules.py`):
```python
import re
import glob

output_file = "aethon_hyperscan_rules.txt"
rules_found = 0

with open(output_file, "w") as out:
    for conf_file in glob.glob("owasp-rules/*.conf"):
        with open(conf_file, "r") as f:
            content = f.read().replace("\\\n", " ") # Unfold multiline rules

        # Extract SecRule lines with @rx
        matches = re.findall(r'SecRule\s+([A-Za-z0-9_|:]+)\s+"@rx\s+(.*?)"\s+"[^"]*?id:(\d+)', content)
        for target, regex, rule_id in matches:
            # Normalize target category
            target_cat = "ARGS"
            if "URI" in target or "FILENAME" in target:
                target_cat = "URI"
            elif "HEADER" in target:
                target_cat = "HEADERS"
            elif "COOKIE" in target:
                target_cat = "COOKIES"

            # Strip inline (?i) to use Hyperscan native flag
            clean_regex = regex.replace("(?i)", "")
            out.write(f"{rule_id}|{target_cat}|CASELESS|{clean_regex}\n")
            rules_found += 1

print(f"Successfully extracted {rules_found} rules into {output_file}")
```

---

## 6. Complete C++ Implementation Blueprint for Aethon

### Step 1: High-Speed Zero-Copy HTTP Boundary Splitter
In your C++ packet worker (`afxdp_control.cpp`), split the raw TCP payload into pointers without heap allocations:

```cpp
#include <string_view>
#include <cstring>

struct ParsedHttp {
    std::string_view method;
    std::string_view uri;
    std::string_view args_get;
    std::string_view headers;
    std::string_view body;
};

inline bool parse_http_fast(const char* payload, size_t len, ParsedHttp& out) {
    if (len < 10) return false;

    // 1. Find Method (space delimited)
    const char* space1 = (const char*)memchr(payload, ' ', len);
    if (!space1) return false;
    out.method = std::string_view(payload, space1 - payload);

    // 2. Find URI and ARGS_GET
    const char* space2 = (const char*)memchr(space1 + 1, ' ', len - (space1 - payload) - 1);
    if (!space2) return false;
    
    std::string_view full_path(space1 + 1, space2 - (space1 + 1));
    size_t qmark = full_path.find('?');
    if (qmark != std::string_view::npos) {
        out.uri = full_path.substr(0, qmark);
        out.args_get = full_path.substr(qmark + 1);
    } else {
        out.uri = full_path;
        out.args_get = {};
    }

    // 3. Find Header/Body delimiter (\r\n\r\n)
    const char* header_end = strstr(space2, "\r\n\r\n");
    if (header_end) {
        out.headers = std::string_view(space2, header_end - space2);
        out.body = std::string_view(header_end + 4, len - (header_end + 4 - payload));
    } else {
        out.headers = std::string_view(space2, len - (space2 - payload));
        out.body = {};
    }

    return true;
}
```

---

### Step 2: Hyperscan C++ Engine Wrapper
```cpp
#include <hs/hs.h>
#include <vector>
#include <iostream>

class AethonHyperscan {
public:
    AethonHyperscan() : db_(nullptr), scratch_(nullptr) {}

    ~AethonHyperscan() {
        if (scratch_) hs_free_scratch(scratch_);
        if (db_) hs_free_database(db_);
    }

    bool compile(const std::vector<const char*>& patterns, 
                 const std::vector<unsigned int>& flags,
                 const std::vector<unsigned int>& ids) {
        hs_compile_error_t* compile_err = nullptr;
        
        hs_error_t err = hs_compile_multi(
            patterns.data(),
            flags.data(),
            ids.data(),
            patterns.size(),
            HS_MODE_BLOCK,
            nullptr,
            &db_,
            &compile_err
        );

        if (err != HS_SUCCESS) {
            std::cerr << "Hyperscan compilation failed: " << compile_err->message << "\n";
            hs_free_compile_error(compile_err);
            return false;
        }

        // Allocate per-thread scratch space
        hs_alloc_scratch(db_, &scratch_);
        return true;
    }

    bool scan(std::string_view text, unsigned int& matched_rule_id) {
        if (text.empty() || !db_ || !scratch_) return false;

        matched_rule_id = 0;
        hs_error_t err = hs_scan(
            db_,
            text.data(),
            text.size(),
            0,
            scratch_,
            [](unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void* ctx) -> int {
                // Store matched ID in context and abort scan (match found!)
                *(static_cast<unsigned int*>(ctx)) = id;
                return 1; // Non-zero halts scan immediately
            },
            &matched_rule_id
        );

        return (matched_rule_id != 0);
    }

private:
    hs_database_t* db_;
    hs_scratch_t* scratch_;
};
```

---

### Step 3: Integrating into the AF_XDP Loop
```cpp
// Inside afxdp_control.cpp worker loop:
ParsedHttp req;
if (parse_http_fast(payload_ptr, payload_len, req)) {
    unsigned int matched_id = 0;

    // 1. Scan URL Query Parameters
    if (!req.args_get.empty() && sqli_scanner.scan(req.args_get, matched_id)) {
        std::cout << "[SECURITY ALERT] SQL Injection (Rule " << matched_id << ") in URL: " << req.args_get << "\n";
        drop_and_block_flow(flow_key);
        continue;
    }

    // 2. Scan POST Request Body
    if (!req.body.empty() && sqli_scanner.scan(req.body, matched_id)) {
        std::cout << "[SECURITY ALERT] SQL Injection (Rule " << matched_id << ") in Body: " << req.body << "\n";
        drop_and_block_flow(flow_key);
        continue;
    }

    // 3. Scan URL Path for Directory Traversal
    if (lfi_scanner.scan(req.uri, matched_id)) {
        std::cout << "[SECURITY ALERT] Directory Traversal (Rule " << matched_id << ") in Path: " << req.uri << "\n";
        drop_and_block_flow(flow_key);
        continue;
    }
}
```

---

## 7. Crucial Gotchas & Defensive Guidelines

1. **Unsupported Regex Constructs:**
   Hyperscan does **NOT** support arbitrary backreferences (e.g. `\1` to match whatever group 1 matched). If an OWASP regex uses backreferences, Hyperscan will return a compilation error. Filter them out or rewrite them.
2. **Scratch Space Concurrency:**
   Never share a `hs_scratch_t` pointer across multiple C++ threads. Each AF_XDP worker thread must call `hs_alloc_scratch()` once to allocate its own thread-local scratch buffer.
3. **Stream Context Footprint (`HS_MODE_STREAM`):**
   When using streaming mode across continuous TCP packets, allocate `hs_stream_t*` inside your `TcpConnection` struct. The memory overhead is roughly **32 to 64 bytes per connection**. Call `hs_close_stream()` when the connection is torn down (`FIN`/`RST`) to prevent memory leaks.
4. **Zero Heap Allocation in Fast Path:**
   Notice that `ParsedHttp` uses `std::string_view` (raw pointer + length). It does **not allocate any memory on the heap** (`malloc`/`new`), ensuring sub-microsecond inspection speeds.

