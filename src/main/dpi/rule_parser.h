/*
===================================================================================
                   AETHON IDS: SNORT / SURICATA RULE SYNTAX REFERENCE
===================================================================================

Every Snort/Suricata rule consists of two main parts:
   1. The Rule Header (Protocol, IP, and Port routing filters)
   2. The Rule Options (Patterns, offsets, distances, metadata, and actions)

Example Rule:
alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (msg:"ET SQL MySQL Dump"; content:"SELECT|20|user"; depth:20; nocase; sid:2014910; rev:3;)

-----------------------------------------------------------------------------------
1. THE RULE HEADER
-----------------------------------------------------------------------------------
Syntax:
   <Action> <Protocol> <Src_IP> <Src_Port> <Direction> <Dst_IP> <Dst_Port>

- Action:
    * alert : Generate an alert and record the event when matched.
    * drop  : Silently drop the packet (inline IPS mode).
    * pass  : Whitelist/ignore this packet; stop processing further rules.
    * reject: Drop the packet and send TCP RST (or ICMP unreachable).

- Protocol:
    * tcp   : Inspect TCP flows.
    * udp   : Inspect UDP flows.
    * icmp  : Inspect ICMP ping / error packets.
    * ip    : Inspect any IPv4/IPv6 packet regardless of transport protocol.

- Src_IP / Dst_IP:
    * any           : Matches any IP address.
    * 192.168.1.1   : Specific single IP.
    * 10.0.0.0/24   : CIDR subnet range.
    * !192.168.1.1  : Negation (any IP EXCEPT this one).
    * [10.0.0.1, 192.168.1.5] : IP list.
    * $HOME_NET     : Variable representing protected internal network.
    * $EXTERNAL_NET : Variable representing outside untrusted network.

- Src_Port / Dst_Port:
    * any       : Matches any port number (0 - 65535).
    * 80        : Specific port.
    * 1024:65535: Port range (from port 1024 to 65535 inclusive).
    * :1024     : Ports less than or equal to 1024 (0 to 1024).
    * 1024:     : Ports greater than or equal to 1024.
    * !80       : Any port EXCEPT port 80.

- Direction:
    * -> : Unidirectional (Source -> Destination only).
    * <> : Bidirectional (Traffic in either direction matches).

-----------------------------------------------------------------------------------
2. THE RULE OPTIONS (PAYLOAD PATTERN MATCHING)
-----------------------------------------------------------------------------------

- content:"<pattern>"
    * The exact byte sequence to search for in the reassembled payload.
    * Supports printable ASCII: content:"GET /admin";
    * Supports raw hexadecimal bytes enclosed in pipes (|):
        - |00|         = null byte (0x00)
        - |20|         = space (0x20)
        - |0d 0a|      = CRLF (\r\n)
        - |81 F1 03 01|= binary exploit shellcode bytes
    * Multiple content keywords can exist in the same rule.
    * Negation: content:!"password"; (Alert if pattern is NOT found).

- nocase:
    * Modifies the immediately preceding content keyword.
    * Performs case-insensitive matching (e.g., "SELECT", "select", "SeLeCt").
    * Hyperscan translation: HS_FLAG_CASELESS.

- fast_pattern:
    * Modifies the preceding content keyword.
    * In multi-content rules, tells the engine: "Scan this specific string FIRST
      in the multi-pattern matcher (Hyperscan) because it is the rarest/longest."

- rawbytes:
    * Look at raw packet data without protocol decoding.

-----------------------------------------------------------------------------------
3. ABSOLUTE POSITION MODIFIERS (RelativeTo Payload Start = Byte 0)
-----------------------------------------------------------------------------------

- offset:<N>
    * Instructs the engine to start searching for the content pattern only
      AFTER skipping N bytes from the start of the payload.
    * Example: content:"HTTP"; offset:4;
      -> Skips bytes 0..3, starts looking at byte 4.

- depth:<N>
    * Instructs the engine to only search WITHIN the first N bytes of the payload.
    * Example: content:"|04|"; depth:1;
      -> Must match strictly within byte index 0.

- Combined (offset:M; depth:N;):
    * Restricts the search to a specific window [M, M+N] from payload start.
    * Example: content:"SSH"; offset:0; depth:3;
      -> The first 3 bytes of the payload MUST be "SSH".

-----------------------------------------------------------------------------------
4. RELATIVE POSITION MODIFIERS (RelativeTo Previous Content Match)
-----------------------------------------------------------------------------------
These keywords ONLY apply if there was a previous content keyword before them!

- distance:<N>
    * Instructs the engine to start searching for this second pattern at least
      N bytes AFTER the end of the previous content match.
    * Can be positive (skip ahead) or 0 (immediately adjacent).
    * Example: content:"USER"; content:"root"; distance:1;
      -> "root" must start at least 1 byte after the end of "USER".

- within:<N>
    * Instructs the engine that this second pattern must occur WITHIN N bytes
      after the end of the previous content match.
    * Example: content:"USER"; content:"admin"; within:10;
      -> "admin" must appear within 10 bytes after "USER".

- Combined (distance:D; within:W;):
    * Restricts relative distance to range [D, D+W] after previous content match.
    * Hyperscan translation: regex pattern -> content1.{D,D+W}content2

-----------------------------------------------------------------------------------
5. REGULAR EXPRESSIONS & ADVANCED PATTERNS
-----------------------------------------------------------------------------------

- pcre:"/<regex>/<flags>"
    * Perl-Compatible Regular Expression.
    * Example: pcre:"/[0-9]{3}-[0-9]{2}-[0-9]{4}/"; (Matches SSN)
    * Flags:
        - i : Case-insensitive.
        - s : Dot matches newline (. matches \n).
        - m : Multi-line (^ and $ match line starts/ends).
    * Hyperscan can compile PCRE patterns directly into its DFA engine!

-----------------------------------------------------------------------------------
6. FLOW & STREAM MODIFIERS
-----------------------------------------------------------------------------------

- flow:<options>
    * established : Only match if TCP handshake is complete (state == ESTABLISHED).
    * to_server   : Client to Server direction (request).
    * to_client   : Server to Client direction (response).
    * not_established: Half-open / handshake scan packets.

-----------------------------------------------------------------------------------
7. METADATA & ALERTING
-----------------------------------------------------------------------------------

- msg:"<text>"
    * Human-readable description of the alert displayed to the security operator.
    * Example: msg:"GPL SQL Slammer Worm propagation attempt";

- sid:<integer>
    * Signature ID: A unique integer identifier for the rule.
    * SIDs < 1,000,000      : Official Snort/VRT rules.
    * SIDs 2,000,000 - 3,000,000: Emerging Threats (ET) open rules.
    * SIDs >= 10,000,000    : Custom user-defined rules.
    * Hyperscan uses this SID integer directly as its callback match ID!

- rev:<integer>
    * Revision number of the rule (e.g., rev:1, rev:2).

- classtype:<category>
    * Attack classification (e.g. attempted-admin, web-application-attack,
      trojan-activity, shellcode-detect, misc-attack).

- reference:<type>,<id>
    * External documentation references (e.g. cve,2021-44228; url,attack.mitre.org;).

- metadata:<key value, key value>
    * Key-value metadata tags (created_at, target, confidence, severity).
===================================================================================

        // PCRE (Perl Compatible Regular Expressions):
        // Used for dynamic attack patterns that static content cannot catch
        // (e.g. variable whitespace, regex SQLi, SSN/card numbers, shellcode NOP sleds).
        // Format in rules: pcre:"/<regex>/<flags>" where flags include 'i' (nocase), 's' (dotall), 'm' (multiline).
        // Intel Hyperscan compiles PCRE directly into high-speed DFA automata.


*/

#pragma once
#include "aethon/aethon.h"
#include <cstddef>
#include <hs/hs.h>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>
#include <array>
#include <optional>
#include <algorithm>
#include <charconv>
#include <filesystem>


namespace aethon {
    namespace rules {
        
        enum class RuleProtocol : uint8_t{
            ANY  = 0,
            ICMP = 1,
            TCP  = 6,
            UDP  = 17
        };


        enum class RuleAction : uint8_t {
            ALERT  = 0,
            DROP   = 1,
            PASS   = 2,
            REJECT = 3
        };

        struct PortRange {
        uint16_t low{0};
        uint16_t high{65535};
        bool is_any{true};
            AETHON_ALWAYS_INLINE constexpr bool matches(uint16_t port) const noexcept {
                return is_any || (port >= low && port <= high);
            }
        };   


        struct RuleContent{
            std::string pattern;      // Raw byte pattern (or regex)
            bool nocase{false};       // Case-insensitive (HS_FLAG_CASELESS)
            bool is_negated{false};   // Negated match (content:!"...")
            bool fast_pattern{false}; // Marked as primary search pattern
            // Absolute Position Modifiers (-1 means modifier is NOT set)
            int32_t depth{-1};        // Search within first N bytes
            int32_t offset{-1};       // Start search after N bytes
            // Relative Position Modifiers (Relative to previous content match)
            int32_t distance{-1};     // Must start at least N bytes after prev match
            int32_t within{-1};       // Must finish within N bytes after prev match
        };


        struct AethonRule{
            uint32_t sid{0}; 
            uint32_t rev{1}; // rivision number

            RuleAction action{RuleAction::ALERT};
            RuleProtocol protocol {RuleProtocol::ANY};

            // directional port filder
            PortRange src_port{};
            PortRange dst_port{};

            // flow seeting
            bool flow_established{false};
            bool flow_to_server{false};
            bool flow_to_client{false};

            // pateerns and regex
            std::vector<RuleContent> contents;
            std::string pcre_regex;
            bool has_pcre{false};

            // human alert data
            std::string msg;
            std::string classtype;

            // Security & Forensic Metadata (for logging and SIEM alerts)
            std::string cve;                        // e.g. "CVE-2002-0649"
            std::string confidence;                 // e.g. "High", "Medium", "Low"
            std::string severity;                   // e.g. "Critical", "Major", "Informational"
            std::string reference;                  // Reference URL or Bugtraq ID
        };


        AETHON_ALWAYS_INLINE std::string normalize_content_to_regex(std::string_view raw){
            std::string out;
            out.reserve(raw.size() * 4);

            bool in_hex =  false;
            std::string hex_byte;
            
            auto hex_char_to_val = [](char c) noexcept -> int{
                 if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };

            for (size_t i = 0; i < raw.size(); ++i) {
                char c = raw[i];
                if(c=='|'){
                    in_hex = !in_hex;
                    hex_byte.clear();
                    continue;
                }

                if(in_hex){
                    if(c==' ' || c == '\t') continue;

                    hex_byte.push_back(c);
                    if(hex_byte.size() == 2){
                        int h1 = hex_char_to_val(hex_byte[0]);
                        int h2 = hex_char_to_val(hex_byte[1]);

                        if(h1 >=0 && h2 >=0){
                            uint8_t byte_val = static_cast<uint8_t>((h1 << 4) | h2);
                            // Convert to \xHH for Hyperscan -- > HH means two hex digit \x means the follwing two character are hexadecimal for 1 raw byte
                            char buf[5];
                            snprintf(buf, sizeof(buf), "\\x%02x", byte_val);
                            out.append(buf);
                        }
                        hex_byte.clear();
                    }
                }else{
                    switch (c) {
                        case '\\': case '^': case '$': case '.': case '[': case ']':
                        case '(':  case ')': case '|': case '*': case '+': case '?':
                        case '{':  case '}':
                            out.push_back('\\');
                            out.push_back(c);
                            break;
                        default:
                            out.push_back(c);
                            break;
                        }
                }
            }
            return out;
        }

        AETHON_ALWAYS_INLINE PortRange parse_port_range(std::string_view s) noexcept {
            PortRange pr;
            // trim while space

            while (!s.empty() && (s.front()==' ' || s.front() == '\t')) {
                s.remove_prefix(1);
            }
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);

            if (s.empty() || s == "any" || s == "$HTTP_PORTS" || s == "$SQL_SERVERS") {
                pr.is_any = true;
                return pr;
            }

            pr.is_any = false;

            size_t colon_pos = s.find(':');
            if(colon_pos == std::string_view::npos){
                // single port like 80 3306
                uint16_t port = 0;
                auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), port);
                if (ec == std::errc()) {
                    pr.low = port;
                    pr.high = port;
                } else {
                    pr.is_any = true; // Fallback on parse failure
                }
            }else{
                // port ranges
                std::string_view low_part  = s.substr(0, colon_pos);
                std::string_view high_part = s.substr(colon_pos + 1);

                if(low_part.empty()){
                    pr.low = 0;
                }else{
                    uint16_t val = 0;
                    auto [ptr,ec] = std::from_chars(low_part.data(),low_part.data() + low_part.size(), val);
                     pr.low = (ec == std::errc()) ? val : 0;
                }

                if (high_part.empty()) {
                pr.high = 65535; // "1024:" -> 1024..65535
                } else {
                    uint16_t val = 65535;
                    auto [ptr, ec] = std::from_chars(high_part.data(), high_part.data() + high_part.size(), val);
                    pr.high = (ec == std::errc()) ? val : 65535;
                }
            }

            return pr;


        };


        AETHON_ALWAYS_INLINE std::optional<AethonRule> parse_rule_line(std::string_view line){
            // parse the Header (action, protocol, src_ip, src_port, direction, dst_ip, dst_port)
            while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
            
            // ignore comment empty line
            if (line.empty() || line.front() == '#') {
                return std::nullopt;
            }

            size_t opt_start = line.find('(');
            size_t opt_end   = line.rfind(')');
            if (opt_start == std::string_view::npos || opt_end == std::string_view::npos || opt_start >= opt_end) {
                return std::nullopt; 
            }

            std::string_view header_str = line.substr(0, opt_start);
            std::string_view body_str   = line.substr(opt_start + 1, opt_end - opt_start - 1);

            std::vector<std::string_view> tokens;
            tokens.reserve(8);

            size_t pos = 0;
            while (pos < header_str.size()) {
                while (pos < header_str.size() && (header_str[pos] == ' ' || header_str[pos] == '\t')) ++pos;
                if (pos >= header_str.size()) break;
                size_t token_start = pos;
                while (pos < header_str.size() && header_str[pos] != ' ' && header_str[pos] != '\t') ++pos;
                tokens.push_back(header_str.substr(token_start, pos - token_start));
            }

            if(tokens.size() < 7){
                return std::nullopt;
            }

            AethonRule rule;

            //  Action
            if (tokens[0] == "alert")       rule.action = RuleAction::ALERT;
            else if (tokens[0] == "drop")   rule.action = RuleAction::DROP;
            else if (tokens[0] == "pass")   rule.action = RuleAction::PASS;
            else if (tokens[0] == "reject") rule.action = RuleAction::REJECT;
            else return std::nullopt;
            
            if (tokens[1] == "tcp" || tokens[1] == "http" || tokens[1] == "tls" || tokens[1] == "smtp" || tokens[1] == "ssh" || tokens[1] == "ftp") {
                rule.protocol = RuleProtocol::TCP;
            } else if (tokens[1] == "udp" || tokens[1] == "dns") {
                rule.protocol = RuleProtocol::UDP;
            } else if (tokens[1] == "icmp") {
                rule.protocol = RuleProtocol::ICMP;
            } else if (tokens[1] == "ip") {
                rule.protocol = RuleProtocol::ANY;
            } else {
                return std::nullopt;
            }
            
            // Ports
            rule.src_port = parse_port_range(tokens[3]);
            rule.dst_port = parse_port_range(tokens[6]);

            
            // parsing options

            /*
                Some options have quoted string values: msg:"...", content:"...", pcre:"...".
                Some options have integer values: sid:2014910, depth:20, offset:4, distance:5, within:10.
                Some options have NO values (flags): nocase;, fast_pattern;.
                Modifiers like nocase, depth, distance, within modify the most recent content in rule.contents!
            */

            size_t bpos = 0;
        while (bpos < body_str.size()) {
            // Skip whitespace
            while (bpos < body_str.size() && (body_str[bpos] == ' ' || body_str[bpos] == '\t' || body_str[bpos] == ';')) ++bpos;
            if (bpos >= body_str.size()) break;
            // Find the semicolon terminating this option, respecting quotes "..."
            size_t semi = bpos;
            bool inside_quote = false;
            while (semi < body_str.size()) {
                if (body_str[semi] == '"' && (semi == 0 || body_str[semi - 1] != '\\')) {
                    inside_quote = !inside_quote;
                } else if (body_str[semi] == ';' && !inside_quote) {
                    break;
                }
                ++semi;
            }
            std::string_view opt = body_str.substr(bpos, semi - bpos);
            bpos = semi + 1;
            // Trim option string
            while (!opt.empty() && (opt.front() == ' ' || opt.front() == '\t')) opt.remove_prefix(1);
            while (!opt.empty() && (opt.back() == ' ' || opt.back() == '\t')) opt.remove_suffix(1);
            if (opt.empty()) continue;
            size_t colon = opt.find(':');
            std::string_view key = (colon == std::string_view::npos) ? opt : opt.substr(0, colon);
            std::string_view val = (colon == std::string_view::npos) ? std::string_view{} : opt.substr(colon + 1);
            // Trim key and val
            while (!key.empty() && key.back() == ' ') key.remove_suffix(1);
            while (!val.empty() && val.front() == ' ') val.remove_prefix(1);
            // Helper to strip quotes: "..." -> ...
          
            auto unquote = [](std::string_view v) noexcept -> std::string_view {
                if (v.size() >= 2 && v.front() == '"' && v.back() == '"') {
                    return v.substr(1, v.size() - 2);
                }
                return v;
            };
            // Parse known options
            if (key == "msg") {
                rule.msg = std::string(unquote(val));
            } else if (key == "sid") {
                uint32_t s = 0;
                std::from_chars(val.data(), val.data() + val.size(), s);
                rule.sid = s;
            } else if (key == "rev") {
                uint32_t r = 1;
                std::from_chars(val.data(), val.data() + val.size(), r);
                rule.rev = r;
            } else if (key == "classtype") {
                rule.classtype = std::string(val);
            } else if (key == "content") {
                RuleContent rc;
                if (!val.empty() && val.front() == '!') {
                    rc.is_negated = true;
                    val.remove_prefix(1);
                }
                rc.pattern = normalize_content_to_regex(unquote(val));
                rule.contents.push_back(std::move(rc));
            } else if (key == "nocase") {
                if (!rule.contents.empty()) {
                    rule.contents.back().nocase = true;
                }
            } else if (key == "fast_pattern") {
                if (!rule.contents.empty()) {
                    rule.contents.back().fast_pattern = true;
                }
            } else if (key == "depth") {
                if (!rule.contents.empty()) {
                    int32_t d = -1;
                    std::from_chars(val.data(), val.data() + val.size(), d);
                    rule.contents.back().depth = d;
                }
            } else if (key == "offset") {
                if (!rule.contents.empty()) {
                    int32_t o = -1;
                    std::from_chars(val.data(), val.data() + val.size(), o);
                    rule.contents.back().offset = o;
                }
            } else if (key == "distance") {
                if (!rule.contents.empty()) {
                    int32_t d = -1;
                    std::from_chars(val.data(), val.data() + val.size(), d);
                    rule.contents.back().distance = d;
                }
            } else if (key == "within") {
                if (!rule.contents.empty()) {
                    int32_t w = -1;
                    std::from_chars(val.data(), val.data() + val.size(), w);
                    rule.contents.back().within = w;
                }
            } else if (key == "pcre") {
                std::string_view raw_pcre = unquote(val);
                // Strip enclosing slashes: /regex/flags -> regex
                if (raw_pcre.size() >= 2 && raw_pcre.front() == '/') {
                    size_t last_slash = raw_pcre.rfind('/');
                    if (last_slash != std::string_view::npos && last_slash > 0) {
                        rule.pcre_regex = std::string(raw_pcre.substr(1, last_slash - 1));
                        rule.has_pcre = true;
                    }
                }
            } else if (key == "flow") {
                if (val.find("established") != std::string_view::npos) rule.flow_established = true;
                if (val.find("to_server")   != std::string_view::npos) rule.flow_to_server   = true;
                if (val.find("to_client")   != std::string_view::npos) rule.flow_to_client   = true;
            } else if (key == "reference") {
                size_t comma = val.find(',');
                if (comma != std::string_view::npos) {
                    std::string_view ref_type = val.substr(0, comma);
                    std::string_view ref_val  = val.substr(comma + 1);
                    if (ref_type == "cve") {
                        rule.cve = "CVE-" + std::string(ref_val);
                    }
                    rule.reference = std::string(val);
                }
            } else if (key == "metadata") {
                size_t mpos = 0;
                while (mpos < val.size()) {
                    while (mpos < val.size() && (val[mpos] == ' ' || val[mpos] == ',')) ++mpos;
                    if (mpos >= val.size()) break;

                    size_t item_end = val.find(',', mpos);
                    if (item_end == std::string_view::npos) item_end = val.size();

                    std::string_view item = val.substr(mpos, item_end - mpos);
                    mpos = item_end + 1;

                    size_t sp = item.find(' ');
                    if (sp != std::string_view::npos) {
                        std::string_view mkey = item.substr(0, sp);
                        std::string_view mval = item.substr(sp + 1);

                        if (mkey == "cve" && rule.cve.empty()) {
                            rule.cve = std::string(mval);
                        } else if (mkey == "confidence") {
                            rule.confidence = std::string(mval);
                        } else if (mkey == "signature_severity" || mkey == "severity") {
                            rule.severity = std::string(mval);
                        }
                    }
                }
            }
        }
        // A valid rule must have a valid SID and at least one pattern (content or pcre)
        if (rule.sid == 0 || (rule.contents.empty() && !rule.has_pcre)) {
            return std::nullopt;
        }
        return rule;
    }

    class RuleDatabase {
    private:
        std::vector<AethonRule> rules_;

    public:
        RuleDatabase() = default;

        // db.add_custom_rule("alert tcp any any -> any 80 (msg:\"Custom XSS\"; content:\"<script>\"; sid:10000001;)");
        bool add_custom_rule(std::string_view rule_text) {
            auto opt_rule = parse_rule_line(rule_text);
            if (opt_rule.has_value()) {
                rules_.push_back(std::move(opt_rule.value()));
                return true;
            }
            return false;
        }

        // load all rules
        size_t load_from_directory(const std::string &dirpath){
            size_t total = 0;
            std::error_code ec;
            if (!std::filesystem::exists(dirpath, ec)) return 0;
            for(const auto &entry : std::filesystem::directory_iterator(dirpath,ec)){
                if (entry.is_regular_file() && entry.path().extension() == ".rules") {
                    total += load_from_file(entry.path().string());
                }
            }
            return total;
        }



        // Load an entire .rules file from disk
        size_t load_from_file(const std::string &filepath) {
            FILE *fp = fopen(filepath.c_str(), "r");
            if (!fp) return 0;

            char *line_buf = nullptr;
            size_t len = 0;
            ssize_t read_bytes = 0;
            size_t count = 0;

            while ((read_bytes = getline(&line_buf, &len, fp)) != -1) {
                if (read_bytes <= 1) continue;

                // Strip trailing newline '\r' or '\n'
                while (read_bytes > 0 && (line_buf[read_bytes - 1] == '\n' || line_buf[read_bytes - 1] == '\r')) {
                    line_buf[--read_bytes] = '\0';
                }

                auto opt_rule = parse_rule_line(std::string_view(line_buf, read_bytes));
                if (opt_rule.has_value()) {
                    rules_.push_back(std::move(opt_rule.value()));
                    ++count;
                }
            }

            if (line_buf) {
                free(line_buf);
            }
            fclose(fp);
            return count;
        }

        // Accessors
        AETHON_ALWAYS_INLINE const std::vector<AethonRule> &rules() const noexcept {
            return rules_;
        }

        AETHON_ALWAYS_INLINE size_t size() const noexcept {
            return rules_.size();
        }

        AETHON_ALWAYS_INLINE bool empty() const noexcept {
            return rules_.empty();
        }

        AETHON_ALWAYS_INLINE void clear() noexcept {
            rules_.clear();
        }
    };

} // namespace rules
} // namespace aethon
