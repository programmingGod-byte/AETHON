// Regression tests for TCP reassembly and the SNI domain policy (no root, no network needed).
// Feeds hand-built segments straight into TcpAssemblerEngine.
//
//   cmake --build build --target test_tcp_reassembly && ./build/src/test_tcp_reassembly
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "tcp_assembler.h"
#include "domain_blocklist.h"
#include "ip_address.h"

#include <cstdio>
#include <vector>

using namespace aethon::IPv4TcpAssembler;

static int g_failures = 0;
#define CHECK(cond, msg)                                                   \
    do {                                                                   \
        if (cond) { std::printf("  PASS %s\n", msg); }                     \
        else { std::printf("  FAIL %s\n", msg); ++g_failures; }            \
    } while (0)

struct Packet {
    iphdr ip{};
    tcphdr tcp{};
};

// One client connection to 192.168.50.1:80 driven segment by segment
class Conn {
public:
    explicit Conn(uint16_t sport) : sport_(sport) {
        Packet syn = make(isn_, TH_SYN);
        engine_.process_packet(&syn.ip, &syn.tcp, nullptr, 0, tick());
        Packet ack = make(isn_ + 1, TH_ACK);
        engine_.process_packet(&ack.ip, &ack.tcp, nullptr, 0, tick());
    }

    // Send stream bytes [off, off+len) taken from data
    TcpAssemblyResult send(const std::vector<uint8_t> &data, uint32_t off, size_t len) {
        Packet p = make(isn_ + 1 + off, TH_ACK);
        return engine_.process_packet(&p.ip, &p.tcp, data.data() + off, len, tick());
    }

private:
    Packet make(uint32_t seq, uint8_t flags) const {
        Packet p;
        p.ip.ihl = 5;
        p.ip.protocol = IPPROTO_TCP;
        p.ip.saddr = inet_addr("192.168.50.2");
        p.ip.daddr = inet_addr("192.168.50.1");
        p.tcp.source = htons(sport_);
        p.tcp.dest = htons(80);
        p.tcp.seq = htonl(seq);
        p.tcp.ack_seq = htonl(1000001);
        p.tcp.doff = 5;
        p.tcp.window = htons(65535);
        reinterpret_cast<uint8_t *>(&p.tcp)[13] = flags;
        return p;
    }
    uint64_t tick() { return now_ += 1000; }

    TcpAssemblerEngine engine_;
    uint16_t sport_;
    uint32_t isn_{5000};
    uint64_t now_{1'000'000'000ULL};
};

// Pseudo-random bytes (non-periodic, so data 64 KB apart differs like a real stream)
static std::vector<uint8_t> pattern(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    uint64_t x = 0x9E3779B97F4A7C15ULL ^ seed;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        v[i] = static_cast<uint8_t>(x);
    }
    return v;
}

// Linux retransmits a lost short segment merged with following bytes (same data, new
// boundaries). Part of the range is already buffered, part is not; the unbuffered part
// holds stale ring data from 64 KB earlier. This must NOT be treated as an attack.
static void test_resegmented_retransmission() {
    std::puts("resegmented retransmission after ring wrap-around");
    auto data = pattern(200000, 3);
    Conn c(40000);

    uint32_t off = 0;
    bool alive = true;
    while (off < 70000 && alive) {          // > 64 KB in order so the ring has wrapped
        alive = c.send(data, off, 536).session != nullptr;
        off += 536;
    }
    CHECK(alive, "70 KB in-order stream accepted");

    auto ooo = c.send(data, off + 144, 536);  // short segment [off, off+144) lost
    CHECK(ooo.session != nullptr, "out-of-order segment buffered");
    CHECK(ooo.need_ack, "out-of-order segment triggers a duplicate ACK");

    auto re = c.send(data, off, 536);         // collapsed retransmission [off, off+536)
    CHECK(re.session != nullptr, "collapsed retransmission keeps the session alive");
    CHECK(re.is_ready && re.payload_len == 144 + 536,
          "missing bytes plus buffered segment delivered in order");
}

// A real overlap evasion: the same stream bytes sent twice with different content.
static void test_conflicting_overlap_detected() {
    std::puts("conflicting overlap (evasion attempt)");
    auto a = pattern(4096, 'A');
    auto b = pattern(4096, 'B');
    Conn c(40001);

    c.send(a, 0, 536);
    c.send(a, 1000, 536);                     // hole at [536, 1000), buffered [1000, 1536)
    auto r = c.send(b, 700, 536);             // overlaps buffered bytes with different data
    CHECK(r.session == nullptr && r.is_closed, "conflicting overlap kills the session");
}

// Identical retransmission of an already buffered segment is harmless.
static void test_identical_duplicate_accepted() {
    std::puts("identical duplicate of a buffered segment");
    auto a = pattern(4096, 'C');
    Conn c(40002);

    c.send(a, 0, 536);
    c.send(a, 1000, 536);
    auto r = c.send(a, 1000, 536);
    CHECK(r.session != nullptr, "identical duplicate keeps the session alive");
}

// Two holes; the first filler only closes the first hole. Buffered data behind the second
// hole must still be tracked: it must be delivered once the second hole is filled, and its
// bitmap bits must not linger and cause a false "overlap attack" after the ring wraps.
static void test_partial_fill_keeps_tracking() {
    std::puts("partial hole fill with more out-of-order data behind it");
    auto data = pattern(300000, 11);
    Conn c(40003);

    c.send(data, 0, 536);                     // in order: rcv_nxt = 536
    c.send(data, 1608, 536);                  // buffered, holes at [536,1072) and [1072,1608)
    auto f1 = c.send(data, 536, 536);         // fills only the first hole
    CHECK(f1.is_ready && f1.payload_len == 536, "first filler delivers only up to the second hole");

    auto f2 = c.send(data, 1072, 536);        // fills the second hole
    CHECK(f2.is_ready && f2.payload_len == 1072, "second filler also delivers the buffered segment");

    // Like a real client: whatever the ACK didn't cover is retransmitted, then the stream goes on
    uint32_t off = f2.is_ready ? 1072 + f2.payload_len : 1072;
    bool alive = true;
    while (off < 1608 + 65536 - 536 && alive) {   // in order until just before one ring length later
        alive = c.send(data, off, 536).session != nullptr;
        off += 536;
    }
    // Reordering exactly over the ring positions of [1608, 2144): B arrives before A
    alive = alive && c.send(data, off + 536, 536).session != nullptr;     // B (out of order)
    alive = alive && c.send(data, off, 536).session != nullptr;           // A (fills the hole)
    CHECK(alive, "stream survives ring wrap-around after partial fills (no stale bitmap bits)");
}

// A sender retransmits data we already have when our ACK was lost. It must be ACKed again,
// and a retransmission that also carries new bytes must deliver them (it was once dropped
// silently because an unsigned window check treated "behind" as "4 GB ahead").
static void test_old_data_is_reacked() {
    std::puts("retransmission of already received data");
    auto data = pattern(8192, 77);
    Conn c(40004);

    c.send(data, 0, 536);
    c.send(data, 536, 536);                               // rcv_nxt = 1072
    auto dup = c.send(data, 0, 536);                      // fully old
    CHECK(dup.session && dup.need_ack && !dup.is_ready, "fully old segment is re-ACKed");

    auto part = c.send(data, 536, 1072);                  // [536, 1608): half old, half new
    CHECK(part.is_ready && part.payload_len == 536, "partly old segment delivers only its new bytes");
    CHECK(part.is_ready && std::memcmp(part.payload, data.data() + 1072, 536) == 0,
          "delivered bytes are the new ones");
}

// Reference RFC 1071 checksum, computed the textbook way (big-endian 16-bit words)
static uint16_t reference_tcp_checksum(uint32_t saddr_be, uint32_t daddr_be, const uint8_t *seg, size_t len) {
    uint32_t sum = 0;
    auto add16 = [&](uint16_t w) { sum += w; };
    const uint32_t s = ntohl(saddr_be), d = ntohl(daddr_be);
    add16(s >> 16); add16(s & 0xFFFF); add16(d >> 16); add16(d & 0xFFFF);
    add16(IPPROTO_TCP); add16(static_cast<uint16_t>(len));
    for (size_t i = 0; i + 1 < len; i += 2) add16(static_cast<uint16_t>(seg[i] << 8 | seg[i + 1]));
    if (len & 1) add16(static_cast<uint16_t>(seg[len - 1] << 8));
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static void test_tcp_checksum() {
    std::puts("TCP checksum verification");
    iphdr ip{};
    ip.saddr = inet_addr("192.168.50.2");
    ip.daddr = inet_addr("192.168.50.1");
    bool all_valid = true, all_detected = true;
    auto data = pattern(1500, 42);
    for (size_t len : {20u, 21u, 33u, 1023u, 1480u}) {          // even, odd, unaligned tails
        std::vector<uint8_t> seg(data.begin(), data.begin() + static_cast<long>(len));
        seg[16] = seg[17] = 0;                                    // checksum field
        uint16_t c = htons(reference_tcp_checksum(ip.saddr, ip.daddr, seg.data(), len));
        std::memcpy(&seg[16], &c, 2);
        all_valid &= aethon::Ipv4::is_valid_tcp_checksum(&ip, seg.data(), len);
        for (size_t bit : {size_t{5}, size_t{13 * 8 + 2}, (len - 1) * 8 + 7}) {  // seq, flags byte, last byte
            auto bad = seg;
            bad[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
            all_detected &= !aethon::Ipv4::is_valid_tcp_checksum(&ip, bad.data(), len);
        }
    }
    CHECK(all_valid, "valid segments accepted (even, odd and unaligned lengths)");
    CHECK(all_detected, "single bit flips in header and payload are rejected");
}

// Under a SYN flood the table must not fill: above the threshold SYNs get a stateless cookie,
// and only a client that echoes a valid cookie gets a session.
static void test_syn_cookies() {
    std::puts("SYN cookies under table pressure");
    TcpAssemblerEngine engine;
    uint64_t now = 5'000'000'000ULL;
    auto make_pkt = [](uint32_t src, uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags) {
        Packet p;
        p.ip.ihl = 5;
        p.ip.saddr = src;
        p.ip.daddr = inet_addr("192.168.50.1");
        p.tcp.source = htons(sport);
        p.tcp.dest = htons(443);
        p.tcp.seq = htonl(seq);
        p.tcp.ack_seq = htonl(ack);
        p.tcp.doff = 5;
        reinterpret_cast<uint8_t *>(&p.tcp)[13] = flags;
        return p;
    };

    // Spoofed flood until the cookie threshold
    uint32_t n = 0;
    while (engine.session_count() < AETHON_SYNCOOKIE_THRESHOLD) {
        Packet syn = make_pkt(htonl(0x0A000000u + n), static_cast<uint16_t>(1024 + n % 60000), n * 7919u, 0, TH_SYN);
        engine.process_packet(&syn.ip, &syn.tcp, nullptr, 0, now);
        ++n;
    }
    size_t before = engine.session_count();

    const uint32_t client = inet_addr("192.168.50.2"), isn = 123456789;
    Packet syn = make_pkt(client, 50000, isn, 0, TH_SYN);
    auto r = engine.process_packet(&syn.ip, &syn.tcp, nullptr, 0, now += 1000);
    CHECK(r.syn_cookie && r.session == nullptr, "SYN above the threshold gets a cookie and no session");
    CHECK(engine.session_count() == before, "no memory allocated for the SYN");

    Packet forged = make_pkt(client, 50000, isn + 1, r.syn_cookie_isn + 2, TH_ACK);
    auto rf = engine.process_packet(&forged.ip, &forged.tcp, nullptr, 0, now += 1000);
    CHECK(rf.session == nullptr, "ACK with a wrong cookie is rejected");

    Packet other = make_pkt(client, 50001, isn + 1, r.syn_cookie_isn + 1, TH_ACK);
    auto ro = engine.process_packet(&other.ip, &other.tcp, nullptr, 0, now += 1000);
    CHECK(ro.session == nullptr, "a cookie is only valid for its own 4-tuple");

    const uint8_t hello[] = "GET / HTTP/1.1\r\n\r\n";
    Packet ack = make_pkt(client, 50000, isn + 1, r.syn_cookie_isn + 1, TH_ACK);
    auto ra = engine.process_packet(&ack.ip, &ack.tcp, hello, sizeof(hello) - 1, now += 1000);
    CHECK(ra.session && ra.from_cookie, "ACK echoing the cookie creates the session");
    CHECK(ra.is_ready && ra.payload_len == sizeof(hello) - 1, "data on the cookie ACK is delivered");
    CHECK(ra.session && ra.session->send_nxt == r.syn_cookie_isn + 1, "server sequence continues from the cookie");

    const uint8_t more[] = "more";
    Packet next = make_pkt(client, 50000, isn + 1 + sizeof(hello) - 1, r.syn_cookie_isn + 1, TH_ACK);
    auto rn = engine.process_packet(&next.ip, &next.tcp, more, 4, now += 1000);
    CHECK(rn.session == ra.session && !rn.from_cookie && rn.is_ready && rn.payload_len == 4,
          "following segments use the normal session path");
}

static void test_domain_policy() {
    std::puts("SNI domain policy");
    aethon::dns::DomainBlocklist list;
    list.add_domain("mydomain.com");
    list.add_domain("aethon.local");

    CHECK(list.is_allowed("test.local"), "unlisted domain is allowed");
    CHECK(list.is_allowed("example.com"), "unlisted .com domain is allowed");
    CHECK(!list.is_allowed("mydomain.com"), "listed domain is blocked");
    CHECK(!list.is_allowed("MyDomain.COM"), "listed domain is blocked case-insensitively");
    CHECK(!list.is_allowed("api.mydomain.com"), "subdomain of a listed domain is blocked");
    CHECK(!list.is_allowed("a.b.mydomain.com"), "deep subdomain of a listed domain is blocked");
    CHECK(list.is_allowed("notmydomain.com"), "suffix without a dot boundary is allowed");
    CHECK(!list.is_allowed(""), "empty SNI is rejected");
}

int main() {
    test_resegmented_retransmission();
    test_conflicting_overlap_detected();
    test_identical_duplicate_accepted();
    test_partial_fill_keeps_tracking();
    test_old_data_is_reacked();
    test_tcp_checksum();
    test_syn_cookies();
    test_domain_policy();

    std::printf("\n%s (%d failure%s)\n", g_failures ? "FAILED" : "ALL PASSED", g_failures,
                g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
