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
    test_domain_policy();

    std::printf("\n%s (%d failure%s)\n", g_failures ? "FAILED" : "ALL PASSED", g_failures,
                g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
