// Randomized torture test for TCP reassembly (no root, no network needed).
// A simulated sender pushes a random stream through TcpAssemblerEngine with loss, reordering,
// duplicates, resegmented retransmissions, stale old segments and out-of-window junk.
// The delivered byte stream must equal the original exactly and the session must never die.
//
//   cmake --build build --target test_tcp_fuzz && ./build/src/test_tcp_fuzz [seeds] [bytes]
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "tcp_assembler.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>

using namespace aethon::IPv4TcpAssembler;

namespace {

struct Packet {
    iphdr ip{};
    tcphdr tcp{};
};

Packet make(uint32_t seq, uint8_t flags, uint16_t sport) {
    Packet p;
    p.ip.ihl = 5;
    p.ip.protocol = IPPROTO_TCP;
    p.ip.saddr = inet_addr("192.168.50.2");
    p.ip.daddr = inet_addr("192.168.50.1");
    p.tcp.source = htons(sport);
    p.tcp.dest = htons(80);
    p.tcp.seq = htonl(seq);
    p.tcp.ack_seq = htonl(1);
    p.tcp.doff = 5;
    p.tcp.window = htons(65535);
    reinterpret_cast<uint8_t *>(&p.tcp)[13] = flags;
    return p;
}

struct Profile {
    const char *name;
    int loss_pct;       // segment dropped
    int reorder_pct;    // swapped with its neighbour
    int dup_pct;        // sent twice
    int small_pct;      // segment shorter than MSS
    int stale_pct;      // an old, already delivered segment is replayed
    int junk_pct;       // out-of-window segment with random content is injected
};

// Returns an empty string on success, otherwise a description of the failure
std::string run(const Profile &pf, uint32_t seed, size_t total) {
    std::mt19937 rng(seed);
    auto pct = [&](int p) { return static_cast<int>(rng() % 100) < p; };

    TcpAssemblerEngine engine;
    uint64_t now = 1'000'000'000ULL;
    const uint16_t sport = static_cast<uint16_t>(20000 + seed % 40000);
    const uint32_t isn = rng();                       // exercises sequence wrap-around too

    std::vector<uint8_t> stream(total), junk(1460), out;
    for (auto &b : stream) b = static_cast<uint8_t>(rng());
    out.reserve(total);

    bool alive = true;
    size_t unacked_old = 0;
    auto feed = [&](uint32_t seq, const uint8_t *data, size_t len) {
        // A segment that ends at or before what we already delivered is a retransmission; the
        // receiver must answer it with an ACK, otherwise the sender backs off until it stalls.
        const bool fully_old = (seq - (isn + 1)) + len <= out.size();
        Packet p = make(seq, TH_ACK, sport);
        auto r = engine.process_packet(&p.ip, &p.tcp, data, static_cast<uint16_t>(len), now += 1000);
        if (!r.session) { alive = false; return; }
        if (fully_old && !r.need_ack) ++unacked_old;
        if (r.is_ready && r.payload_len) out.insert(out.end(), r.payload, r.payload + r.payload_len);
    };

    Packet syn = make(isn, TH_SYN, sport);
    engine.process_packet(&syn.ip, &syn.tcp, nullptr, 0, now);
    Packet ack = make(isn + 1, TH_ACK, sport);
    engine.process_packet(&ack.ip, &ack.tcp, nullptr, 0, now += 1000);

    constexpr size_t kWindow = 60000;
    size_t snd_nxt = 0;
    for (int round = 0; alive && out.size() < total; ++round) {
        if (round > 200000) return "no progress (livelock)";
        const size_t acked = out.size();
        if (snd_nxt < acked) snd_nxt = acked;

        // Build one flight inside the receive window
        std::vector<std::pair<size_t, size_t>> flight;
        while (snd_nxt < acked + kWindow && snd_nxt < total) {
            size_t len = pct(pf.small_pct) ? 1 + rng() % 1459 : 1460;
            len = std::min(len, total - snd_nxt);
            flight.push_back({snd_nxt, len});
            snd_nxt += len;
        }
        for (size_t i = 0; i + 1 < flight.size(); ++i)
            if (pct(pf.reorder_pct)) std::swap(flight[i], flight[i + 1]);

        for (auto [off, len] : flight) {
            if (!alive) break;
            if (pct(pf.loss_pct)) continue;
            feed(isn + 1 + static_cast<uint32_t>(off), stream.data() + off, len);
            if (alive && pct(pf.dup_pct)) feed(isn + 1 + static_cast<uint32_t>(off), stream.data() + off, len);
            if (alive && pct(pf.stale_pct) && out.size() > 3000) {
                size_t old = rng() % (out.size() - 1500);
                feed(isn + 1 + static_cast<uint32_t>(old), stream.data() + old, 1460);
            }
            if (alive && pct(pf.junk_pct)) {
                for (auto &b : junk) b = static_cast<uint8_t>(rng());
                // Beyond the 64 KB reassembly window: must be ignored, never stored
                uint32_t far = static_cast<uint32_t>(out.size() + 70000 + rng() % 100000);
                feed(isn + 1 + far, junk.data(), junk.size());
            }
        }
        if (!alive) break;

        // Retransmit from the first missing byte, with boundaries unrelated to the originals
        if (out.size() < snd_nxt) {
            size_t from = out.size();
            size_t len = std::min<size_t>(1 + rng() % 2920, total - from);
            while (len > 0 && alive) {
                size_t chunk = std::min<size_t>(len, 1460);
                feed(isn + 1 + static_cast<uint32_t>(from), stream.data() + from, chunk);
                from += chunk;
                len -= chunk;
            }
            snd_nxt = out.size();     // go-back-N like a Linux RTO
        }
    }

    if (!alive) return "session killed after " + std::to_string(out.size()) + " bytes";
    if (unacked_old) return std::to_string(unacked_old) + " retransmissions of old data got no ACK";
    if (out.size() != total) return "delivered " + std::to_string(out.size()) + " of " + std::to_string(total);
    if (std::memcmp(out.data(), stream.data(), total) != 0) {
        size_t i = 0;
        while (out[i] == stream[i]) ++i;
        return "stream corrupted at byte " + std::to_string(i);
    }
    return "";
}

} // namespace

int main(int argc, char **argv) {
    const int seeds = argc > 1 ? std::atoi(argv[1]) : 30;
    const size_t bytes = argc > 2 ? static_cast<size_t>(std::atoll(argv[2])) : 1'000'000;

    const Profile profiles[] = {
        {"clean",            0,  0,  0, 10, 0, 0},
        {"loss 2%",          2,  0,  0, 10, 0, 0},
        {"loss 10%",        10,  0,  0, 10, 0, 0},
        {"reorder 25%",      0, 25,  0, 10, 0, 0},
        {"duplicate 10%",    0,  0, 10, 10, 0, 0},
        {"stale replays",    1,  0,  0, 10, 5, 0},
        {"out-of-window",    1,  0,  0, 10, 0, 5},
        {"everything",       5, 15,  5, 30, 3, 3},
        {"tiny segments",    3, 10,  3, 90, 0, 0},
    };

    int failures = 0;
    for (const auto &pf : profiles) {
        int bad = 0;
        std::string first;
        for (int s = 0; s < seeds; ++s) {
            std::string err = run(pf, static_cast<uint32_t>(s * 7919 + 17), bytes);
            if (!err.empty() && bad++ == 0) first = "seed " + std::to_string(s) + ": " + err;
        }
        std::printf("  %s %-15s %d/%d seeds ok%s%s\n", bad ? "FAIL" : "PASS", pf.name, seeds - bad, seeds,
                    bad ? "  first: " : "", first.c_str());
        failures += bad;
    }
    std::printf("\n%s\n", failures ? "FAILED" : "ALL PASSED");
    return failures ? 1 : 0;
}
