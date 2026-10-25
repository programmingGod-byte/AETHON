// JA3 rate limiter tests (no root needed).
//   1. correctness of the per-worker limiter (window, per-fingerprint counting, fail-open)
//   2. the per-worker design is race-free: N threads each with their own limiter, no shared state
//
// Background: the first JA3 implementation shared ONE SingleThreadHashMap across all worker
// threads and put std::atomic fields inside the value. That is a data race: the atomics only
// guard individual fields of a value you already hold, but find()/insert() read and write the
// map's own cells, probe chain and size_ (all plain, non-atomic) from several threads at once
// (undefined behavior), and insert() copy-assigns the whole value while another thread does an
// atomic RMW on it. The fix is one limiter per worker (a flow always returns to the same worker
// via RSS), so there is no shared state and no need for atomics or locks. These tests exercise
// that design.
#include <netinet/in.h>
#include "tcp_pipeline.h"

#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using aethon::pipeline::Ja3RateLimiter;
using aethon::tls::JA3;

static int g_failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) std::printf("  PASS %s\n", msg); \
    else { std::printf("  FAIL %s\n", msg); ++g_failures; } } while (0)

static JA3 fp(const std::string &s) {
    JA3 j;
    int n = static_cast<int>(std::min(s.size(), sizeof(j.ja3_str)));
    std::memcpy(j.ja3_str, s.data(), static_cast<size_t>(n));
    j.curr_id = n;
    return j;
}

static void test_correctness() {
    std::puts("per-worker limiter correctness");
    Ja3RateLimiter::Config cfg{/*limit=*/10, /*window_ns=*/1'000'000'000ULL};
    Ja3RateLimiter lim(cfg);
    JA3 chrome = fp("771,4865-4866,0-23,29-23,0");
    uint64_t t = 1'000'000'000ULL;

    int blocked = 0;
    for (int i = 0; i < 10; ++i) blocked += lim.should_block(chrome, 0x01020304, t);
    CHECK(blocked == 0, "first 10 ClientHellos within the limit are allowed");
    CHECK(lim.should_block(chrome, 0x01020304, t), "the 11th in the window is blocked");

    // A different fingerprint has its own counter
    JA3 curl = fp("771,4867,0,0,0");
    CHECK(!lim.should_block(curl, 0x01020304, t), "a different fingerprint is independent");

    // Window reset: after the window elapses the count restarts
    t += 1'100'000'000ULL;
    CHECK(!lim.should_block(chrome, 0x01020304, t), "count resets after the window elapses");

    // Empty fingerprint (also the map's empty key) is never counted or blocked
    JA3 none; none.curr_id = 0;
    bool any = false;
    for (int i = 0; i < 100; ++i) any |= lim.should_block(none, 0x05060708, t);
    CHECK(!any, "empty fingerprint is never blocked");

    // The limit is per fingerprint, shared across source IPs (the point of JA3 limiting)
    Ja3RateLimiter lim2(cfg);
    int blk = 0;
    for (int i = 0; i < 20; ++i) blk += lim2.should_block(chrome, 0x0A000000u + i, t);  // 20 different IPs
    CHECK(blk > 0, "same fingerprint from many source IPs still hits the shared per-fingerprint limit");
}

static void test_many_fingerprints_bounded() {
    std::puts("memory is bounded under many unique fingerprints");
    Ja3RateLimiter lim;
    for (int i = 0; i < 20000; ++i) lim.should_block(fp("fp-" + std::to_string(i)), 0x01020304, 1'000'000'000ULL);
    CHECK(lim.tracked() <= 4000, "fingerprint table is capped (fails open past the cap)");
}

// Each worker owns its limiter; running several in parallel must be safe and independent.
// (ThreadSanitizer builds of this test are expected to be clean, unlike the old shared map.)
static void test_per_worker_parallel() {
    std::puts("per-worker limiters run in parallel with no shared state");
    constexpr int kWorkers = 4;
    constexpr int kPerWorker = 200000;
    std::vector<int> blocked(kWorkers, 0);
    std::vector<std::thread> ts;
    for (int w = 0; w < kWorkers; ++w) {
        ts.emplace_back([&, w]() {
            Ja3RateLimiter lim(Ja3RateLimiter::Config{50, 1'000'000'000ULL});
            JA3 j = fp("worker-shared-fingerprint");
            uint64_t t = 1'000'000'000ULL;
            int b = 0;
            for (int i = 0; i < kPerWorker; ++i) {
                if (i % 1000 == 999) t += 1'100'000'000ULL;   // advance past the window periodically
                b += lim.should_block(j, 0x01020304u + static_cast<uint32_t>(i), t);
            }
            blocked[w] = b;
        });
    }
    for (auto &t : ts) t.join();
    bool all_limited = true;
    for (int b : blocked) all_limited &= (b > 0);
    CHECK(all_limited, "every worker independently enforced its limit without crashing or corruption");
}

int main() {
    test_correctness();
    test_many_fingerprints_bounded();
    test_per_worker_parallel();
    std::printf("\n%s (%d failure%s)\n", g_failures ? "FAILED" : "ALL PASSED", g_failures,
                g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
