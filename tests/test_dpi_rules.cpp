// DPI rule-set test (no root needed). Loads rules/rulesets.conf exactly like Aethon, compiles it
// with Hyperscan, and checks:
//   1. coverage - a payload built from each rule's own content chain triggers that rule
//   2. benign   - realistic requests, documents and random binary uploads hit no BLOCKING rule
//
//   ./build/src/test_dpi_rules [rules/rulesets.conf]
#include "hyper_scan_engine.h"

#include <cstdio>
#include <random>
#include <string>
#include <vector>

using namespace aethon;

namespace {

int g_failures = 0;
#define CHECK(cond, msg) do { \
    if (cond) std::printf("  PASS %s\n", msg); \
    else { std::printf("  FAIL %s\n", msg); ++g_failures; } } while (0)

std::vector<uint32_t> g_block_hits;
void on_alert(const scan::AttackAlert &a) { if (a.blocking) g_block_hits.push_back(a.sid); }

// Scan data as one stream delivered in 1460-byte segments, like Aethon's pipeline.
// Returns the blocking SIDs that fired.
std::vector<uint32_t> scan_stream(scan::HyperscanWorker &w, const std::string &data) {
    g_block_hits.clear();
    hs_stream_t *st = w.open_stream();
    for (size_t off = 0; off < data.size(); off += 1460) {
        size_t n = std::min<size_t>(1460, data.size() - off);
        w.scan_stream(st, reinterpret_cast<const uint8_t *>(data.data()) + off, n);
    }
    hs_close_stream(st, nullptr, nullptr, nullptr);
    return g_block_hits;
}

std::string http_post(const std::string &body) {
    return "POST /api/upload HTTP/1.1\r\nHost: test.local\r\nUser-Agent: aethon-dpi-test\r\n"
           "Content-Type: application/octet-stream\r\nContent-Length: " + std::to_string(body.size()) +
           "\r\nConnection: close\r\n\r\n" + body;
}

// Build a byte string that satisfies a rule's content chain: offset padding, then each content
// separated by its minimum required distance. Uses the decoded literal bytes.
std::string synthesize(const rules::AethonRule &r) {
    std::string out;
    const auto &c0 = r.contents[0];
    if (c0.offset > 0) out.append(static_cast<size_t>(c0.offset), 'Q');
    out += c0.bytes;
    for (size_t i = 1; i < r.contents.size(); ++i) {
        int gap = r.contents[i].distance > 0 ? r.contents[i].distance : 1;
        out.append(static_cast<size_t>(gap), 'Q');
        out += r.contents[i].bytes;
    }
    return out;
}

bool has(const std::vector<uint32_t> &v, uint32_t sid) {
    for (uint32_t x : v) if (x == sid) return true;
    return false;
}

// Realistic traffic that must not trip any blocking rule.
std::vector<std::pair<const char *, std::string>> benign_corpus() {
    std::vector<std::pair<const char *, std::string>> v;
    v.push_back({"browser GET",
        "GET /products?id=42&sort=price&page=2 HTTP/1.1\r\nHost: shop.example.com\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.9\r\nCookie: session=7f3a9c1e2b; theme=dark\r\n\r\n"});
    v.push_back({"curl GET", "GET /api/health HTTP/1.1\r\nHost: 192.168.50.1\r\nUser-Agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"});
    v.push_back({"JSON POST",
        http_post("{\"user\":\"alice\",\"items\":[{\"sku\":\"A-17\",\"qty\":2}],\"note\":\"please select the blue one\"}")});
    v.push_back({"login form POST",
        "POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 44\r\n\r\nusername=alice%40example.com&password=hunter2x"});
    std::string html = "<!doctype html><html><head><title>Docs</title></head><body>";
    for (int i = 0; i < 300; ++i)
        html += "<p>Section " + std::to_string(i) + ": read the admin guide and select a plan.</p>";
    html += "</body></html>";
    v.push_back({"HTML document upload", http_post(html)});
    std::string png = std::string("\x89PNG\r\n\x1a\n", 8);
    std::mt19937 rng(7);
    for (int i = 0; i < 300000; ++i) png.push_back(static_cast<char>(rng()));
    v.push_back({"random binary upload (300 KB)", http_post(png)});
    return v;
}

} // namespace

int main(int argc, char **argv) {
    const char *conf = argc > 1 ? argv[1] : "rules/rulesets.conf";

    rules::RuleDatabase db;
    auto st = db.load_rulesets(conf, /*verbose=*/false);
    if (db.empty()) {
        std::fprintf(stderr, "could not load any rules from %s (run from the repo root)\n", conf);
        return 2;
    }
    std::printf("Loaded %zu rules (%zu blocking) from %s\n", st.loaded, st.blocking, conf);

    const std::string cache_dir = "/tmp/aethon_hs_cache_test";
    scan::HyperscanEngine engine;
    engine.set_alert_callback(on_alert);
    scan::CompileStats cs;
    bool ok = engine.compile_or_load(db, cache_dir, cs);
    CHECK(ok, "rule set compiles into a Hyperscan database");
    if (!ok) return 1;
    std::printf("%s %zu patterns (%zu blocking) in %d ms%s; skipped %zu unsupported, %zu too short; "
                "db %zu KB, stream state %zu B\n",
                cs.from_cache ? "Loaded" : "Compiled", cs.compiled, cs.blocking, static_cast<int>(cs.compile_ms),
                cs.from_cache ? " from cache" : "",
                cs.skipped_invalid, cs.skipped_weak, cs.database_bytes / 1024, cs.stream_state_bytes);

    // Serialized-DB cache: a second load with the same rules must hit the cache and be fast.
    {
        scan::HyperscanEngine e2;
        scan::CompileStats cs2;
        bool ok2 = e2.compile_or_load(db, cache_dir, cs2);
        CHECK(ok2 && cs2.from_cache, "second load comes from the serialized-DB cache");
        CHECK(ok2 && cs2.compile_ms < 2000, "cache load is fast (< 2 s vs. a full compile)");
        CHECK(cs2.compiled == cs.compiled, "cache has the same pattern count");
    }
    auto worker = engine.create_worker();

    // 1. Coverage: each blocking rule must fire on a payload built from its own contents.
    std::puts("\nCoverage (each blocking rule detects its own signature)");
    size_t checked = 0, detected = 0;
    for (const auto &r : db.rules()) {
        if (!r.block || r.contents.empty()) continue;
        bool skip = false;
        for (const auto &c : r.contents) if (c.bytes.empty()) skip = true;   // pure-pcre chains
        if (skip) continue;
        ++checked;
        if (has(scan_stream(worker, synthesize(r)), r.sid)) ++detected;
    }
    std::printf("  %zu/%zu blocking content rules detected their own signature\n", detected, checked);
    // Hyperscan's combined matching plus distance approximation won't be 100%, but should be high.
    CHECK(checked > 0 && detected * 100 >= checked * 90, "at least 90% self-detection coverage");

    // 2. Benign traffic must not be blocked.
    std::puts("\nBenign traffic is not blocked");
    for (auto &[name, req] : benign_corpus()) {
        auto hits = scan_stream(worker, req);
        if (hits.empty()) std::printf("  PASS %s\n", name);
        else { std::printf("  FAIL %s (blocked by SID %u)\n", name, hits[0]); ++g_failures; }
    }

    std::printf("\n%s (%d failure%s)\n", g_failures ? "FAILED" : "ALL PASSED", g_failures,
                g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
