#pragma once
// Counters for rare events (resets, drops, SYN cookies, expiries) so a test run can show
// *why* connections ended. Relaxed atomics shared by all workers; never touched per packet
// on the normal path, only when the event happens.
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>

namespace aethon::stats {

enum class Event : uint8_t {
    TcpBadChecksum,       // segment dropped: TCP checksum invalid
    RstNoSession,         // RST/ACK for a segment of an unknown connection
    RstOverlapEvasion,    // retransmission conflicts with buffered data
    RstDpiMatch,          // Hyperscan rule matched (plain or decrypted)
    RstSniBlocked,        // blocked or missing SNI
    RstBadClientHello,    // ClientHello too large or invalid record length
    RstBackendFailed,     // could not hand data to the backend (buffer full, socket error)
    RstTlsError,          // TLS decrypt / protocol error
    Ja3RateLimited,       // ClientHello dropped: fingerprint over its per-worker rate limit
    SynCookieSent,        // SYN answered statelessly (table under pressure)
    SynCookieAccepted,    // connection created from a valid cookie
    SessionExpiredIdle,   // session purged after the idle timeout
    SessionRtoGiveUp,     // peer stopped acknowledging; session dropped after max retries
    Count
};

inline constexpr std::array<const char *, static_cast<size_t>(Event::Count)> kEventNames{
    "tcp_bad_checksum", "rst_no_session", "rst_overlap_evasion", "rst_dpi_match",
    "rst_sni_blocked",  "rst_bad_client_hello", "rst_backend_failed", "rst_tls_error",
    "ja3_rate_limited",
    "syn_cookie_sent",  "syn_cookie_accepted", "session_expired_idle", "session_rto_give_up",
};

inline std::array<std::atomic<uint64_t>, static_cast<size_t>(Event::Count)> g_events{};

inline void count(Event e) noexcept {
    g_events[static_cast<size_t>(e)].fetch_add(1, std::memory_order_relaxed);
}

// Prints "name=value" for every non-zero counter on one line. Returns false if all are zero.
inline bool print_nonzero(std::FILE *out, const char *prefix) noexcept {
    bool any = false;
    for (size_t i = 0; i < g_events.size(); ++i) {
        uint64_t v = g_events[i].load(std::memory_order_relaxed);
        if (v == 0) continue;
        if (!any) std::fprintf(out, "%s", prefix);
        std::fprintf(out, " %s=%llu", kEventNames[i], static_cast<unsigned long long>(v));
        any = true;
    }
    if (any) std::fprintf(out, "\n");
    return any;
}

inline uint64_t total() noexcept {
    uint64_t t = 0;
    for (auto &c : g_events) t += c.load(std::memory_order_relaxed);
    return t;
}

} // namespace aethon::stats
