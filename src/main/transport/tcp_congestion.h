#pragma once
#include <cstdint>
#include <algorithm>
#include <cstddef>
#include "aethon/aethon.h"

#ifndef AETHON_ALWAYS_INLINE
#if defined(__GNUC__) || defined(__clang__)
#define AETHON_ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
#define AETHON_ALWAYS_INLINE inline
#endif
#endif

#ifndef AETHON_UNLIKELY
#if defined(__GNUC__) || defined(__clang__)
#define AETHON_UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define AETHON_UNLIKELY(x) (x)
#endif
#endif

namespace aethon {
namespace tcp {

    /**
     * @brief TCP Congestion Control State & Reno Algorithm (RFC 5681, RFC 6928)
     * 
     * Coordinates Congestion Window (cwnd) and Slow Start Threshold (ssthresh)
     * to protect transit networks and optimize transmission rate without packet drops.
     */
    class alignas(16) TcpRenoCongestionControl {
    public:
        static constexpr uint32_t DEFAULT_MSS = 1460;
        static constexpr uint32_t INITIAL_CWND_SEGMENTS = 10; // RFC 6928 initcwnd = 10 MSS (~14.6 KB)

        uint32_t cwnd{INITIAL_CWND_SEGMENTS * DEFAULT_MSS};   // Congestion window in bytes
        uint32_t ssthresh{65535};                            // Slow-start threshold in bytes
        uint32_t mss{DEFAULT_MSS};                           // Maximum segment size

        TcpRenoCongestionControl() noexcept = default;
        explicit TcpRenoCongestionControl(uint32_t segment_size) noexcept 
            : cwnd(INITIAL_CWND_SEGMENTS * segment_size), ssthresh(65535), mss(segment_size) {}

        /**
         * @brief Advance congestion window upon receiving a cumulative forward ACK.
         * 
         * - Slow Start (cwnd < ssthresh): Exponential growth.
         * - Congestion Avoidance (cwnd >= ssthresh): Additive increase (~1 MSS per RTT).
         */
        AETHON_ALWAYS_INLINE void on_ack(size_t bytes_acked) noexcept {
            if (cwnd < ssthresh) {
                cwnd += static_cast<uint32_t>(std::min<size_t>(bytes_acked, mss));
            } else {
                uint32_t inc = (mss * mss) / cwnd;
                cwnd += (inc > 0) ? inc : 1;
            }

            // Cap at 16 MB maximum transmission window
            if (AETHON_UNLIKELY(cwnd > 16 * 1024 * 1024)) {
                cwnd = 16 * 1024 * 1024;
            }
        }

        /**
         * @brief Multiplicative Decrease on Fast Retransmit (3 duplicate ACKs).
         */
        AETHON_ALWAYS_INLINE void on_fast_retransmit() noexcept {
            ssthresh = std::max<uint32_t>(2 * mss, cwnd / 2);
            cwnd = ssthresh;
        }

        /**
         * @brief Heavy Collapse on RTO expiration.
         */
        AETHON_ALWAYS_INLINE void on_rto_timeout() noexcept {
            ssthresh = std::max<uint32_t>(2 * mss, cwnd / 2);
            cwnd = 1 * mss;
        }

        /**
         * @brief Returns the allowed outbound transmit bytes taking into account
         * both Flow Control (snd_wnd) and Congestion Control (cwnd).
         */
        AETHON_ALWAYS_INLINE size_t allowed_to_send(size_t in_flight, uint32_t snd_wnd) const noexcept {
            size_t eff_wnd = std::min<size_t>(snd_wnd, cwnd);
            if (in_flight >= eff_wnd) {
                return 0;
            }
            return eff_wnd - in_flight;
        }
    };

} // namespace tcp
} // namespace aethon

