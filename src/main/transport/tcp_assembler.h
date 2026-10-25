/*

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |  (16 bits each)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |  (32 bits!)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |  (32 bits!)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |  (16 bits)
| (4b)  |   (6b)    |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    | (0-40 bytes)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


tcp->doff ---> the length of the Tcp header in 4-byte words.

flags 6 bits

SYN --> starts a new connection (Used to create a session)
ACK ---> acknodeges received data
FIN --> sender has finished sending data (graceful close)
RST  --> Abruptly kills the connection immediately (purge session)

TCP session key = (source_ip , destination_ip, source_port, destination_port)

TCP handshake

      CLIENT                                  SERVER
         |                                       |
         | ---- 1. SYN (seq = 1000) -----------> |  (Client wants to connect)
         |                                       |
         | <--- 2. SYN-ACK (seq=5000, ack=1001)- |  (Server accepts)
         |                                       |
         | ---- 3. ACK (seq = 1001, ack=5001)--> |  (Connection ESTABLISHED!)
         |                                       |
         | ---- 4. DATA (seq = 1001, len=500)--> |  (Actual HTTP/TLS payload!)


A SYN flag virtually consue 1 sequence number
that means the very first real byte of connection will start at : INtital Data sequence Number (ISN) = SYN_seq + 1

MSS (maximum segment size ) -> Options Kind = 2 ---> tell the other side the mtu is 1500 bytes. subtract 40 byttes for I{/Tcp header, the maximum payload i can receive in 1 pakcket is 1460 bytes;
Window  Scale ( option 3) --> header_window << shift 

3. SACK Permitted (Selective Acknowledgment) — Option Kind = 4
In basic TCP, if Packet 2 is lost but Packets 3, 4, 5 arrive, the server has to ask for everything starting from 2 again.
With SACK, the receiver can say: "I got bytes 3000..5000, just retransmit bytes 1000..2999."

------  TCP option use standard TLV (type length value ) encoding
+------------+------------+-----------------------+
| Kind (1B)  | Length (1B)| Value (Length-2 Bytes)|
+------------+------------+-----------------------+

Kind = 0 (TCPOPT_EOL): End of options list. Stop parsing immediately!
Kind = 1 (TCPOPT_NOP): No-operation (1 byte of padding for alignment). Skip 1 byte.

*/
#pragma once
#include <hs/hs.h>
#include <vector>
#include "aethon/aethon.h"
#include "tcp_congestion.h"

#ifndef AETHON_ALWAYS_INLINE
#if defined(__GNUC__) || defined(__clang__)
#define AETHON_ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
#define AETHON_ALWAYS_INLINE inline
#endif
#endif

#include "aethon/single_thread_hasmap.h"
#include "tls_engine.h"
#include <array>
#include <cstddef>

#include <cstdint>
#include <cstring>
#include <linux/in.h>
#include <new>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <poll.h>
namespace aethon {
    namespace IPv4TcpAssembler {
        enum class TcpState : uint8_t{
            CLOSED = 0,
            SYN_SENT = 1, // SAW SYN FROM THE CLIEND
            ESTABLISHED = 2,
            CLOSING = 3,
        };



          struct alignas(16) TcpKey {
            uint32_t src_ip{0};
            uint32_t dst_ip{0};
            uint16_t src_port{0};
            uint16_t dst_port{0};
            uint32_t _pad{0}; 
            AETHON_ALWAYS_INLINE bool operator==(const TcpKey &o) const noexcept {
                return src_ip == o.src_ip &&
                       dst_ip == o.dst_ip &&
                       src_port == o.src_port &&
                       dst_port == o.dst_port;
            }
            AETHON_ALWAYS_INLINE bool operator!=(const TcpKey &o) const noexcept {
                return !(*this == o);
            }
        };


        struct TcpKeyHasher {
            AETHON_ALWAYS_INLINE size_t operator()(const TcpKey &k) const noexcept {
                uint64_t h1 = (static_cast<uint64_t>(k.src_ip) << 32) | k.dst_ip;
                uint64_t h2 = (static_cast<uint64_t>(k.src_port) << 16) | k.dst_port;
                
                h1 ^= h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2);
                h1 ^= h1 >> 30;
                h1 *= 0xbf58476d1ce4e5b9ULL;
                h1 ^= h1 >> 27;
                h1 *= 0x94d049bb133111ebULL;
                h1 ^= h1 >> 31;
                return static_cast<size_t>(h1);
            }
        };


        static constexpr TcpKey KemptyTcpKey {0,0,0,0,0};
        struct TcpSeq{
             AETHON_ALWAYS_INLINE static bool lt(uint32_t a, uint32_t b) noexcept {
                return static_cast<int32_t>(a - b) < 0;
            }
            AETHON_ALWAYS_INLINE static bool lte(uint32_t a, uint32_t b) noexcept {
                return static_cast<int32_t>(a - b) <= 0;
            }
            AETHON_ALWAYS_INLINE static bool gt(uint32_t a, uint32_t b) noexcept {
                return static_cast<int32_t>(a - b) > 0;
            }
            AETHON_ALWAYS_INLINE static bool gte(uint32_t a, uint32_t b) noexcept {
                return static_cast<int32_t>(a - b) >= 0;
            }
            AETHON_ALWAYS_INLINE static uint32_t diff(uint32_t a, uint32_t b) noexcept {
                return a - b;
            }
        };


        struct TcpNegotiatedParams{
            uint16_t mss{1460}; // mtu
            uint8_t wscale {0}; // window scaler factor
            bool sack_permitted{false};
        };

        AETHON_ALWAYS_INLINE static void parse_tcp_syn_option(const struct tcphdr * __restrict__ tcph,TcpNegotiatedParams &out_params) noexcept{
            
            // tcp header length
            const size_t tcp_hdr_len = tcph->doff * 4;

            if(AETHON_UNLIKELY(tcp_hdr_len <= sizeof(struct tcphdr))){
                return ;
            }
            
            const uint8_t *__restrict__ opt = reinterpret_cast<const uint8_t *>(tcph) + sizeof(struct tcphdr);
            const uint8_t *__restrict__ end = reinterpret_cast<const uint8_t *>(tcph) + tcp_hdr_len;

            while (opt < end) {
                const uint8_t kind = *opt;
                if(kind == TCPOPT_EOL){
                    break; // end of list
                }
                if(kind == TCPOPT_NOP){
                    ++opt;
                    continue;
                }

                // kind 1 byte length 1 byte value 2 byte

                if(AETHON_UNLIKELY(opt + 1 >= end)){
                    break;
                }

                const uint8_t len = *(opt + 1);
                if(AETHON_UNLIKELY(len <2 || opt + len > end)) break;

                switch (kind) {
                    case TCPOPT_MAXSEG: // kind 2 : mSS (length 4)
                        if(AETHON_LIKELY(len == TCPOLEN_MAXSEG)){
                            out_params.mss =  ntohs(*reinterpret_cast<const uint16_t *>(opt + 2));
                        }
                        break;
                        
                    case TCPOPT_WINDOW: // kind 3 window scale (length = 3)
                        if(AETHON_LIKELY(len == TCPOLEN_WINDOW)){
                            out_params.wscale = *(opt + 2);
                            if(out_params.wscale > 14) out_params.wscale = 14 ; // max shift 14
                        }
                        break;
                    
                    case TCPOPT_SACK_PERMITTED:
                        if(AETHON_LIKELY(len == TCPOLEN_SACK_PERMITTED)){
                            out_params.sack_permitted = true;
                        }
                        break;
                    default:
                        break;
                }

                opt+=len;
            }



        }

        
        static constexpr size_t AETHON_MAX_ACTIVE_TCP_SESSION = 65536;
        static constexpr size_t AETHON_TCP_WINDOW_SIZE = 65536;
        static constexpr size_t AETHON_TCP_BITMAP_WORDS        = AETHON_TCP_WINDOW_SIZE / 64; 
        static constexpr uint64_t AETHON_TCP_SYN_TIMEOUT_NS    = 3ULL * 1000000000ULL;  
        static constexpr uint64_t AETHON_TCP_ESTAB_TIMEOUT_NS  = 30ULL * 1000000000ULL; 


        struct TcpStreamSession;
        struct TcpAssemblyResult{
             bool is_ready{false};
            bool is_syn{false};
            bool is_closed{false};
            bool need_ack{false};
            uint16_t src_port{0};
            uint16_t dst_port{0};
            const uint8_t *payload{nullptr};
            size_t payload_len{0};
            TcpStreamSession *session{nullptr};
            hs_stream_t *hs_stream{nullptr};
            bool fast_retransmit{false};
        };

        
        struct alignas(implementation::hardware_destructive_interference_size)
        TcpStreamSession{
            TcpKey key{KemptyTcpKey};
            TcpState state{TcpState::CLOSED};
            uint8_t _pad0{0};
            uint16_t out_of_order_count{0}; // how many out of out packet sitting in the ring buffer
            uint32_t isn{0};
            uint32_t rcv_nxt{0};
            uint64_t last_seen_ns{0};
            TcpNegotiatedParams params{};

            uint64_t *bitmap{nullptr};
            uint8_t  *ring_buf{nullptr}; // 64 kb preallocated 

            tls::TlsConnection tls_conn;

            int backend_fd {-1};
            uint16_t backend_port {0};
            static constexpr size_t MAX_BACKEND_BUF = 256 * 1024;
            std::vector<uint8_t> backend_tx_buf;
            bool epollout_armed{false};

            /*
                send_una                                       send_nxt
            [Already Acked]| In flight in snd_buf(3KB)   |    (Not sent yet)    ]     

            */

            // Outbound TCP Reliability State
            uint32_t snd_una{0};                       // Oldest unacknowledged sequence number
            uint32_t snd_wnd{65535};                   // Client's advertised receive window (starts at 64 KB)
            static constexpr size_t MAX_SND_BUF = 256 * 1024; // 256 KB max in-flight
            std::vector<uint8_t> snd_buf;              // Data in-flight or waiting to be sent
            uint64_t last_tx_time_ns{0};               // Timestamp of last transmission
            uint32_t rto_ms{200};                       // RTO in milliseconds (starts at 200ms)
            uint8_t retransmit_count{0};               // Number of retransmissions

            uint8_t dup_ack_count{0};                      // Number of duplicate ACKs received
            tcp::TcpRenoCongestionControl cc;              // Congestion Control (cwnd, ssthresh)
            // Compute dynamic receive window based on remaining buffer capacity

            bool fin_pending{false}; // backend reached EOF ; defer FIN until send_buf drains


            AETHON_ALWAYS_INLINE uint16_t recv_window() const noexcept {
                size_t used = backend_tx_buf.size();
                if (used >= MAX_BACKEND_BUF) return 0;
                size_t remaining = MAX_BACKEND_BUF - used;
                return static_cast<uint16_t>(std::min<size_t>(65535, remaining));
            }

            hs_stream_t *hs_stream{nullptr};

            uint8_t client_mac[6]{0};
            uint8_t server_mac[6]{0};
            uint32_t send_nxt{0};

            std::vector<uint8_t> client_hello_buf;

            TcpStreamSession() = default;

            ~TcpStreamSession() {

                if(backend_fd >=0){
                    ::close(backend_fd);
                    backend_fd = -1;
                }

                if (ring_buf) {
                    std::free(ring_buf);
                    ring_buf = nullptr;
                }
                if (bitmap) {
                    std::free(bitmap);
                    bitmap = nullptr;
                }

                if(hs_stream){
                    hs_close_stream(hs_stream, nullptr, nullptr, nullptr);
                    hs_stream = nullptr;
                }
            }
            TcpStreamSession(const TcpStreamSession &) = delete;
            TcpStreamSession &operator=(const TcpStreamSession &) = delete;


            AETHON_ALWAYS_INLINE bool flush_backend_tx() noexcept {
                if(backend_fd < 0 || backend_tx_buf.empty()) return true;
                ssize_t sent = ::send(backend_fd, backend_tx_buf.data(), backend_tx_buf.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
                if (sent > 0) {
                    backend_tx_buf.erase(backend_tx_buf.begin(), backend_tx_buf.begin() + sent);
                }
                return backend_tx_buf.empty();
            }




            AETHON_ALWAYS_INLINE bool init_bufferes() noexcept {
                if(AETHON_LIKELY(ring_buf != nullptr)){
                    return true;
                }

                ring_buf = static_cast<uint8_t *>(implementation
                ::smart_allocate<uint8_t,implementation::hardware_destructive_interference_size>(AETHON_TCP_WINDOW_SIZE));

                if(AETHON_UNLIKELY(!ring_buf)) return false;

                 bitmap = static_cast<uint64_t *>(
                    implementation::smart_allocate<uint64_t, implementation::hardware_destructive_interference_size>(AETHON_TCP_BITMAP_WORDS * sizeof(uint64_t)));
                if (AETHON_UNLIKELY(!bitmap)) {
                    std::free(ring_buf);
                    ring_buf = nullptr;
                    return false;
                }
                std::memset(bitmap, 0, AETHON_TCP_BITMAP_WORDS * sizeof(uint64_t));
                return true;
            }

            AETHON_ALWAYS_INLINE bool forward_to_backend(const uint8_t *data, size_t len, uint16_t target_port) noexcept {
                if(AETHON_UNLIKELY(!data || len == 0 || target_port ==0)){
                    return false;
                }

                if(AETHON_UNLIKELY(backend_fd < 0 || backend_port != target_port)){
                    if(backend_fd >=0){
                        ::close(backend_fd);
                        backend_fd = -1;
                    }

                    backend_tx_buf.clear();

                    backend_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
                    if(backend_fd < 0){
                        return false;
                    }

                    int one = 1;
                    setsockopt(backend_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
                    struct sockaddr_in sin {};
                    sin.sin_family  = AF_INET;
                    sin.sin_port = htons(target_port);
                    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

                    connect(backend_fd, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin));
                    backend_port = target_port;
                    // Bound the pending write buffer to protect against OOM
                    if (backend_tx_buf.size() + len > MAX_BACKEND_BUF) {
                        return false;
                    }
                    backend_tx_buf.insert(backend_tx_buf.end(), data, data + len);
                    return true;
                }

                if(!backend_tx_buf.empty()){
                    // Check capacity before buffering in case backend is slow
                    if (backend_tx_buf.size() + len > MAX_BACKEND_BUF) {
                        return false;
                    }
                    backend_tx_buf.insert(backend_tx_buf.end(), data, data + len);
                    flush_backend_tx();
                    return true;
                }

                ssize_t sent = ::send(backend_fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL);
                if(sent < 0){
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
                        if (backend_tx_buf.size() + len > MAX_BACKEND_BUF) {
                            return false;
                        }
                        backend_tx_buf.insert(backend_tx_buf.end(), data, data + len);
                        return true;
                    }
                    return false;
                }

                if(static_cast<size_t>(sent) < len){
                    size_t unsent = len - sent;
                    if (backend_tx_buf.size() + unsent > MAX_BACKEND_BUF) {
                        return false;
                    }
                    backend_tx_buf.insert(backend_tx_buf.end(), data + sent, data + len);
                }
                return true;
            }


            AETHON_ALWAYS_INLINE ssize_t read_from_backend(uint8_t * buf, size_t max_len, int timeout_ms = 50) noexcept {
                 if(AETHON_UNLIKELY(backend_fd < 0 || !buf || max_len == 0)){
                    return -1;
                }
                return  ::recv(backend_fd, buf, max_len, MSG_DONTWAIT);
                
            }

            
            AETHON_ALWAYS_INLINE void write_ring_buffer(size_t start, const uint8_t * __restrict__ data,size_t len) noexcept{
                start&=0xFFFF;

                AETHON_BUILTIN_PREFETCH(&ring_buf[start], 1, 3);
                if(AETHON_UNLIKELY(start + len  > AETHON_TCP_WINDOW_SIZE)){
                    size_t first = AETHON_TCP_WINDOW_SIZE - start;
                    std::memcpy(&ring_buf[start],data,first);
                    std::memcpy(&ring_buf[0], data + first, len-first);
                }else{
                     std::memcpy(&ring_buf[start], data, len);
                }

            }


            AETHON_ALWAYS_INLINE void read_ring_buffer(size_t start, uint8_t * __restrict__ out, size_t len) const noexcept {
                start &= 0xFFFF;
                AETHON_BUILTIN_PREFETCH(&ring_buf[start], 0, 3);
                if (AETHON_UNLIKELY(start + len > AETHON_TCP_WINDOW_SIZE)) {
                    size_t first = AETHON_TCP_WINDOW_SIZE - start;
                    std::memcpy(out, &ring_buf[start], first);
                    std::memcpy(out + first, &ring_buf[0], len - first);
                } else {
                    std::memcpy(out, &ring_buf[start], len);
                }
            }

            
            AETHON_ALWAYS_INLINE void set_bitmap_range(size_t start, size_t count) noexcept{
                start&=0xFFFF;
                while (count>0) {
                    size_t word_idx = start >> 6; // divide by 64
                    size_t bit_offset = start & 63; // % 64

                    size_t bits_in_word =64 - bit_offset;

                    size_t n = (count < bits_in_word) ? count : bits_in_word;

                    uint64_t mask = (n == 64) ? ~0ULL : ((1ULL << n) - 1ULL);
                    bitmap[word_idx]|= (mask << bit_offset);
                    start = (start + n) & 0xFFFF;
                    count-=n;
                }
            }

              AETHON_ALWAYS_INLINE void clear_bitmap_range(size_t start, size_t count) noexcept {
                start &= 0xFFFF;
                while (count > 0) {
                    size_t word_idx = start >> 6;
                    size_t bit_offset = start & 63;
                    size_t bits_in_word = 64 - bit_offset;
                    size_t n = (count < bits_in_word) ? count : bits_in_word;
                    uint64_t mask = (n == 64) ? ~0ULL : ((1ULL << n) - 1ULL);
                    bitmap[word_idx] &= ~(mask << bit_offset);
                    start = (start + n) & 0xFFFF;
                    count -= n;
                }
            }

            AETHON_ALWAYS_INLINE bool is_range_set(size_t start, size_t count) const noexcept {
                if (!bitmap || count == 0) return false;
                start &= 0xFFFF;
                while (count > 0) {
                    size_t word_idx = start >> 6;
                    size_t bit_offset = start & 63;
                    size_t bits_in_word = 64 - bit_offset;
                    size_t n = (count < bits_in_word) ? count : bits_in_word;
                    uint64_t mask = (n == 64) ? ~0ULL : ((1ULL << n) - 1ULL);
                    if ((bitmap[word_idx] & (mask << bit_offset)) != 0) {
                        return true;
                    }
                    start = (start + n) & 0xFFFF;
                    count -= n;
                }
                return false;
            }


            AETHON_ALWAYS_INLINE size_t count_continuous_bytes(uint32_t start_seq, size_t max_bytes) const noexcept{
                size_t assembled = 0;
                while (assembled < max_bytes) {
                    size_t idx = (start_seq + assembled) & 0xFFFF;
                    size_t word_idx = idx>>6;
                    size_t bit_offset = idx & 63;

                    uint64_t word  = bitmap[word_idx]  >> bit_offset;
                    
                    // hole
                    if((word & 1ULL) ==0){
                        break; 
                    }

                    uint64_t inverted = ~word;

                    size_t contiguous = (inverted == 0 ) ? (64 - bit_offset) : static_cast<size_t>(__builtin_ctzll(inverted));
                    size_t available_in_word = 64 - bit_offset;

                    if(contiguous > available_in_word){
                        contiguous = available_in_word;
                    }

                    if(assembled + contiguous > max_bytes){
                        contiguous = max_bytes - assembled;
                    }

                    assembled+=contiguous;

                    if(contiguous < available_in_word){
                        break;
                    }
                }

                return assembled;
            }


        };


        class alignas(implementation::hardware_destructive_interference_size)
        TcpAssemblerEngine{
            private:
                 using SessionMap = aethon::SingleThreadHashMap<TcpKey, TcpStreamSession*, KemptyTcpKey, TcpKeyHasher>;

                 SessionMap sessions_{AETHON_MAX_ACTIVE_TCP_SESSION * 2};
                 // we copy and fallten that assembled data out of the ring buffer
                 alignas(implementation::hardware_destructive_interference_size) std::array<uint8_t, AETHON_TCP_WINDOW_SIZE> drain_buf_{};

                 uint64_t last_cleanup_ns_{0};

            public:
                TcpAssemblerEngine () = default;

                ~TcpAssemblerEngine(){

                }

                TcpAssemblerEngine (const TcpAssemblerEngine&) = delete;
                TcpAssemblerEngine &operator=(const TcpAssemblerEngine &) = delete;

                template <typename Fn>
                void for_each_session(Fn &&fn) noexcept {
                    for (size_t i = 0; i < sessions_.capacity(); ++i) {
                        auto *cell = &sessions_.cells()[i];
                        if (cell->key != KemptyTcpKey && cell->val) {
                            fn(cell->val);
                        }
                    }
                }

                void clear() noexcept{
                    for(size_t i = 0; i< sessions_.capacity(); i++){
                        auto *cell = &sessions_.cells()[i];
                        if(cell->key != KemptyTcpKey){
                            delete cell->val;
                            cell->val = nullptr;
                            cell->key = KemptyTcpKey;
                        }
                    }
                }

            void purged_expired(uint64_t now_ns) noexcept {
                for (size_t i = 0; i < sessions_.capacity(); ++i) {
                    AETHON_BUILTIN_PREFETCH(&sessions_.cells()[i], 0, 1);
                    auto *cell = &sessions_.cells()[i];
                    if (cell->key != KemptyTcpKey) {
                        TcpStreamSession *session = cell->val;
                        if (session) {
                            uint64_t age = now_ns - session->last_seen_ns;
                            bool is_expired = (session->state == TcpState::SYN_SENT)
                                                  ? (age > AETHON_TCP_SYN_TIMEOUT_NS)
                                                  : (age > AETHON_TCP_ESTAB_TIMEOUT_NS);
                            if (AETHON_UNLIKELY(is_expired)) {
                                TcpKey stale_key = cell->key;
                                delete session;
                                sessions_.erase(stale_key);
                            }
                        }
                    }
                }
            }

            void close_session(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) noexcept {
                TcpKey key;
                key.src_ip = src_ip;
                key.dst_ip = dst_ip;
                key.src_port = src_port;
                key.dst_port = dst_port;
                TcpStreamSession **slot = sessions_.find(key);
                if (slot && *slot) {
                    delete *slot;
                    sessions_.erase(key);
                }
            }

            // process packet

            AETHON_ALWAYS_INLINE TcpAssemblyResult process_packet(
                const struct iphdr * __restrict__ iph,
                const struct tcphdr * __restrict__ tcph,
                const uint8_t * __restrict__ payload,
                uint16_t payload_len,
                uint64_t now_ns
            ) noexcept{
                TcpAssemblyResult result;
                AETHON_BUILTIN_PREFETCH(iph, 0, 3);
                AETHON_BUILTIN_PREFETCH(tcph, 0, 3);
                if (payload_len > 0) {
                    AETHON_BUILTIN_PREFETCH(payload, 0, 3);
                }


                /*
                    Out of those 2,000,000 packets in 1 second 
                    Exactly 1 single packet will trigger the 1-second cleanup.
                */
                if(AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(now_ns - last_cleanup_ns_ > 1000000000ULL, 0, 0.999999)){
                    purged_expired(now_ns);
                    last_cleanup_ns_ =now_ns;
                }


                TcpKey key;
                
                key.src_ip   = iph->saddr;
                key.dst_ip   = iph->daddr;
                key.src_port = tcph->source;
                key.dst_port = tcph->dest;
                result.src_port = ntohs(tcph->source);
                result.dst_port = ntohs(tcph->dest);

                const uint8_t flags = reinterpret_cast<const uint8_t *>(tcph)[13];
                const uint32_t seq   = ntohl(tcph->seq);

                if (AETHON_UNLIKELY((flags & TH_SYN) && !(flags & TH_ACK) && sessions_.size() >= AETHON_MAX_ACTIVE_TCP_SESSION)) {
                    return result;
                }

                TcpStreamSession **slot = sessions_.find(key);
                TcpStreamSession *session = nullptr;

                if(AETHON_LIKELY(slot != nullptr)){
                    session = *slot;
                    AETHON_BUILTIN_PREFETCH(session, 1, 3);
                    result.session = session;
                }else{
                    // if NON SYN Packet DROP
                    if(AETHON_UNLIKELY(!(flags & TH_SYN))){
                        return result;
                    }

                    // table capacity defence

                    if(AETHON_UNLIKELY(sessions_.size() >= AETHON_MAX_ACTIVE_TCP_SESSION)){
                        return result;
                    }

                    // light weight session allocation only 64 bytes

                    session = new (std::nothrow) TcpStreamSession();
                    if(AETHON_UNLIKELY(!session)){
                        return result;
                    }

                    session->key = key;
                    session->isn = seq;
                    session->rcv_nxt = seq + 1;

                    session->state = TcpState::SYN_SENT;

                    session->last_seen_ns = now_ns;

                    parse_tcp_syn_option(tcph, session->params);

                     sessions_.insert(key, session);
                    result.session = session;
                    result.is_syn = true;
                    return result;
                }

                session->last_seen_ns = now_ns;

                // RST --> connection killed by the sender
                if(AETHON_UNLIKELY(flags & TH_RST)){
                    session->state = TcpState::CLOSED;
                    result.is_closed = true;
                    delete session;
                    sessions_.erase(key);
                    result.session = nullptr;
                    return result;
                }

                // SYN Retransmission: Duplicate handshake packer

                if(AETHON_UNLIKELY(flags & TH_SYN)){
                    result.is_syn = true;
                    return result;
                }


                // Transition: First packet after SYN moves session to ESTABLISHED
                if (AETHON_UNLIKELY(session->state == TcpState::SYN_SENT)) {
                    if (AETHON_LIKELY(flags & TH_ACK)) {
                        session->state = TcpState::ESTABLISHED;
                    } else {
                        return result;
                    }
                }

                // If connection is not ESTABLISHED, ignore data
                if (AETHON_UNLIKELY(session->state != TcpState::ESTABLISHED)) {
                    return result;
                }

                // Process client ACKs on established connections to slide outbound send window
                if (AETHON_LIKELY(flags & TH_ACK)) {

                    session->snd_wnd = static_cast<uint32_t>(ntohs(tcph->window)) << session->params.wscale;

                    uint32_t ack_seq = ntohl(tcph->ack_seq);
                    if (TcpSeq::gt(ack_seq, session->snd_una) && TcpSeq::lte(ack_seq, session->send_nxt)) {
                        size_t bytes_acked = ack_seq - session->snd_una;
                        if (bytes_acked <= session->snd_buf.size()) {
                            session->snd_buf.erase(session->snd_buf.begin(), session->snd_buf.begin() + bytes_acked);
                        } else {
                            session->snd_buf.clear();
                        }

                        session->snd_una = ack_seq;
                        session->cc.on_ack(bytes_acked);
                        // Successful ACK: reset RTO timer and retry counter
                        session->rto_ms = 200;
                        session->retransmit_count = 0;
                        session->dup_ack_count = 0;
                        session->last_tx_time_ns = now_ns;
                    } else if (ack_seq == session->snd_una && session->snd_una != session->send_nxt && payload_len == 0) {
                        // RFC 5681: Fast Retransmit on 3 duplicate ACKs
                        session->dup_ack_count++;
                        if (session->dup_ack_count == 3) {
                            session->cc.on_fast_retransmit();
                            result.fast_retransmit = true;
                        }
                    }
                }

                // process data payload

                if(AETHON_LIKELY(payload_len > 0)){
                    uint32_t cur_seq = seq;
                    const uint8_t * cur_payload = payload;
                    uint16_t cur_len = payload_len;

                    // protect against spoofed out -of -window-sequences

                    if(AETHON_UNLIKELY(TcpSeq::diff(cur_seq, session->rcv_nxt) + cur_len > AETHON_TCP_WINDOW_SIZE)){
                        return result;
                    }

                    // packet completelybehinf rcv_nxt

                    if(AETHON_UNLIKELY(TcpSeq::lte(cur_seq+cur_len,session->rcv_nxt))){
                        result.need_ack = true;
                        return result; 
                    }

                    // partial overlap Packet starts before rcv_nxt , but end after rcv_nxt

                    if(AETHON_UNLIKELY(TcpSeq::lt(cur_seq, session->rcv_nxt))){
                        uint32_t trim = session->rcv_nxt - cur_seq;
                        cur_payload  += trim;
                        cur_len      -= trim;
                        cur_seq       = session->rcv_nxt;
                    }

                    // In-order packet (packet matches rcv_nxt AND there are no out-of-order packets waiting)

                    if(AETHON_LIKELY(cur_seq == session->rcv_nxt && session->out_of_order_count ==0)){
                        result.payload     = cur_payload;
                        result.payload_len = cur_len;
                        result.is_ready    = true;
                        session->rcv_nxt  += cur_len;
                        // our of order packets (gap/hole in the sequence)
                    }else if(TcpSeq::gt(cur_seq, session->rcv_nxt)){

                        if(AETHON_LIKELY(session->init_bufferes())){
                            if (session->is_range_set(cur_seq, cur_len)) {
                                uint8_t existing[1500];
                                size_t check_len = (cur_len < sizeof(existing)) ? cur_len : sizeof(existing);
                                session->read_ring_buffer(cur_seq, existing, check_len);
                                if (std::memcmp(existing, cur_payload, check_len) != 0) {
                                    result.is_closed = true;
                                    delete session;
                                    sessions_.erase(key);
                                    result.session = nullptr;
                                    return result;
                                }
                            }
                            session->write_ring_buffer(cur_seq, cur_payload, cur_len);
                            session->set_bitmap_range(cur_seq, cur_len);
                            session->out_of_order_count++;
                        }
                    }

                    // gap - filler packet (fills the missing hole at rcv_nxt)
                    else{
                        if(AETHON_LIKELY(session->init_bufferes())){
                            if (session->is_range_set(cur_seq, cur_len)) {
                                uint8_t existing[1500];
                                size_t check_len = (cur_len < sizeof(existing)) ? cur_len : sizeof(existing);
                                session->read_ring_buffer(cur_seq, existing, check_len);
                                if (std::memcmp(existing, cur_payload, check_len) != 0) {
                                    result.is_closed = true;
                                    delete session;
                                    sessions_.erase(key);
                                    result.session = nullptr;
                                    return result;
                                }
                            }
                            session->write_ring_buffer(cur_seq, cur_payload, cur_len);
                            session->set_bitmap_range(cur_seq, cur_len);

                            // drain all continuous bytes starting at rcv_next
                            size_t contiguous = session->count_continuous_bytes(session->rcv_nxt, AETHON_TCP_WINDOW_SIZE);

                            if(AETHON_LIKELY(contiguous >0 )){

                                session->read_ring_buffer(session->rcv_nxt, drain_buf_.data(), contiguous);
                                session->clear_bitmap_range(session->rcv_nxt, contiguous);

                                session->rcv_nxt += contiguous;

                                result.payload = drain_buf_.data();
                                result.payload_len = contiguous;
                                result.is_ready = true;

                                if(session->out_of_order_count > 0){
                                    session->out_of_order_count --;
                                }
                            }
                        }
                    }

                } // end
                

                if(AETHON_UNLIKELY(flags & TH_FIN)){
                    session->rcv_nxt++;
                    session->state = TcpState::CLOSING;
                    result.is_closed = true;
                }

                return result;

            }



        };

    };


};










































