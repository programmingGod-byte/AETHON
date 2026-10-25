#pragma once

#include "aethon/aethon.h"
#include "af_xdp_header.h"
#include <algorithm>
#include <cstring>
#include <liburing.h>
#include <vector>
#include <sys/epoll.h>

#ifndef AETHON_ALWAYS_INLINE
#if defined(__GNUC__) || defined(__clang__)
#define AETHON_ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
#define AETHON_ALWAYS_INLINE inline
#endif
#endif

#include "tcp_assembler.h"
#include "hyper_scan_engine.h"
#include "packet_injector.h"
#include <cstddef>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstdint>
#include <iostream>
#include <sys/types.h>
#include <random>
#include "tls_engine.h"
#include "tls_parser.h"
#include "domain_blocklist.h"
#include "aethon/single_thread_hasmap.h"
#include <chrono>
#include "service_registry.h"

namespace aethon {
namespace pipeline {
    static constexpr size_t MAX_JA3_IPS = 65536;
    struct rate_lim_ja3{
        uint16_t tokens{0};
        uint64_t last_updated{0};
        uint16_t limit{10};
        uint64_t window{10};
    };
    struct ja3_ips{
        uint32_t ips[MAX_JA3_IPS]{};
        struct rate_lim_ja3 rate_lim{};
        int offset{0};
    };
    using JA3_map = aethon::SingleThreadHashMap<aethon::tls::JA3, struct ja3_ips>;
    inline JA3_map g_ja3_map{1024};
    inline JA3_map* ja3_map{&g_ja3_map};
    AETHON_ALWAYS_INLINE void print_ip(uint32_t ip) noexcept {
        char buf[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = ip;
        if (inet_ntop(AF_INET, &addr, buf, sizeof(buf))) {
            std::cout << buf;
        } else {
            std::cout << "unknown";
        }
    }

    AETHON_ALWAYS_INLINE static uint32_t generate_random_isn() noexcept {
        // RFC 6528 / RFC 9293: Cryptographically unpredictable Initial Sequence Number
        // Defends against off-path blind TCP injection, connection spoofing, and RST attacks.
        thread_local std::mt19937_64 rng([]() {
            std::random_device rd;
            return (static_cast<uint64_t>(rd()) << 32) ^ rd() ^
                   static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count());
        }());
        uint32_t val = static_cast<uint32_t>(rng());
        return (val == 0) ? 1 : val; // Ensure non-zero ISN
    }

    inline dns::DomainBlocklist g_domain_blocklist;
    inline service::ServiceRegistry g_service_registry;

    AETHON_ALWAYS_INLINE bool send_tcp_segmented_data(
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        IPv4TcpAssembler::TcpStreamSession * __restrict__ session,
        const uint8_t * __restrict__ data,
        size_t len,
        std::vector<uint64_t> &tx_pool
    ) noexcept {
        if (AETHON_UNLIKELY(!sock || !session)) {
            return false;
        }

        // if new data append to the snd_buf

        if(data && len > 0){
            if(session->snd_buf.size() + len > session->MAX_SND_BUF){
                return false; // buffer full
            }

            session->snd_buf.insert(session->snd_buf.end(),data,data  + len);
        }

        constexpr size_t AETHON_MSS = 1460;
        size_t sent_offset = session->send_nxt - session->snd_una;

        while (sent_offset < session->snd_buf.size()) {
            if(AETHON_UNLIKELY(tx_pool.empty())){
                break;
            }

            // Combined Flow Control (snd_wnd) and Congestion Control (cwnd)
            size_t in_flight = session->send_nxt - session->snd_una;
            size_t allowed = session->cc.allowed_to_send(in_flight, session->snd_wnd);
            if (allowed == 0) {
                break;
            }

            size_t chunk_len = std::min({session->snd_buf.size() - sent_offset, AETHON_MSS, allowed});
            uint64_t tx_buf_addr = tx_pool.back();
            tx_pool.pop_back();
            uint8_t *pkt = reinterpret_cast<uint8_t *>(xsk_umem__get_data(sock->umen->buffer, tx_buf_addr));
            AETHON_BUILTIN_PREFETCH(pkt, 1, 3);
            // Send the chunk from snd_buf:
            bool sent = net::PacketInjector::ipv4_send_tcp_data(
                sock, tx_buf_addr, pkt,
                session->client_mac, session->server_mac,
                session->key.src_ip, session->key.dst_ip,
                session->key.src_port, session->key.dst_port,
                session->send_nxt, session->rcv_nxt,
                session->snd_buf.data() + sent_offset, chunk_len, // <-- data from snd_buf!
                session->recv_window());
            if (AETHON_LIKELY(sent)) {
                uint64_t tx_now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                // Karn's algorithm: sample RTT on outbound data when not retransmitting
                if (session->rtt_time_ns == 0 && session->retransmit_count == 0) {
                    session->rtt_seq = session->send_nxt + chunk_len;
                    session->rtt_time_ns = tx_now_ns;
                }
                session->send_nxt += chunk_len;
                sent_offset += chunk_len;
                // Record timestamp for RTO timer:
                session->last_tx_time_ns = tx_now_ns;
            } else {
                tx_pool.push_back(tx_buf_addr);
                break;
            }
        
        }

        
        return (sent_offset == session->snd_buf.size());
    }

    AETHON_ALWAYS_INLINE bool retransmit_unacked_data(
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        IPv4TcpAssembler::TcpStreamSession * __restrict__ session,
        std::vector<uint64_t> &tx_pool,
        size_t max_packets = 10,
        bool is_rto = true
    ) noexcept {
        if (!sock || !session || session->snd_buf.empty() || tx_pool.empty()) {
            return false;
        }

        constexpr size_t AETHON_MSS = 1460;
        size_t in_flight = session->send_nxt - session->snd_una;
        if (in_flight == 0) return false;

        // Issue #9: Go-Back-N burst retransmission of up to max_packets (default 10) segments
        size_t to_retransmit = std::min({in_flight, session->snd_buf.size(), max_packets * AETHON_MSS});
        size_t retrans_offset = 0;
        uint32_t packets_sent = 0;

        while (retrans_offset < to_retransmit && !tx_pool.empty()) {
            size_t chunk_len = std::min(to_retransmit - retrans_offset, AETHON_MSS);
            uint64_t tx_buf_addr = tx_pool.back();
            tx_pool.pop_back();

            uint8_t *pkt = reinterpret_cast<uint8_t *>(xsk_umem__get_data(sock->umen->buffer, tx_buf_addr));
            AETHON_BUILTIN_PREFETCH(pkt, 1, 3);

            uint32_t seq = session->snd_una + static_cast<uint32_t>(retrans_offset);
            bool sent = net::PacketInjector::ipv4_send_tcp_data(
                sock, tx_buf_addr, pkt,
                session->client_mac, session->server_mac,
                session->key.src_ip, session->key.dst_ip,
                session->key.src_port, session->key.dst_port,
                seq, session->rcv_nxt,
                session->snd_buf.data() + retrans_offset, chunk_len,
                session->recv_window());

            if (AETHON_LIKELY(sent)) {
                retrans_offset += chunk_len;
                packets_sent++;
            } else {
                tx_pool.push_back(tx_buf_addr);
                break;
            }
        }

        if (packets_sent > 0) {
            session->last_tx_time_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            // Karn's algorithm: Invalidate pending RTT sample upon retransmission
            session->rtt_time_ns = 0;
            if (is_rto) {
                // Issue #8: Exponential backoff doubling RTO up to 60,000 ms (60 seconds, RFC 6298)
                session->rto_ms = std::min(session->rto_ms * 2, 60000u);
                session->retransmit_count++;
            }
            return true;
        }

        return false;
    }

    template <typename Scanner>
    AETHON_ALWAYS_INLINE bool handle_tcp_packet(
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        uint64_t buf_addr,
        uint8_t * __restrict__ pkt,
        const struct ether_header * __restrict__ eth,
        const struct iphdr * __restrict__ iph,
        size_t ip_pkt_len,
        uint64_t now_ns,
        IPv4TcpAssembler::TcpAssemblerEngine & __restrict__ tcp_engine,
        Scanner & __restrict__ scanner,
        std::vector<uint64_t>&tx_pool ,
    int epfd) noexcept
    {
        const size_t ip_hdr_len = iph->ihl * 4;

        if (AETHON_UNLIKELY(ip_pkt_len < ip_hdr_len + sizeof(struct tcphdr))) {
            return false;
        }

        const auto * __restrict__ tcph = reinterpret_cast<const struct tcphdr *>(
            reinterpret_cast<const uint8_t *>(iph) + ip_hdr_len);

        const size_t tcp_hdr_len = tcph->doff * 4;

        if (AETHON_UNLIKELY(tcp_hdr_len < sizeof(struct tcphdr) || ip_pkt_len < ip_hdr_len + tcp_hdr_len)) {
            return false;
        }

        const uint16_t total_ip_len = ntohs(iph->tot_len);
        if (AETHON_UNLIKELY(total_ip_len < ip_hdr_len + tcp_hdr_len)) {
            return false;
        }

        const uint16_t payload_len = total_ip_len - ip_hdr_len - tcp_hdr_len;
        const uint8_t * __restrict__ payload = reinterpret_cast<const uint8_t *>(tcph) + tcp_hdr_len;

        IPv4TcpAssembler::TcpAssemblyResult res = tcp_engine.process_packet(
            iph, tcph, payload, payload_len, now_ns);

        if (AETHON_UNLIKELY(res.fast_retransmit && res.session)) {
            // RFC 5681: Fast Retransmit sends single lost segment at snd_una without RTO backoff
            retransmit_unacked_data(sock, res.session, tx_pool, 1, false);
        }

        if(AETHON_UNLIKELY(res.is_syn && res.session)){
            std::memcpy(res.session->client_mac,eth->ether_shost,6);
            std::memcpy(res.session->server_mac, eth->ether_dhost, 6);

            // RFC 6528: Only generate a new randomized ISN if this is a fresh handshake (server_isn == 0).
            // Retransmitted SYNs in SYN_SENT state reuse the existing server_isn without resetting sequence numbers!
            if (res.session->server_isn == 0) {
                res.session->server_isn = generate_random_isn();
                res.session->send_nxt = res.session->server_isn + 1;
                res.session->snd_una = res.session->server_isn + 1;
            }
            // RFC 6298: Record timestamp of SYN-ACK transmission for initial handshake RTT measurement
            res.session->synack_tx_time_ns = now_ns;

            return net::PacketInjector::ipv4_send_tcp_syn_ack(
                sock, buf_addr, pkt, eth, iph, tcph, res.session->server_isn, ntohl(tcph->seq));
        }
        

        if(AETHON_UNLIKELY(res.need_ack && res.session)){
            return net::PacketInjector::ipv4_send_tcp_ack(
                sock, buf_addr, pkt, eth, iph, tcph, res.session->send_nxt, res.session->rcv_nxt, res.session->recv_window());
        }

        // Outbound Pump: If client ACKed data on established session, pump any remaining unsent snd_buf
        if (res.session && res.session->state == IPv4TcpAssembler::TcpState::ESTABLISHED) {
            if (!res.session->snd_buf.empty()) {
                send_tcp_segmented_data(sock, res.session, nullptr, 0, tx_pool);
            }

            // If backend closed earlier and client has now acknowledged all data, send FIN and close
            if (res.session->fin_pending && res.session->snd_buf.empty() && res.session->snd_una == res.session->send_nxt) {
                bool sent = net::PacketInjector::ipv4_send_tcp_fin(
                    sock, buf_addr, pkt,
                    eth->ether_shost, eth->ether_dhost,
                    iph->saddr, iph->daddr,
                    tcph->source, tcph->dest,
                    res.session->send_nxt, res.session->rcv_nxt,
                    res.session->recv_window());
                tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                return sent;
            }
        }


        if (AETHON_LIKELY(res.is_ready && res.payload_len > 0)) {
            const uint8_t * hello_data = res.payload;
            size_t hello_len = res.payload_len;

            // RFC 8446 limits the maximum TLS record payload to 2^14 (16384) bytes + 5-byte header.
            static constexpr size_t MAX_CLIENT_HELLO = 16384 + 5;

            // Handle multi-segment ClientHello (e.g., Chrome with post-quantum keys > 1460 bytes MTU)
            if(res.session && res.session->tls_conn.status() == tls::TlsSessionStatus::IDLE){
                // Check if an accumulation is already in progress or if this packet starts a TLS ClientHello
                if (!res.session->client_hello_buf.empty() || 
                    (res.payload_len >= 6 && res.payload[0] == 0x16 && res.payload[5] == 0x01)) {

                    // Reject connections exceeding maximum allowable TLS record size
                    if (AETHON_UNLIKELY(res.session->client_hello_buf.size() + res.payload_len > MAX_CLIENT_HELLO)) {
                        res.session->client_hello_buf.clear();
                        tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                        return net::PacketInjector::ipv4_send_tcp_rst(
                            sock, buf_addr, pkt, eth, iph, tcph, payload_len);
                    }

                    res.session->client_hello_buf.insert(
                        res.session->client_hello_buf.end(), res.payload, res.payload + res.payload_len);
                    hello_data = res.session->client_hello_buf.data();
                    hello_len = res.session->client_hello_buf.size();

                    // Read 5-byte TLS record header (length at bytes 3-4) to verify full record arrival
                    if (hello_len >= 5) {
                        uint16_t rec_len = (static_cast<uint16_t>(hello_data[3]) << 8) | hello_data[4];
                        if (AETHON_UNLIKELY(rec_len > 16384)) {
                            // Malformed TLS record length exceeding RFC limit; abort connection
                            res.session->client_hello_buf.clear();
                            tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                            return net::PacketInjector::ipv4_send_tcp_rst(
                                sock, buf_addr, pkt, eth, iph, tcph, payload_len);
                        }
                        // If record is incomplete, ACK this segment immediately with flow control window and wait for the rest
                        if (hello_len < 5 + static_cast<size_t>(rec_len)) {
                            return net::PacketInjector::ipv4_send_tcp_ack(
                                sock, buf_addr, pkt, eth, iph, tcph, res.session->send_nxt, res.session->rcv_nxt, res.session->recv_window());
                        }
                    }
                }
            }

            // Parse complete ClientHello to extract SNI and enforce domain policy
            auto tls_info = tls::parse_client_hello(hello_data, hello_len);
            bool exceed = false;
            if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(tls_info.is_client_hello, 1, 0.02)) {
                if (ja3_map && tls_info.ja3_str.curr_id > 0) {
                    auto *value = ja3_map->find(tls_info.ja3_str);
                    if (AETHON_UNLIKELY(value)) {
                        if (AETHON_LIKELY(value->offset < static_cast<int>(MAX_JA3_IPS))) {
                            value->ips[value->offset++] = iph->saddr;
                        }
                        const uint64_t window_ns = value->rate_lim.window * 1000000000ULL;
                        if (now_ns - value->rate_lim.last_updated > window_ns) {
                            value->rate_lim.last_updated = now_ns;
                            value->rate_lim.tokens = 1;
                        } else {
                            if (AETHON_UNLIKELY(value->rate_lim.tokens + 1 > value->rate_lim.limit)) {
                                exceed = true;
                                value->rate_lim.last_updated = now_ns;
                                value->rate_lim.tokens = 0;
                            } else {
                                value->rate_lim.tokens++;
                            }
                        }
                    } else {
                        struct ja3_ips new_ip_list{};
                        new_ip_list.ips[new_ip_list.offset++] = iph->saddr;
                        new_ip_list.rate_lim.tokens = 1;
                        new_ip_list.rate_lim.window = 10;
                        new_ip_list.rate_lim.limit = 10;
                        new_ip_list.rate_lim.last_updated = now_ns;
                        ja3_map->insert(tls_info.ja3_str, new_ip_list);
                    }
                }
                if (AETHON_UNLIKELY(exceed)) {
                    std::cout << "\n[IPS RATE-LIMIT] JA3 Fingerprint Limit Exceeded! Dropping ClientHello." << std::endl;
                    std::cout << "  Attacker : ";
                    print_ip(iph->saddr);
                    std::cout << ":" << ntohs(tcph->source) << std::endl;
                    std::cout << "  JA3      : " << tls_info.ja3() << std::endl;
                    return true;
                }
                if (AETHON_UNLIKELY(tls_info.sni.empty() || !g_domain_blocklist.is_allowed(tls_info.sni))) {
                    std::cout << "\n[IPS BLOCK] Unauthorized TLS Domain! SNI: " << (tls_info.sni.empty() ? "NONE" : tls_info.sni) << std::endl;
                    std::cout << "  Attacker : ";
                    print_ip(iph->saddr);
                    std::cout << ":" << ntohs(tcph->source) << std::endl;
                    std::cout << "  Target   : ";
                    print_ip(iph->daddr);
                    std::cout << ":" << ntohs(tcph->dest) << std::endl;

                    if (res.session) {
                        res.session->client_hello_buf.clear();
                    }
                    tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                    return net::PacketInjector::ipv4_send_tcp_rst(
                        sock, buf_addr, pkt, eth, iph, tcph, payload_len);
                }

                if (res.session) {
                    const auto * svc = g_service_registry.find_by_domain(tls_info.sni);
                    if (!svc) {
                        svc = g_service_registry.find_by_ip_port(iph->daddr, ntohs(tcph->dest));
                    }
                    if (svc && svc->ssl_ctx) {
                        res.session->tls_conn.init(svc->ssl_ctx);
                        res.session->backend_port = svc->backend_port;
                    }
                }

                if (res.session) {
                    std::memcpy(res.session->client_mac, eth->ether_shost, 6);
                    std::memcpy(res.session->server_mac, eth->ether_dhost, 6);
                }
            }
            if (res.session && res.session->tls_conn.status() != tls::TlsSessionStatus::IDLE) {
                // Feed the fully assembled ClientHello into OpenSSL and reclaim memory
                res.session->tls_conn.feed_network_data(hello_data, hello_len);
                res.session->client_hello_buf.clear();

                if (res.session->tls_conn.status() == tls::TlsSessionStatus::HANDSHAKE) {
                    res.session->tls_conn.step_handshake();
                    uint8_t tx_buf[20480];
                    int tx_len;
                    while ((tx_len = res.session->tls_conn.read_pending_tx(tx_buf, sizeof(tx_buf))) > 0) {
                        send_tcp_segmented_data(sock, res.session, tx_buf, static_cast<size_t>(tx_len), tx_pool);
                    }
                    if (res.session->tls_conn.status() == tls::TlsSessionStatus::HANDSHAKE) {
                        return false;
                    }
                }

                if (res.session->tls_conn.is_established()) {
                    bool any_decrypted = false;
                    uint8_t plain_buf[16384];
                    int plain_len;
                    while ((plain_len = res.session->tls_conn.decrypt(plain_buf, sizeof(plain_buf))) > 0) {
                        any_decrypted = true;
                        if (AETHON_UNLIKELY(res.session && !res.session->hs_stream)) {
                            res.session->hs_stream = scanner.open_stream();
                        }
                        bool attack_detected = (res.session && res.session->hs_stream)
                            ? scanner.scan_stream(res.session->hs_stream, plain_buf, plain_len)
                            : scanner.scan(plain_buf, plain_len);
                        if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(attack_detected, 1, 0.0001)) {
                            std::cout << "\n[IPS BLOCK] Malicious Decrypted TLS Payload Dropped!" << std::endl;
                            std::cout << "  Attacker : ";
                            print_ip(iph->saddr);
                            std::cout << ":" << ntohs(tcph->source) << std::endl;
                            std::cout << "  Target   : ";
                            print_ip(iph->daddr);
                            std::cout << ":" << ntohs(tcph->dest) << std::endl;

                            tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                            return net::PacketInjector::ipv4_send_tcp_rst(
                                sock, buf_addr, pkt, eth, iph, tcph, payload_len);
                        }else{
                            uint16_t target_port = res.session->backend_port;
                            if(target_port == 0){
                                const auto *svc = g_service_registry.find_by_ip_port(iph->daddr, ntohs(tcph->dest));
                                if(svc) target_port = svc->backend_port;
                            }
                            if(target_port > 0){
                                int prev_fd = res.session->backend_fd;
                                //  Protect against unbounded memory growth in backend_tx_buf (CWE-400 / CWE-770)
                                if (AETHON_UNLIKELY(!res.session->forward_to_backend(plain_buf, plain_len, target_port))) {
                                    tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                                    return net::PacketInjector::ipv4_send_tcp_rst(
                                        sock, buf_addr, pkt, eth, iph, tcph, payload_len);
                                }
                                if(AETHON_LIKELY(epfd >= 0 && res.session->backend_fd >= 0)){
                                    if (prev_fd != res.session->backend_fd) {
                                        // Socket was freshly connected: register with epoll
                                        struct epoll_event ev{};
                                        uint32_t ev_mask = EPOLLIN | EPOLLRDHUP;
                                        if (!res.session->backend_tx_buf.empty()) {
                                            ev_mask |= EPOLLOUT;
                                        }
                                        ev.events = ev_mask;
                                        ev.data.ptr = res.session;
                                        epoll_ctl(epfd, EPOLL_CTL_ADD, res.session->backend_fd, &ev);
                                        res.session->epollout_armed = !res.session->backend_tx_buf.empty();
                                    } else if (!res.session->backend_tx_buf.empty() && !res.session->epollout_armed) {
                                        // Data is buffered and EPOLLOUT is not active: arm EPOLLOUT!
                                        struct epoll_event ev{};
                                        ev.events = EPOLLIN | EPOLLRDHUP | EPOLLOUT;
                                        ev.data.ptr = res.session;
                                        epoll_ctl(epfd, EPOLL_CTL_MOD, res.session->backend_fd, &ev);
                                        res.session->epollout_armed = true;
                                    }
                                }
                            }
                        }
                    }

                    if (any_decrypted) {
                        return net::PacketInjector::ipv4_send_tcp_ack(
                            sock, buf_addr, pkt, eth, iph, tcph, res.session->send_nxt, res.session->rcv_nxt, res.session->recv_window());
                    }
                }

                if (AETHON_LIKELY(res.session && res.session->backend_fd >= 0)) {
                    uint8_t resp_buf[16384];
                    ssize_t resp_len = res.session->read_from_backend(resp_buf, sizeof(resp_buf));
                    if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(resp_len > 0, 1, 0.90)) {
                        res.session->tls_conn.encrypt(resp_buf, static_cast<size_t>(resp_len));
                        uint8_t enc_tx[20480];
                        int enc_len;
                        while ((enc_len = res.session->tls_conn.read_pending_tx(enc_tx, sizeof(enc_tx))) > 0) {
                            send_tcp_segmented_data(sock, res.session, enc_tx, static_cast<size_t>(enc_len), tx_pool);
                        }
                    }
                }
            } else {
                if (AETHON_UNLIKELY(res.session && !res.session->hs_stream)) {
                    res.session->hs_stream = scanner.open_stream();
                }
                // Forward and scan full assembled hello_data / hello_len (covers multi-segment ClientHello for plain/passthrough)
                bool attack_detected = (res.session && res.session->hs_stream)
                    ? scanner.scan_stream(res.session->hs_stream, hello_data, hello_len)
                    : scanner.scan(hello_data, hello_len);
                if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(attack_detected, 1, 0.0001)) {
                    std::cout << "\n[IPS BLOCK] Malicious TCP Packet Dropped!" << std::endl;
                    std::cout << "  Attacker : ";
                    print_ip(iph->saddr);
                    std::cout << ":" << ntohs(tcph->source) << std::endl;
                    std::cout << "  Target   : ";
                    print_ip(iph->daddr);
                    std::cout << ":" << ntohs(tcph->dest) << std::endl;

                    if (res.session) {
                        res.session->client_hello_buf.clear();
                    }
                    tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                    return net::PacketInjector::ipv4_send_tcp_rst(
                        sock, buf_addr, pkt, eth, iph, tcph, payload_len);
                }else{
                    uint16_t target_port = res.session ? res.session->backend_port : 0;
                    if(target_port == 0){
                        const auto *svc =g_service_registry.find_by_ip_port(iph->daddr, ntohs(tcph->dest));
                        if(svc) target_port = svc->backend_port;
                    }

                    if(target_port > 0 && res.session){
                        int prev_fd = res.session->backend_fd;
                        // Bug A fix: Protect against unbounded memory growth in backend_tx_buf (CWE-400 / CWE-770)
                        if (AETHON_UNLIKELY(!res.session->forward_to_backend(hello_data, hello_len, target_port))) {
                            res.session->client_hello_buf.clear();
                            tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                            return net::PacketInjector::ipv4_send_tcp_rst(
                                sock, buf_addr, pkt, eth, iph, tcph, payload_len);
                        }

                        // Bug 2 fix: Now that full assembled hello_data has been forwarded, clear client_hello_buf
                        res.session->client_hello_buf.clear();

                        if(AETHON_LIKELY(epfd >= 0 && res.session->backend_fd >= 0)){
                            if (prev_fd != res.session->backend_fd) {
                                // Socket was freshly connected: register with epoll
                                struct epoll_event ev{};
                                uint32_t ev_mask = EPOLLIN | EPOLLRDHUP;
                                if (!res.session->backend_tx_buf.empty()) {
                                    ev_mask |= EPOLLOUT;
                                }
                                ev.events = ev_mask;
                                ev.data.ptr = res.session;
                                epoll_ctl(epfd, EPOLL_CTL_ADD, res.session->backend_fd, &ev);
                                res.session->epollout_armed = !res.session->backend_tx_buf.empty();
                            } else if (!res.session->backend_tx_buf.empty() && !res.session->epollout_armed) {
                                // Data is buffered and EPOLLOUT is not active: arm EPOLLOUT!
                                struct epoll_event ev{};
                                ev.events = EPOLLIN | EPOLLRDHUP | EPOLLOUT;
                                ev.data.ptr = res.session;
                                epoll_ctl(epfd, EPOLL_CTL_MOD, res.session->backend_fd, &ev);
                                res.session->epollout_armed = true;
                            }
                        }
                        
                        return net::PacketInjector::ipv4_send_tcp_ack(
                            sock, buf_addr, pkt, eth, iph, tcph, res.session->send_nxt, res.session->rcv_nxt, res.session->recv_window());
                    } else if (res.session) {
                        res.session->client_hello_buf.clear();
                    }
                }
            }
        }

        if (AETHON_UNLIKELY(res.is_closed)) {
            if (res.session) {
                if (res.session->backend_fd >= 0) {
                    epoll_ctl(epfd, EPOLL_CTL_DEL, res.session->backend_fd, nullptr);
                    ::close(res.session->backend_fd);
                    res.session->backend_fd = -1;
                }

                bool sent = net::PacketInjector::ipv4_send_tcp_fin(
                    sock, buf_addr, pkt,
                    eth->ether_shost, eth->ether_dhost,
                    iph->saddr, iph->daddr,
                    tcph->source, tcph->dest,
                    res.session->send_nxt, res.session->rcv_nxt,
                    res.session->recv_window());

                tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                return sent;
            }

            tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
        }

        return false;
    }

    
    AETHON_ALWAYS_INLINE uint32_t check_tcp_retransmissions(
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        std::vector<uint64_t> &tx_pool,
        IPv4TcpAssembler::TcpAssemblerEngine &tcp_engine
    ) noexcept {
        // Issue #10: thread_local prevents cross-thread data race and worker starvation
        thread_local uint64_t last_rto_sweep_ns = 0;
        uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();

        // RTO Sweep: Check once every 100 ms across active TCP sessions
        if (AETHON_LIKELY(now_ns - last_rto_sweep_ns < 100000000ULL)) {
            return 0;
        }
        last_rto_sweep_ns = now_ns;

        constexpr uint8_t MAX_TCP_RETRIES = 8;
        uint32_t retransmitted = 0;
        tcp_engine.for_each_session([&](IPv4TcpAssembler::TcpStreamSession *session) {
            if (session && session->state == IPv4TcpAssembler::TcpState::ESTABLISHED) {
                // Check if session has unacknowledged in-flight data
                if (session->snd_una != session->send_nxt && !session->snd_buf.empty()) {
                    uint64_t rto_ns = static_cast<uint64_t>(session->rto_ms) * 1000000ULL;
                    if (now_ns - session->last_tx_time_ns > rto_ns) {
                        if (session->retransmit_count >= MAX_TCP_RETRIES) {
                            // Max retries exceeded: remote client is dead, close session
                            tcp_engine.close_session(session->key.src_ip, session->key.dst_ip, session->key.src_port, session->key.dst_port);
                        } else {
                            session->cc.on_rto_timeout();
                            // Issue #9: Go-Back-N burst retransmission sending up to 10 packets
                            if (retransmit_unacked_data(sock, session, tx_pool, 10, true)) {
                                retransmitted++;
                            }
                        }
                    }
                } else if (session->snd_una == session->send_nxt && !session->snd_buf.empty()) {
                    send_tcp_segmented_data(sock, session, nullptr, 0, tx_pool);
                } else if (session->fin_pending && session->snd_buf.empty() && session->snd_una == session->send_nxt && !tx_pool.empty()) {
                    uint64_t tx_buf_addr = tx_pool.back();
                    tx_pool.pop_back();
                    uint8_t *pkt = reinterpret_cast<uint8_t *>(xsk_umem__get_data(sock->umen->buffer, tx_buf_addr));
                    bool sent = net::PacketInjector::ipv4_send_tcp_fin(
                        sock, tx_buf_addr, pkt,
                        session->client_mac, session->server_mac,
                        session->key.src_ip, session->key.dst_ip,
                        session->key.src_port, session->key.dst_port,
                        session->send_nxt, session->rcv_nxt,
                        session->recv_window());
                    if (sent) {
                        session->send_nxt++;
                    } else {
                        tx_pool.push_back(tx_buf_addr);
                    }
                    tcp_engine.close_session(session->key.src_ip, session->key.dst_ip, session->key.src_port, session->key.dst_port);
                }
            }
        });

        return retransmitted;
    }

    AETHON_ALWAYS_INLINE uint32_t drain_backend_events(
        int epfd,
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        std::vector<uint64_t> &tx_pool,
        IPv4TcpAssembler::TcpAssemblerEngine &tcp_engine
    ) noexcept {
        if (AETHON_UNLIKELY(epfd < 0)) return 0;

        static constexpr size_t BACKEND_BATCH_SIZE = 16;
        struct epoll_event events[BACKEND_BATCH_SIZE];
        int nfds = epoll_wait(epfd, events, BACKEND_BATCH_SIZE, 0);
        if (AETHON_LIKELY(nfds <= 0)) return 0;

        uint32_t work_done = 0;

        for (int i = 0; i < nfds; ++i) {
            auto *session = reinterpret_cast<IPv4TcpAssembler::TcpStreamSession *>(events[i].data.ptr);
            if (AETHON_UNLIKELY(!session || session->backend_fd < 0)) continue;

            if (events[i].events & EPOLLOUT) {
                uint16_t old_win = session->recv_window();
                session->flush_backend_tx();
                uint16_t new_win = session->recv_window();

                if (session->backend_tx_buf.empty()) {
                    struct epoll_event ev{};
                    ev.events = EPOLLIN | EPOLLRDHUP;
                    ev.data.ptr = session;
                    epoll_ctl(epfd, EPOLL_CTL_MOD, session->backend_fd, &ev);
                    session->epollout_armed = false;
                }

                // Window Update: If the client was throttled (window < 16 KB) and the buffer
                // has now cleared (window >= 16 KB), send an immediate Window Update ACK so
                // the client does not stall waiting for TCP persist timer backoff (up to 120s).
                if (old_win < 16384 && new_win >= 16384 && !tx_pool.empty()) {
                    uint64_t tx_buf_addr = tx_pool.back();
                    tx_pool.pop_back();
                    uint8_t *pkt = reinterpret_cast<uint8_t *>(xsk_umem__get_data(sock->umen->buffer, tx_buf_addr));
                    bool sent = net::PacketInjector::ipv4_send_tcp_data(
                        sock, tx_buf_addr, pkt,
                        session->client_mac, session->server_mac,
                        session->key.src_ip, session->key.dst_ip,
                        session->key.src_port, session->key.dst_port,
                        session->send_nxt, session->rcv_nxt,
                        nullptr, 0, new_win);
                    if (AETHON_LIKELY(sent)) {
                        work_done++;
                    } else {
                        tx_pool.push_back(tx_buf_addr);
                    }
                }
            }

            

            bool backend_closed = false;
            if(events[i].events & EPOLLIN){
                // keep reading until kernel buffer is completely empty or send_buf is full
                while (session->snd_buf.size() < session->MAX_SND_BUF) {
                    uint8_t resp_buf[16384];
                    ssize_t n = session->read_from_backend(resp_buf, sizeof(resp_buf));
                    if(n>0){
                        if(session->tls_conn.is_established()){
                            session->tls_conn.encrypt(resp_buf, static_cast<size_t>(n));
                            uint8_t enc_tx[20480];
                            int enc_len;
                            while ((enc_len = session->tls_conn.read_pending_tx(enc_tx, sizeof(enc_tx))) > 0) {
                                if (send_tcp_segmented_data(sock, session, enc_tx, static_cast<size_t>(enc_len), tx_pool)) {
                                    work_done++;
                                }
                            }
                        }else{
                             if (send_tcp_segmented_data(sock, session, resp_buf, static_cast<size_t>(n), tx_pool)) {
                                work_done++;
                            }
                        }
                    } else if (n == 0) {
                        backend_closed = true;
                        break;
                    } else {
                        // n < 0: EAGAIN or EWOULDBLOCK means kernel buffer empty for now
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;
                        }
                        // Other error (e.g. ECONNRESET)
                        backend_closed = true;
                        break;
                    }
                }
            }

             // Only mark closed if EPOLLHUP/EPOLLERR fired and no unread data remains
            if ((events[i].events & (EPOLLHUP | EPOLLERR)) && !backend_closed) {
                backend_closed = true;
            }













            if (AETHON_UNLIKELY(backend_closed)) {

                if(session->backend_fd >=0){
                    epoll_ctl(epfd, EPOLL_CTL_DEL, session->backend_fd, nullptr);
                    ::close(session->backend_fd);
                    session->backend_fd = -1;

                }

                // if send_buf is already comppletely empty fully ACKED send FIN immediately

                if(session->snd_buf.empty() && session->snd_una == session->send_nxt){

                    
                    if (!tx_pool.empty()) {
                        uint64_t tx_buf_addr = tx_pool.back();
                        tx_pool.pop_back();
                        uint8_t *pkt = reinterpret_cast<uint8_t *>(xsk_umem__get_data(sock->umen->buffer, tx_buf_addr));
                        bool sent = net::PacketInjector::ipv4_send_tcp_fin(
                            sock, tx_buf_addr, pkt,
                            session->client_mac, session->server_mac,
                            session->key.src_ip, session->key.dst_ip,
                            session->key.src_port, session->key.dst_port,
                            session->send_nxt, session->rcv_nxt,
                            session->recv_window());
                            if (sent) {
                                session->send_nxt++;
                            } else {
                                tx_pool.push_back(tx_buf_addr);
                            }
                        }
                    tcp_engine.close_session(session->key.src_ip, session->key.dst_ip, session->key.src_port, session->key.dst_port);
                        
                }else{

                    session->fin_pending = true;
                }
            }
        }
        
        return work_done;
    }

}
}

