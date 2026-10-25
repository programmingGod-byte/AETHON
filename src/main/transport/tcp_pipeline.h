#pragma once

#include "aethon/aethon.h"
#include "af_xdp_header.h"
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

    inline dns::DomainBlocklist g_domain_blocklist;
    inline service::ServiceRegistry g_service_registry;

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

        if (AETHON_LIKELY(res.is_ready && res.payload_len > 0)) {
            auto tls_info = tls::parse_client_hello(res.payload, res.payload_len);
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
                res.session->tls_conn.feed_network_data(res.payload, res.payload_len);

                if (res.session->tls_conn.status() == tls::TlsSessionStatus::HANDSHAKE) {
                    res.session->tls_conn.step_handshake();
                    uint8_t tx_buf[16384];
                    int tx_len = res.session->tls_conn.read_pending_tx(tx_buf, sizeof(tx_buf));
                    if (tx_len > 0) {
                        net::PacketInjector::ipv4_send_tcp_data(
                            sock, buf_addr, pkt, eth, iph, tcph,
                            res.session->rcv_nxt, ntohl(tcph->seq) + payload_len,
                            tx_buf, tx_len);
                        return true;
                    }
                }

                if (res.session->tls_conn.is_established()) {
                    uint8_t plain_buf[16384];
                    int plain_len = res.session->tls_conn.decrypt(plain_buf, sizeof(plain_buf));
                    if (plain_len > 0) {
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
                                res.session->forward_to_backend(plain_buf, plain_len, target_port);
                                if(AETHON_LIKELY(epfd >=0 && res.session->backend_fd >=0)){
                                    struct epoll_event ev{};
                                    ev.data.ptr = res.session;
                                    // add a new socket to watch
                                    epoll_ctl(epfd, EPOLL_CTL_ADD, res.session->backend_fd, &ev);
                                }
                            }
                        }
                    }
                }

                if (AETHON_LIKELY(res.session && res.session->backend_fd >= 0)) {
                    uint8_t resp_buf[16384];
                    ssize_t resp_len = res.session->read_from_backend(resp_buf, sizeof(resp_buf));
                    if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(resp_len > 0, 1, 0.90)) {
                        res.session->tls_conn.encrypt(resp_buf, static_cast<size_t>(resp_len));
                        uint8_t enc_tx[16384];
                        int enc_len = res.session->tls_conn.read_pending_tx(enc_tx, sizeof(enc_tx));
                        if (AETHON_LIKELY(enc_len > 0)) {
                            uint64_t tx_buf_addr = buf_addr;
                            uint8_t *tx_pkt = pkt;
                            if (AETHON_LIKELY(!tx_pool.empty())) {
                                tx_buf_addr = tx_pool.back();
                                tx_pool.pop_back();
                                tx_pkt = reinterpret_cast<uint8_t *>(xsk_umem__get_data(sock->umen->buffer, tx_buf_addr));
                                AETHON_BUILTIN_PREFETCH(tx_pkt, 1, 3);
                            }
                            return net::PacketInjector::ipv4_send_tcp_data(
                                sock, tx_buf_addr, tx_pkt, eth, iph, tcph, 
                                res.session->rcv_nxt, ntohl(tcph->seq) + payload_len, enc_tx, enc_len);
                        }
                    }
                }
            } else {
                if (AETHON_UNLIKELY(res.session && !res.session->hs_stream)) {
                    res.session->hs_stream = scanner.open_stream();
                }
                bool attack_detected = (res.session && res.session->hs_stream)
                    ? scanner.scan_stream(res.session->hs_stream, res.payload, res.payload_len)
                    : scanner.scan(res.payload, res.payload_len);
                if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(attack_detected, 1, 0.0001)) {
                    std::cout << "\n[IPS BLOCK] Malicious TCP Packet Dropped!" << std::endl;
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
                    uint16_t target_port = res.session ? res.session->backend_port : 0;
                    if(target_port == 0){
                        const auto *svc =g_service_registry.find_by_ip_port(iph->daddr, ntohs(tcph->dest));
                        if(svc) target_port = svc->backend_port;
                    }

                    if(target_port > 0 && res.session){
                        res.session->forward_to_backend(res.payload, res.payload_len, target_port);
                    }
                }
            }
        }

        if(AETHON_UNLIKELY(res.is_closed)){
            tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
        }

        return false;
    }






    AETHON_ALWAYS_INLINE bool send_backend_response_packet(
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        IPv4TcpAssembler::TcpStreamSession * __restrict__ session,
        const uint8_t * __restrict__ data,
        size_t len,
        std::vector<uint64_t> &tx_pool
    ) noexcept {
        if (AETHON_UNLIKELY(!sock || !session || !data || len == 0 || tx_pool.empty())) {
            return false;
        }

        uint64_t tx_buf_addr = tx_pool.back();
        tx_pool.pop_back();

        uint8_t *pkt = reinterpret_cast<uint8_t *>(xsk_umem__get_data(sock->umen->buffer, tx_buf_addr));
        AETHON_BUILTIN_PREFETCH(pkt, 1, 3);

        bool sent = net::PacketInjector::ipv4_send_tcp_data(
            sock, tx_buf_addr, pkt,
            session->client_mac, session->server_mac,
            session->key.dst_ip, session->key.src_ip,
            htons(session->key.dst_port), htons(session->key.src_port),
            session->send_nxt, session->rcv_nxt,
            data, len);

        if (AETHON_LIKELY(sent)) {
            session->send_nxt += len;
        } else {
            tx_pool.push_back(tx_buf_addr);
        }
        return sent;
    }




    AETHON_ALWAYS_INLINE uint32_t drain_backend_events(
        int epfd,
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        std::vector<uint64_t> &tx_pool
    ) noexcept {
        if (AETHON_UNLIKELY(epfd < 0)) return 0;

        static constexpr size_t BACKEND_BATCH_SIZE = 16;
        struct epoll_event events[BACKEND_BATCH_SIZE];
        int nfds = epoll_wait(epfd, events, BACKEND_BATCH_SIZE, 0);
        if (AETHON_LIKELY(nfds <= 0)) return 0;

        uint32_t work_done = 0;
        for (int i = 0; i < nfds; ++i) {
            // Retrieve the active TCP session associated with this backend socket
            auto *session = reinterpret_cast<IPv4TcpAssembler::TcpStreamSession *>(events[i].data.ptr);
            if (AETHON_UNLIKELY(!session || session->backend_fd < 0)) continue;

            uint8_t resp_buf[16384];
            ssize_t n = session->read_from_backend(resp_buf, sizeof(resp_buf));
            if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(n > 0, 1, 0.90)) {
                session->tls_conn.encrypt(resp_buf, static_cast<size_t>(n));
                uint8_t enc_tx[16384];
                int enc_len = session->tls_conn.read_pending_tx(enc_tx, sizeof(enc_tx));
                if (AETHON_LIKELY(enc_len > 0)) {
                    if (send_backend_response_packet(sock, session, enc_tx, static_cast<size_t>(enc_len), tx_pool)) {
                        work_done++;
                    }
                }
            }
        }
        return work_done;
    }

}
}

