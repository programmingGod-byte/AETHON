#pragma once

#include "../../aethon/aethon.h"
#include "tcp_assembler.cpp"
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
#include "service_registry.h"

namespace aethon {
namespace pipeline {

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
        Scanner & __restrict__ scanner) noexcept
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

            if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(tls_info.is_client_hello, 1, 0.02)) {
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
                        bool attack_detected = scanner.scan(plain_buf, plain_len);
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
                            }
                        }
                    }
                }

                if(res.session && res.session->backend_fd >=0 ){
                    uint8_t resp_buf[16384];
                    ssize_t resp_len = res.session->read_from_backend(resp_buf, sizeof(resp_buf));
                    if(resp_len > 0){
                        res.session->tls_conn.encrypt(resp_buf, static_cast<size_t>(resp_len));
                        uint8_t enc_tx[16384];
                        int enc_len = res.session->tls_conn.read_pending_tx(enc_tx, sizeof(enc_tx));
                        if(enc_len > 0){
                            net::PacketInjector::ipv4_send_tcp_data(sock, buf_addr, pkt, eth, iph, tcph, res.session->rcv_nxt, ntohl(tcph->seq) + payload_len, enc_tx, enc_len);
                            return true;
                        }
                    }
                }
            } else {
                bool attack_detected = scanner.scan(res.payload, res.payload_len);
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

        return false;
    }

}
}

