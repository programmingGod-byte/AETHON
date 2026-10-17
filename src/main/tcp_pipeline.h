#pragma once

#include "../../aethon/aethon.h"
#include "tcp_assembler.cpp"
#include "hyper_scan_engine.h"
#include "packet_injector.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <cstdint>
#include <iostream>

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
            bool attack_detected = scanner.scan(res.payload, res.payload_len);

            if (AETHON_UNLIKELY(attack_detected)) {
                std::cout << "\n[IPS BLOCK] Malicious TCP Packet Dropped!" << std::endl;
                std::cout << "  Attacker : ";
                print_ip(iph->saddr);
                std::cout << ":" << ntohs(tcph->source) << std::endl;
                std::cout << "  Target   : ";
                print_ip(iph->daddr);
                std::cout << ":" << ntohs(tcph->dest) << std::endl;

                tcp_engine.close_session(iph->saddr, iph->daddr, tcph->source, tcph->dest);
                bool rst_sent = net::PacketInjector::ipv4_send_tcp_rst(
                    sock, buf_addr, pkt, eth, iph, tcph, payload_len);
                return rst_sent;
            }
        }

        return false;
    }

}
}