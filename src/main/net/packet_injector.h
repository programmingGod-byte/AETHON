#pragma once

#include "aethon/aethon.h"
#include "af_xdp_header.h"

#ifndef AETHON_ALWAYS_INLINE
#if defined(__GNUC__) || defined(__clang__)
#define AETHON_ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
#define AETHON_ALWAYS_INLINE inline
#endif
#endif
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

namespace aethon {
namespace net {

class alignas(implementation::hardware_destructive_interference_size) PacketInjector {
public:
    static AETHON_ALWAYS_INLINE uint16_t ipv4_compute_checksum(const uint8_t * __restrict__ pkt, size_t len) noexcept {
        uint32_t sum = 0;

        AETHON_UNROLL(4)
        while (len >= 2) {
            sum += (static_cast<uint16_t>(pkt[0]) << 8) | static_cast<uint16_t>(pkt[1]);
            pkt += 2;
            len -= 2;
        }

        if (len) {
            sum += static_cast<uint16_t>(pkt[0]) << 8;
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return static_cast<uint16_t>(~sum);
    }

    static AETHON_ALWAYS_INLINE uint16_t ipv4_tcp_compute_checksum(
        uint32_t src_ip,
        uint32_t dst_ip,
        const struct tcphdr * __restrict__ tcph,
        size_t tcp_len
    ) noexcept {
        struct PseudoHeader {
            uint32_t src_ip;
            uint32_t dst_ip;
            uint8_t zero;
            uint8_t protocol;
            uint16_t tcp_len;
        } __attribute__((packed));

        PseudoHeader ph;
        ph.src_ip = src_ip;
        ph.dst_ip = dst_ip;
        ph.zero = 0;
        ph.protocol = IPPROTO_TCP;
        ph.tcp_len = htons(static_cast<uint16_t>(tcp_len));

        uint32_t sum = 0;
        const auto *ph_ptr = reinterpret_cast<const uint8_t *>(&ph);

        AETHON_UNROLL(6)
        for (size_t i = 0; i < sizeof(PseudoHeader); i += 2) {
            sum += (static_cast<uint16_t>(ph_ptr[i]) << 8) | static_cast<uint16_t>(ph_ptr[i + 1]);
        }

        const auto *tcp_ptr = reinterpret_cast<const uint8_t *>(tcph);

        AETHON_UNROLL(10)
        for (size_t i = 0; i < tcp_len; i += 2) {
            if (i + 1 < tcp_len) {
                sum += (static_cast<uint16_t>(tcp_ptr[i]) << 8) | static_cast<uint16_t>(tcp_ptr[i + 1]);
            } else {
                sum += static_cast<uint16_t>(tcp_ptr[i]) << 8;
            }
        }

        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return static_cast<uint16_t>(~sum);
    }

    static AETHON_ALWAYS_INLINE bool ipv4_send_tcp_data(
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        uint64_t buf_addr,
        uint8_t * __restrict__ pkt,
        const uint8_t * __restrict__ client_mac,
        const uint8_t * __restrict__ server_mac,
        uint32_t client_ip,
        uint32_t server_ip,
        uint16_t client_port,
        uint16_t server_port,
        uint32_t server_seq,
        uint32_t client_ack,
        const uint8_t * __restrict__ tls_data,
        size_t tls_len
    ) noexcept {
        const size_t total_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + tls_len;
        AETHON_BUILTIN_PREFETCH(pkt, 1, 3);

        auto *out_eth = reinterpret_cast<struct ether_header *>(pkt);
        std::memcpy(out_eth->ether_dhost, client_mac, ETH_ALEN);
        std::memcpy(out_eth->ether_shost, server_mac, ETH_ALEN);
        out_eth->ether_type = htons(ETHERTYPE_IP);

        auto *out_iph = reinterpret_cast<struct iphdr *>(pkt + sizeof(struct ether_header));
        out_iph->ihl = 5;
        out_iph->version = 4;
        out_iph->tos = 0;
        out_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + tls_len);
        out_iph->id = htons(0x1337);
        out_iph->frag_off = 0;
        out_iph->ttl = 64;
        out_iph->protocol = IPPROTO_TCP;
        out_iph->saddr = server_ip;
        out_iph->daddr = client_ip;
        out_iph->check = 0;
        out_iph->check = htons(ipv4_compute_checksum(reinterpret_cast<const uint8_t *>(out_iph), sizeof(struct iphdr)));

        auto *out_tcph = reinterpret_cast<struct tcphdr *>(pkt + sizeof(struct ether_header) + sizeof(struct iphdr));
        std::memset(out_tcph, 0, sizeof(struct tcphdr));
        out_tcph->source = server_port;
        out_tcph->dest = client_port;
        out_tcph->seq = htonl(server_seq);
        out_tcph->ack_seq = htonl(client_ack);
        out_tcph->doff = 5;
        out_tcph->ack = 1;
        out_tcph->psh = (tls_len > 0) ? 1 : 0;
        out_tcph->window = htons(65535);

        uint8_t *payload_dst = pkt + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
        if (AETHON_LIKELY(tls_len > 0)) {
            std::memcpy(payload_dst, tls_data, tls_len);
        }

        out_tcph->check = 0;
        out_tcph->check = htons(ipv4_tcp_compute_checksum(out_iph->saddr, out_iph->daddr, out_tcph, sizeof(struct tcphdr) + tls_len));

        uint32_t idx = 0;
        if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(xsk_ring_prod__reserve(&sock->tx, 1, &idx) != 1, 0, 0.001)) {
            return false;
        }

        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&sock->tx, idx);
        tx_desc->addr = buf_addr;
        tx_desc->len = total_len;
        xsk_ring_prod__submit(&sock->tx, 1);
        if (AETHON_UNLIKELY(xsk_ring_prod__needs_wakeup(&sock->tx))) {
            sendto(xsk_socket__fd(sock->xsk), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
        }
        return true;
    }

    static AETHON_ALWAYS_INLINE bool ipv4_send_tcp_data(
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        uint64_t buf_addr,
        uint8_t * __restrict__ pkt,
        const struct ether_header * __restrict__ eth,
        const struct iphdr * __restrict__ iph,
        const struct tcphdr * __restrict__ tcph,
        uint32_t server_seq,
        uint32_t client_ack,
        const uint8_t * __restrict__ tls_data,
        size_t tls_len
    ) noexcept {
        return ipv4_send_tcp_data(
            sock, buf_addr, pkt,
            reinterpret_cast<const uint8_t *>(eth->ether_shost),
            reinterpret_cast<const uint8_t *>(eth->ether_dhost),
            iph->saddr, iph->daddr,
            tcph->source, tcph->dest,
            server_seq, client_ack, tls_data, tls_len);
    }



    static AETHON_ALWAYS_INLINE bool ipv4_send_tcp_rst(
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        uint64_t buf_addr,
        uint8_t * __restrict__ pkt,
        const struct ether_header * __restrict__ eth,
        const struct iphdr * __restrict__ iph,
        const struct tcphdr * __restrict__ tcph,
        size_t payload_len
    ) noexcept {
        constexpr size_t total_rst_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);

        AETHON_BUILTIN_PREFETCH(pkt, 1, 3);

        uint8_t client_mac[ETH_ALEN];
        uint8_t server_mac[ETH_ALEN];
        std::memcpy(client_mac, eth->ether_shost, ETH_ALEN);
        std::memcpy(server_mac, eth->ether_dhost, ETH_ALEN);

        const uint32_t client_ip = iph->saddr;
        const uint32_t server_ip = iph->daddr;

        const uint16_t client_port = tcph->source;
        const uint16_t server_port = tcph->dest;

        const uint32_t client_seq = tcph->seq;
        const uint32_t client_ack_seq = tcph->ack_seq;
        const uint8_t in_flags = reinterpret_cast<const uint8_t *>(tcph)[13];

        auto *out_eth = reinterpret_cast<struct ether_header *>(pkt);
        std::memcpy(out_eth->ether_dhost, client_mac, ETH_ALEN);
        std::memcpy(out_eth->ether_shost, server_mac, ETH_ALEN);
        out_eth->ether_type = htons(ETHERTYPE_IP);

        auto *out_iph = reinterpret_cast<struct iphdr *>(pkt + sizeof(struct ether_header));
        out_iph->ihl = 5;
        out_iph->version = 4;
        out_iph->tos = 0;
        out_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        out_iph->id = htons(0x1337);
        out_iph->frag_off = 0;
        out_iph->ttl = 64;
        out_iph->protocol = IPPROTO_TCP;
        out_iph->saddr = server_ip;
        out_iph->daddr = client_ip;
        out_iph->check = 0;
        out_iph->check = htons(ipv4_compute_checksum(reinterpret_cast<const uint8_t *>(out_iph), sizeof(struct iphdr)));

        auto *out_tcph = reinterpret_cast<struct tcphdr *>(pkt + sizeof(struct ether_header) + sizeof(struct iphdr));
        std::memset(out_tcph, 0, sizeof(struct tcphdr));
        out_tcph->source = server_port;
        out_tcph->dest = client_port;

        if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY((in_flags & TH_ACK) != 0, 1, 0.99)) {
            out_tcph->seq = client_ack_seq;
            out_tcph->ack_seq = 0;
            out_tcph->rst = 1;
        } else {
            out_tcph->seq = 0;
            out_tcph->ack_seq = htonl(ntohl(client_seq) + (payload_len > 0 ? static_cast<uint32_t>(payload_len) : 1));
            out_tcph->rst = 1;
            out_tcph->ack = 1;
        }

        out_tcph->doff = 5;
        out_tcph->check = 0;
        out_tcph->check = htons(ipv4_tcp_compute_checksum(out_iph->saddr, out_iph->daddr, out_tcph, sizeof(struct tcphdr)));

        uint32_t idx = 0;
        if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(xsk_ring_prod__reserve(&sock->tx, 1, &idx) != 1, 0, 0.001)) {
            return false;
        }

        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&sock->tx, idx);
        tx_desc->addr = buf_addr;
        tx_desc->len = total_rst_len;

        xsk_ring_prod__submit(&sock->tx, 1);
        if (AETHON_UNLIKELY(xsk_ring_prod__needs_wakeup(&sock->tx))) {
            sendto(xsk_socket__fd(sock->xsk), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
        }
        return true;
    }





        static AETHON_ALWAYS_INLINE bool ipv4_send_tcp_syn_ack(
        xdp::aethon_xsk_socket_info * __restrict__ sock,
        uint64_t buf_addr,
        uint8_t * __restrict__ pkt,
        const struct ether_header * __restrict__ eth,
        const struct iphdr * __restrict__ iph,
        const struct tcphdr * __restrict__ tcph,
        uint32_t server_isn,
        uint32_t client_seq
    ) noexcept {
        constexpr size_t total_synack_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
        AETHON_BUILTIN_PREFETCH(pkt, 1, 3);

        uint8_t client_mac[ETH_ALEN];
        uint8_t server_mac[ETH_ALEN];
        std::memcpy(client_mac, eth->ether_shost, ETH_ALEN);
        std::memcpy(server_mac, eth->ether_dhost, ETH_ALEN);

        const uint32_t client_ip = iph->saddr;
        const uint32_t server_ip = iph->daddr;
        const uint16_t client_port = tcph->source;
        const uint16_t server_port = tcph->dest;

        auto *out_eth = reinterpret_cast<struct ether_header *>(pkt);
        std::memcpy(out_eth->ether_dhost, client_mac, ETH_ALEN);
        std::memcpy(out_eth->ether_shost, server_mac, ETH_ALEN);
        out_eth->ether_type = htons(ETHERTYPE_IP);

        auto *out_iph = reinterpret_cast<struct iphdr *>(pkt + sizeof(struct ether_header));
        out_iph->ihl = 5;
        out_iph->version = 4;
        out_iph->tos = 0;
        out_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        out_iph->id = htons(0x1337);
        out_iph->frag_off = 0;
        out_iph->ttl = 64;
        out_iph->protocol = IPPROTO_TCP;
        out_iph->saddr = server_ip;
        out_iph->daddr = client_ip;
        out_iph->check = 0;
        out_iph->check = htons(ipv4_compute_checksum(reinterpret_cast<const uint8_t *>(out_iph), sizeof(struct iphdr)));

        auto *out_tcph = reinterpret_cast<struct tcphdr *>(pkt + sizeof(struct ether_header) + sizeof(struct iphdr));
        std::memset(out_tcph, 0, sizeof(struct tcphdr));
        out_tcph->source = server_port;
        out_tcph->dest = client_port;
        out_tcph->seq = htonl(server_isn);
        out_tcph->ack_seq = htonl(client_seq + 1);
        out_tcph->syn = 1;
        out_tcph->ack = 1;
        out_tcph->doff = 5;
        out_tcph->window = htons(65535);
        out_tcph->check = 0;
        out_tcph->check = htons(ipv4_tcp_compute_checksum(out_iph->saddr, out_iph->daddr, out_tcph, sizeof(struct tcphdr)));

        uint32_t idx = 0;
        if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(xsk_ring_prod__reserve(&sock->tx, 1, &idx) != 1, 0, 0.001)) {
            return false;
        }

        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&sock->tx, idx);
        tx_desc->addr = buf_addr;
        tx_desc->len = total_synack_len;
        xsk_ring_prod__submit(&sock->tx, 1);
        if (AETHON_UNLIKELY(xsk_ring_prod__needs_wakeup(&sock->tx))) {
            sendto(xsk_socket__fd(sock->xsk), nullptr, 0, MSG_DONTWAIT, nullptr, 0);
        }
        return true;
    }


};

}
}