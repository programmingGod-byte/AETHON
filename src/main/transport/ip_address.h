#pragma once
#include "aethon/aethon.h"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ifaddrs.h>
#include <iostream>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
namespace aethon {

namespace Ipv4 {
struct alignas(implementation::hardware_destructive_interference_size)
    HostIpTable {
  uint32_t ips[8]{0}; // up to 8 local ips
  uint8_t count{0};

  AETHON_ALWAYS_INLINE bool contains(uint32_t ip) const noexcept {
    for (uint8_t i = 0; i < count; ++i) {
      if (ips[i] == ip)
        return true;
    }
    return false;
  }
};

inline HostIpTable g_host_ips;

inline void load_interface_ips(const char *__restrict__ ifname) noexcept {
  struct ifaddrs *ifaddr = nullptr;
  if (AETHON_UNLIKELY(getifaddrs(&ifaddr)) == -1) {
    AETHON_SAFE_CHECK(Trait::always_false<bool>,
                      "cannot able to get the interface address \n");
    return;
  }

  g_host_ips.count = 0;
  for (struct ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    if (std::strcmp(ifa->ifa_name, ifname) == 0) {
      if (AETHON_LIKELY(g_host_ips.count < 8)) {
        const auto *sa =
            reinterpret_cast<const struct sockaddr_in *>(ifa->ifa_addr);
        g_host_ips.ips[g_host_ips.count++] = sa->sin_addr.s_addr;

        char ip_str[INET_ADDRSTRLEN];
        // convert binary ip address to  texts
        inet_ntop(AF_INET, &sa->sin_addr.s_addr, ip_str, sizeof(ip_str));
        std::cout << "[Network] Monitoring Interface IP: " << ip_str << "\n";
      }
    }
  }

  freeifaddrs(ifaddr);
}

AETHON_ALWAYS_INLINE bool is_valid_ipv4_checksum(const struct iphdr *__restrict__ iph) noexcept {
  const uint8_t ihl = iph->ihl;
  if (AETHON_UNLIKELY(ihl < 5 || ihl > 15)) {
    return false;
  }
  uint64_t acc = 0;
  const auto *__restrict__ ptr = reinterpret_cast<const uint8_t *>(iph);

  if (AETHON_LIKELY(ihl == 5)) {
    uint64_t w0 = *reinterpret_cast<const uint64_t *>(ptr);
    uint64_t w1 = *reinterpret_cast<const uint64_t *>(ptr + 8);
    uint32_t w2 = *reinterpret_cast<const uint32_t *>(ptr + 16);
    // Sum 32-bit halves into 64-bit accumulator to avoid overflow
    acc = (w0 & 0xFFFFFFFF) + (w0 >> 32) + (w1 & 0xFFFFFFFF) + (w1 >> 32) + w2;
  } else {

    const auto *__restrict__ u32_ptr = reinterpret_cast<const uint32_t *>(iph);
    size_t words = ihl; 
   
    while (words >= 4) {
      acc += u32_ptr[0];
      acc += u32_ptr[1];
      acc += u32_ptr[2];
      acc += u32_ptr[3];
      u32_ptr += 4;
      words -= 4;
    }
    while (words > 0) {
      acc += *u32_ptr++;
      --words;
    }
  }

  acc = (acc & 0xFFFFFFFF) + (acc >> 32);
  acc = (acc & 0xFFFFFFFF) + (acc >> 32);

  acc = (acc & 0xFFFF) + (acc >> 16);
  acc = (acc & 0xFFFF) + (acc >> 16);
  // A valid checksum sums to 0xFFFF in one's complement (or ~acc == 0)
  return static_cast<uint16_t>(acc) == 0xFFFF;
}

// Verifies the TCP checksum over the pseudo-header and the whole segment (header + payload).
// Words are summed in memory order, so the result is endian-independent (RFC 1071).
// Requires full checksums on the wire: receive-side offloads that leave partial checksums
// (e.g. veth with TX checksum offload on the peer) must be disabled.
AETHON_ALWAYS_INLINE bool is_valid_tcp_checksum(const struct iphdr *__restrict__ iph,
                                                const uint8_t *__restrict__ segment,
                                                size_t segment_len) noexcept {
  uint64_t acc = static_cast<uint64_t>(iph->saddr) + iph->daddr +
                 htons(static_cast<uint16_t>(IPPROTO_TCP)) +
                 htons(static_cast<uint16_t>(segment_len));

  const uint8_t *__restrict__ p = segment;
  size_t n = segment_len;
  while (n >= 8) {
    uint64_t w;
    std::memcpy(&w, p, 8);
    acc += (w & 0xFFFFFFFF) + (w >> 32);
    p += 8;
    n -= 8;
  }
  if (n >= 4) {
    uint32_t w;
    std::memcpy(&w, p, 4);
    acc += w;
    p += 4;
    n -= 4;
  }
  if (n >= 2) {
    uint16_t w;
    std::memcpy(&w, p, 2);
    acc += w;
    p += 2;
    n -= 2;
  }
  if (n) {
    uint16_t w = 0;            // odd trailing byte, padded with a zero byte
    std::memcpy(&w, p, 1);
    acc += w;
  }

  acc = (acc & 0xFFFFFFFF) + (acc >> 32);
  acc = (acc & 0xFFFFFFFF) + (acc >> 32);
  acc = (acc & 0xFFFF) + (acc >> 16);
  acc = (acc & 0xFFFF) + (acc >> 16);
  acc = (acc & 0xFFFF) + (acc >> 16);
  return static_cast<uint16_t>(acc) == 0xFFFF;
}
}; // namespace Ipv4
}; // namespace aethon