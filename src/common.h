#ifndef __COMMON_H
#define __COMMON_H

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
#endif
#include <linux/types.h>


#define aethon_always_inline __always_inline

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX 5
#endif


struct datarec {
  __u64 rx_packets;
  __u64 rx_bytes;
};

/* IP STRUCT WITH CUSTOM HASH  */

struct aethon_ip_address {
  union {
    unsigned int v4;
    unsigned int v6[4];
  } addr;

  unsigned int is_ipv6;
};


#ifdef __cplusplus

constexpr aethon_ip_address EMPTY_IP = {.addr = {.v6 = {0, 0, 0, 0}},
                                        .is_ipv6 = 0xFFFFFFFF};
constexpr aethon_ip_address TOMBSTONE_IP = {.addr = {.v6 = {0, 0, 0, 0}},
                                            .is_ipv6 = 0xFFFFFFFE};


inline bool operator==(const struct aethon_ip_address &a,
                       const struct aethon_ip_address &b) {
  if (a.is_ipv6 != b.is_ipv6)
    return false;
  if (a.is_ipv6) {
    return a.addr.v6[0] == b.addr.v6[0] && a.addr.v6[1] == b.addr.v6[1] &&
           a.addr.v6[2] == b.addr.v6[2] && a.addr.v6[3] == b.addr.v6[3];
  }
  return a.addr.v4 == b.addr.v4;
}

inline bool operator!=(const struct aethon_ip_address &a,
                       const struct aethon_ip_address &b) {
  return !(a == b);
}

struct AethonIpHash {
  std::size_t operator()(const aethon_ip_address &ip) const noexcept {
    if (!ip.is_ipv6) {
      uint64_t x = ip.addr.v4;
      x ^= x >> 16;
      x *= 0x45d9f3b;
      x ^= x >> 16;
      return static_cast<size_t>(x);
    } else {
      uint64_t h1 =
          (static_cast<uint64_t>(ip.addr.v6[0]) << 32) | ip.addr.v6[1];
      uint64_t h2 =
          (static_cast<uint64_t>(ip.addr.v6[2]) << 32) | ip.addr.v6[3];
      uint64_t x = h1 ^ (h2 * 0xbf58476d1ce4e5b9ULL);
      x ^= x >> 30;
      x *= 0xbf58476d1ce4e5b9ULL;
      x ^= x >> 27;
      return static_cast<size_t>(x);
    }
  }
};

#endif


#endif
