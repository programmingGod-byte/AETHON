#include "../common.h"
#include "aethon/fast_hash_map.h"

namespace aethon {
inline bool operator==(const struct aethon_ip_address &a,
                       const struct aethon_ip_address &b) {
  if (a.is_ipv6 != b.is_ipv6)
    return false;
  if (a.is_ipv6 == 0)
    return a.addr.v4 == b.addr.v4;

  return a.addr.v6[0] == b.addr.v6[0] && a.addr.v6[1] == b.addr.v6[1] &&
         a.addr.v6[2] == b.addr.v6[2] && a.addr.v6[3] == b.addr.v6[3];
}



}; // namespace aethon