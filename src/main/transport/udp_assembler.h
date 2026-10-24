// the UDP assembler (source IP , Destination Ip , protocol ,Identification ID)
#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include "aethon/aethon.h"
#include "aethon/single_thread_hasmap.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <new>
#include <sys/types.h>


/*
  fragment offset in Ipv4 is 13 bits so max 2^13 - 1 = 8191 
  In Ipv4 max total length is 16 bit wide so 2^16 - 1 = 65535 // an ipv4 packet cannot be larger than 65535 bytes
  so 8 * 8191 = 65526 bytes

  every single ip fragment on the internet is mandated by the ipv4 protocol to be aligend to multiple of 8 bytes 
  A fragment can start at 0 byte, 8 byte ,

  1 mtu = 1480 rougly   so 65535 / 1480 = 44 .2 packets 

  fragment offest in the unit of 8 bytes 

  bitmap[0] hold blocks 0 to 63 
  bitmap[1] hold blocks 64 to 127 


*/
namespace aethon {
namespace UDPIpv4Assembler {
static constexpr std::size_t AETHON_MAX_IP_DATAGRAM_SIZE =
    65535; // offset size max
static constexpr std::size_t AETHON_MAX_ACTIVE_DGRAM_SESSIONS =
    65536; // max no of concurrent udp connection to maintain

// 64 kb packet contain at max around 45 fragment of size 1500 bytes 1MTU
// an attack can send one 1 BYTE fragment to do more cpu operation

static constexpr std::size_t AETHON_MAX_IP_DATAGRAM_FRAGMENT_PER_ID = 64;
static constexpr std::size_t AETHON_DATAGRAM_REASSEMBLY_TIMEOUT_SEC =
    10; // 10s timeout

struct alignas(16) FragmentKey {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t ip_id;
  uint8_t protocol;
  uint8_t _pad{0};

  AETHON_ALWAYS_INLINE bool operator==(const FragmentKey &o) const noexcept {
    return src_ip == o.src_ip && dst_ip == o.dst_ip && ip_id == o.ip_id &&
           protocol == o.protocol;
  }

  AETHON_ALWAYS_INLINE bool operator!=(const FragmentKey &o) const noexcept{
    return !(*this == o);
  }
};

// High-speed 64-bit Murmur/SplitMix hash for FragmentKey

static constexpr FragmentKey kEmptyFragmentKey{0, 0, 0, 0, 0};


struct FragmentKeyHasher {
  AETHON_ALWAYS_INLINE uint64_t
  operator()(const FragmentKey &k) const noexcept {
    uint64_t h1 = (static_cast<uint64_t>(k.src_ip) << 32) | k.dst_ip;
    uint64_t h2 = (static_cast<uint64_t>(k.ip_id) << 16) | k.protocol;

    // Fast mixing
    h1 ^= h2 + 0x9e3779b97f4a7c15ULL + (h1 << 6) + (h1 >> 2);
    h1 ^= h1 >> 30;
    h1 *= 0xbf58476d1ce4e5b9ULL;
    h1 ^= h1 >> 27;
    h1 *= 0x94d049bb133111ebULL;
    h1 ^= h1 >> 31;
    return h1;
  }
};

static constexpr std::size_t AETHON_TOTAL_8BYTE_BLOCKS =
    (AETHON_MAX_IP_DATAGRAM_SIZE + 1) / 8;
static constexpr std::size_t AETHON_BITMAP_WORDS =
    AETHON_TOTAL_8BYTE_BLOCKS / 64;

// single IPv4 packet
struct ReassemblySession {
  uint64_t created_at_ns{0};
  uint32_t total_expected_len{
      0};                     // Set when the last fragment (MF == 0) arrives
  uint32_t received_bytes{0}; // Total unique bytes assembled so far
  uint16_t fragment_count{0}; // Number of fragments received (checked against
                              // AETHON_MAX_IP_DATAGRAM_FRAGMENT_PER_ID)
  bool has_last_fragment{false};

  std::array<uint64_t, AETHON_BITMAP_WORDS> block_bitmap{};
  std::array<uint8_t, AETHON_MAX_IP_DATAGRAM_SIZE> buffer{};

  AETHON_ALWAYS_INLINE bool is_complete() const noexcept {
    return has_last_fragment && (received_bytes >= total_expected_len);
  }

  AETHON_ALWAYS_INLINE static bool
  is_block_written(const std::array<uint64_t, AETHON_BITMAP_WORDS> &bitmap,
                   size_t block_idx) noexcept

  {
    size_t word_idx = block_idx >> 6; // block_id/64
    size_t bit_idx = block_idx & 63;  // block_idx % 64

    return (bitmap[word_idx] & (1ULL << bit_idx)) != 0;
  }

  AETHON_ALWAYS_INLINE static void
  mark_block_written(std::array<uint64_t, AETHON_BITMAP_WORDS> &bitmap,
                     size_t block_idx) noexcept {
    size_t word_idx = block_idx >> 6;
    size_t bit_idx = block_idx & 63;
    bitmap[word_idx] |= (1ULL << bit_idx);
  }

  // add_fragment when fragmet comes with offset , payload , len ,
  // more_fragments

  AETHON_ALWAYS_INLINE bool check_fragment(uint16_t offset,
                                         const uint8_t *payload, uint16_t len,
                                         bool more_fragments){

      if(AETHON_UNLIKELY(more_fragments && (len & 7)!=0)){
        return false; // illegal fragment length
      }

      if(AETHON_UNLIKELY(len==0)){
        return false;
      }

      if(AETHON_UNLIKELY(offset &7)!=0){
        return false;
      }

      if(AETHON_UNLIKELY(offset ==0 && len < 8)){
        // tiny fragment cannot hold udp header
        return false;
      }

      return true;
  }


  AETHON_ALWAYS_INLINE bool add_fragment(uint16_t offset,
                                         const uint8_t *payload, uint16_t len,
                                         bool more_fragments) noexcept {

    if(!check_fragment(offset, payload, len, more_fragments)) return false;
        
    // 1. Boundary & exploit check (Ping of Death protection)
    if (AETHON_UNLIKELY(static_cast<size_t>(offset) + len >
                        AETHON_MAX_IP_DATAGRAM_SIZE)) {
      return false;
    }

    // 2. Micro-fragmentation attack protection
    if (AETHON_UNLIKELY(++fragment_count >
                        AETHON_MAX_IP_DATAGRAM_FRAGMENT_PER_ID)) {
      return false;
    }

    AETHON_BUILTIN_PREFETCH(&buffer[offset], 1, 3);
    AETHON_BUILTIN_PREFETCH(payload, 0, 3);

    // 3. If MF == 0, this is the final fragment!
    if (!more_fragments) {
      has_last_fragment = true;
      total_expected_len = offset + len;
    }

    size_t start_block = offset >> 3;           // offset / 8  the arriving fragment offest represent bytes and each block account for 8 bytes 64 bits in bitmap
    size_t end_block = (offset + len + 7) >> 3; // ceil((offset + len) / 8)

    for (size_t b = start_block; b < end_block; ++b) {
      if (AETHON_UNLIKELY(is_block_written(block_bitmap, b))) {
        continue;
      }

      size_t block_datagram_offset = b << 3; // b * 8

      size_t copy_start_in_payload = (block_datagram_offset >= offset)
                                         ? (block_datagram_offset - offset)
                                         : 0;

      size_t bytes_to_copy = 8;
      if (AETHON_UNLIKELY(copy_start_in_payload + bytes_to_copy > len)) {
        bytes_to_copy = len - copy_start_in_payload; // Partial trailing block
      }

      std::memcpy(&buffer[block_datagram_offset],
                  &payload[copy_start_in_payload], bytes_to_copy);

      // Mark as written and count bytes
      mark_block_written(block_bitmap, b);
      received_bytes += bytes_to_copy;
    }

    return true;
  }
};


struct AssemblyResult {
  bool is_complete{false};
  uint16_t src_port{0};
  uint16_t dst_port{0};
  const uint8_t *payload{nullptr};
  size_t payload_len{0};
  void *completed_session{nullptr};
};

class UDPassemblerEngine {
private:
  using SessionMap = aethon::SingleThreadHashMap<FragmentKey, ReassemblySession*, kEmptyFragmentKey, FragmentKeyHasher>;
  SessionMap sessions_{AETHON_MAX_ACTIVE_DGRAM_SESSIONS * 2};
  uint64_t last_cleanup_ns_{0};

public:
  UDPassemblerEngine() = default;
  ~UDPassemblerEngine() {
    clear();
  }

  UDPassemblerEngine(const UDPassemblerEngine &) = delete;
  UDPassemblerEngine &operator=(const UDPassemblerEngine &) = delete;

  void clear() noexcept {
    for (size_t i = 0; i < sessions_.capacity(); ++i) {
      auto *cell = &sessions_.cells()[i];
      if (cell->key != kEmptyFragmentKey) {
        delete cell->val;
        cell->val = nullptr;
        cell->key = kEmptyFragmentKey;
      }
    }
  }

  void purged_expired(uint64_t now_ns) noexcept {
    constexpr uint64_t timeout_ns = static_cast<uint64_t>(AETHON_DATAGRAM_REASSEMBLY_TIMEOUT_SEC) * 1000000000ULL;
    for (size_t i = 0; i < sessions_.capacity(); ++i) {
      AETHON_BUILTIN_PREFETCH(&sessions_.cells()[i], 0, 1);
      auto *cell = &sessions_.cells()[i];
      if (cell->key != kEmptyFragmentKey) {
        ReassemblySession *session = cell->val;
        if (AETHON_UNLIKELY(session && (now_ns - session->created_at_ns > timeout_ns))) {
          FragmentKey stale_key = cell->key;
          delete session;
          sessions_.erase(stale_key);
        }
      }
    }
  }

  AETHON_ALWAYS_INLINE AssemblyResult process_fragment(
      const FragmentKey &key, 
      uint16_t offset, 
      const uint8_t *payload,
      uint16_t len,
      bool more_fragments, 
      uint64_t now_ns) noexcept 
  {
    AssemblyResult result;
    
    AETHON_BUILTIN_PREFETCH(&key, 0, 3);
    AETHON_BUILTIN_PREFETCH(payload, 0, 3);

    if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(now_ns - last_cleanup_ns_ > 1000000000ULL, 0, 0.999999)) {
      purged_expired(now_ns);
      last_cleanup_ns_ = now_ns;
    }

    ReassemblySession **slot = sessions_.find(key);
    ReassemblySession *session = nullptr;

    if (AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(slot != nullptr, 1, 0.80)) {
      session = *slot;
      AETHON_BUILTIN_PREFETCH(session, 1, 3);
    } else {
      if (AETHON_UNLIKELY(sessions_.size() >= AETHON_MAX_ACTIVE_DGRAM_SESSIONS)) {
        return result;
      }

      session = new (std::nothrow) ReassemblySession();
      if (AETHON_UNLIKELY(!session)) {
        return result;
      }

      session->created_at_ns = now_ns;
      sessions_.insert(key, session);
    }

    if (AETHON_UNLIKELY(!session->add_fragment(offset, payload, len, more_fragments))) {
      delete session;
      sessions_.erase(key);
      return result;
    }

    if (session->is_complete()) {
      result.is_complete = true;
      result.src_port = ntohs(*reinterpret_cast<const uint16_t *>(&session->buffer[0]));
      result.dst_port = ntohs(*reinterpret_cast<const uint16_t *>(&session->buffer[2]));
      result.payload = &session->buffer[8];
      result.payload_len = session->total_expected_len - 8;
      result.completed_session = session;
      sessions_.erase(key);
    }

    return result;
  }

  AETHON_ALWAYS_INLINE void release_completed(AssemblyResult &res) noexcept {
    if (res.completed_session) {
      delete reinterpret_cast<ReassemblySession *>(res.completed_session);
      res.completed_session = nullptr;
    }
  }
};


}; // namespace UDPIpv4Assembler
}; // namespace aethon