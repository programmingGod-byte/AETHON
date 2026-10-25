/*
+-------------------------------------------------------------+
| Layer 2: Ethernet Header (14 bytes)                         |
+-------------------------------------------------------------+
| Layer 3: IPv4 Header (20 bytes min)                         |
+-------------------------------------------------------------+
| Layer 4: TCP Header (20 bytes min, with SYN, ACK, etc.)     |
+-------------------------------------------------------------+
| Layer 7: TLS Protocol                                       |
|  +--------------------------------------------------------+ |
|  | TLS Record Header (5 bytes)                            | |
|  +--------------------------------------------------------+ |
|  | TLS Handshake Header (4 bytes)                         | |
|  +--------------------------------------------------------+ |
|  | ClientHello Message Body                               | |
|  |   - Version & Random (34 bytes)                        | |
|  |   - Session ID (variable)                              | |
|  |   - Cipher Suites (variable)                           | |
|  |   - Compression Methods (variable)                     | |
|  |   - Extensions                                         | |
|  |       * Extension 0x0000: Server Name Indication (SNI) | |
|  +--------------------------------------------------------+ |
+-------------------------------------------------------------+

1. TLS Record Layer (Outer Envelope: 5 Bytes)
   Offset     Field            Size       Allowed Values / Meaning
   Byte 0     Content Type     1 byte     0x14: ChangeCipherSpec, 0x15: Alert,
                                          0x16: Handshake (target),
                                          0x17: Application Data (encrypted
payload) Byte 1-2   Legacy Version   2 bytes    0x0301 (TLS 1.0), 0x0303
(TLS 1.2/1.3) Byte 3-4   Record Length    2 bytes    Big-endian uint16 length of
following record data

2. TLS Handshake Protocol Header (4 Bytes)
   Offset     Field            Size       Allowed Values / Meaning
   Byte 5     Handshake Type   1 byte     0x01: ClientHello (target),
                                          0x02: ServerHello, 0x0B: Certificate
   Byte 6-8   Handshake Length 3 bytes    Big-endian 24-bit uint length of
ClientHello body

3. ClientHello Body Fields (Sequential Layout)
   - Client Version     : 2 bytes (0x0303 for TLS 1.2+)
   - Client Random      : 32 bytes (cryptographic random nonce)
   - Session ID Length  : 1 byte (L1, 0 to 32 bytes)
   - Session ID Data    : L1 bytes (skip)
   - Cipher Suites Len  : 2 bytes (L2, big-endian uint16)
   - Cipher Suites Data : L2 bytes (skip)
   - Compression Len    : 1 byte (L3, usually 1 byte)
   - Compression Data   : L3 bytes (skip)
   - Extensions Length  : 2 bytes (E, big-endian uint16 length of all
extensions)

4. Extensions Structure (TLV List: Type-Length-Value)
   Each extension has:
   - Extension Type     : 2 bytes (0x0000 is Server Name Indication / SNI)
   - Extension Length   : 2 bytes (length of this extension's payload)

5. SNI Extension Payload (when Extension Type == 0x0000)
   - Server Name List Len : 2 bytes (total list length)
   - Server Name Type     : 1 byte  (0x00 = host_name / DNS domain)
   - Host Name Length (N) : 2 bytes (big-endian uint16 length of hostname
string)
   - Host Name String     : N bytes (raw ASCII domain, e.g. "github.com")

   +-----------------------------------------------------------------------------------------+
|                                    OUTER EXTENSION TLV                                  |
|  [Extension Type: 2B]  |  [Extension Length: 2B]  |                                     |
|         0x0000         |           0x0014         |                                     |
+---------------------------------------------------+                                     |
|                                                    \                                    |
|                                                     \                                   |
|   +---------------------------------------------------------------------------------+   |
|   |                              SNI VALUE PAYLOAD                                  |   |
|   | [List Length: 2B] | [Name Type: 1B] | [Host Name Length: 2B] | [Host Name: N B] |   |
|   |      0x0012       |      0x00       |        0x000F          |  "api.github.com"|   |
|   +---------------------------------------------------------------------------------+   |
+-----------------------------------------------------------------------------------------+


*/

#pragma once
#include "aethon/aethon.h"
#include <arpa/inet.h>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace aethon::tls {

inline constexpr uint8_t TLS_RECORD_HANDSHAKE = 0x16;
inline constexpr uint8_t TLS_RECORD_APPLICATION_DATA = 0x17;
inline constexpr uint8_t TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
inline constexpr uint16_t TLS_EXT_SERVER_NAME = 0x0000;
inline constexpr uint16_t TLS_EXT_SUPPORTED_GROUPS = 0x000A;
inline constexpr uint16_t TLS_EXT_EC_POINT_FORMATS = 0x000B;
inline constexpr uint8_t TLS_SNI_HOST_NAME = 0x00;
constexpr int MAX_JA3_HASH_STRING=2000;

struct JA3{
  char ja3_str[MAX_JA3_HASH_STRING]{};
  int curr_id{0};

  AETHON_ALWAYS_INLINE bool operator==(const JA3 &other) const noexcept {
    if (curr_id != other.curr_id) return false;
    return std::memcmp(ja3_str, other.ja3_str, curr_id) == 0;
  }

  AETHON_ALWAYS_INLINE bool operator!=(const JA3 &other) const noexcept { return !(*this == other);}
  AETHON_ALWAYS_INLINE std::string_view string_view() const noexcept {
    return std::string_view(ja3_str, curr_id > 0 ? static_cast<size_t>(curr_id) : 0);
  }
  AETHON_ALWAYS_INLINE const char* c_str() const noexcept { return ja3_str;}
};

struct TlsParseResult {
  bool is_tls{false};
  bool is_client_hello{false};
  struct JA3 ja3_str{};
  std::string_view sni{};
  AETHON_ALWAYS_INLINE std::string_view ja3() const noexcept { return ja3_str.string_view();}
};

AETHON_ALWAYS_INLINE uint16_t read_u16_be(const uint8_t *data) noexcept {
  return (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
}

AETHON_ALWAYS_INLINE constexpr bool is_grease(uint16_t value) noexcept {
  return (value & 0x0F0F) == 0x0A0A && ((value >> 8) == (value & 0xFF));
}

AETHON_ALWAYS_INLINE uint32_t read_u24_be(const uint8_t *data) noexcept {
  return (static_cast<uint32_t>(data[0]) << 16) |
         (static_cast<uint32_t>(data[1]) << 8) | static_cast<uint32_t>(data[2]);
}

AETHON_ALWAYS_INLINE void append_char(TlsParseResult &res, char a) noexcept {
  if (AETHON_LIKELY(res.ja3_str.curr_id < MAX_JA3_HASH_STRING - 1)) {
    res.ja3_str.ja3_str[res.ja3_str.curr_id++] = a;
    res.ja3_str.ja3_str[res.ja3_str.curr_id] = '\0';
  }
}

template<typename T>
AETHON_ALWAYS_INLINE void append_int(TlsParseResult &res, T a) noexcept {
  if (a == 0) {
    append_char(res, '0');
    return;
  }
  char buf[12];
  int idx = 0;
  while (a > 0) {
    buf[idx++] = static_cast<char>('0' + (a % 10));
    a /= 10;
  }
  for (int i = idx - 1; i >= 0; --i) {
    append_char(res, buf[i]);
  }
}

AETHON_ALWAYS_INLINE TlsParseResult parse_client_hello(const uint8_t *payload,
                                                       size_t len) noexcept {
  TlsParseResult result{};
  result.ja3_str.curr_id = 0;
  result.ja3_str.ja3_str[0] = '\0';

  if (AETHON_UNLIKELY(len < 9)) {
    return result;
  }

  if (payload[0] != TLS_RECORD_HANDSHAKE) {
    if (payload[0] == TLS_RECORD_APPLICATION_DATA) {
      result.is_tls = true;
    }
    return result;
  }

  result.is_tls = true;

  const uint16_t record_version = read_u16_be(payload + 1);
  const uint16_t ja3_version = read_u16_be(payload + 9);
  append_int(result, ja3_version);
  append_char(result, ',');

  if (AETHON_UNLIKELY(record_version < 0x0300 || record_version > 0x0304)) {
    return result;
  }

  const uint16_t record_len = read_u16_be(payload + 3);

  if (AETHON_UNLIKELY(len < 5 + static_cast<size_t>(record_len))) {
    return result;
  }

  if (AETHON_UNLIKELY(payload[5] != TLS_HANDSHAKE_CLIENT_HELLO)) {
    return result;
  }

  result.is_client_hello = true;

  size_t offset = 43;

  if (AETHON_UNLIKELY(len < offset + 1)) {
    return result;
  }

  const uint8_t session_id_len = payload[offset];
  offset += 1 + session_id_len;
  if (AETHON_UNLIKELY(len < offset + 2)) {
    return result;
  }

  const uint16_t cipher_suites_len = read_u16_be(payload + offset);
  offset += 2;
  if (AETHON_UNLIKELY(len < offset + cipher_suites_len)) {
    return result;
  }

  bool first = true;
  for (size_t i = 0; i + 2 <= cipher_suites_len; i += 2) {
    const uint16_t cipher = read_u16_be(payload + offset + i);
    if (is_grease(cipher)) continue;
    if (!first) append_char(result, '-');
    append_int(result, cipher);
    first = false;
  }
  append_char(result, ',');
  offset += cipher_suites_len;

  if (AETHON_UNLIKELY(len < offset + 1)) {
    return result;
  }

  const uint8_t compression_methods_len = payload[offset];
  offset += 1 + compression_methods_len;

  const uint8_t *groups_payload = nullptr;
  uint16_t groups_payload_len = 0;
  const uint8_t *formats_payload = nullptr;
  uint16_t formats_payload_len = 0;

  if (offset + 2 <= len) {
    const uint16_t extensions_total_len = read_u16_be(payload + offset);
    offset += 2;

    if (AETHON_LIKELY(offset + extensions_total_len <= len)) {
      const size_t extensions_end = offset + extensions_total_len;
      bool first_ext = true;

      while (offset + 4 <= extensions_end) {
        const uint16_t ext_type = read_u16_be(payload + offset);
        const uint16_t ext_len = read_u16_be(payload + offset + 2);
        offset += 4;

        if (AETHON_UNLIKELY(offset + ext_len > extensions_end)) {
          break;
        }

        const uint8_t *ext_data = payload + offset;

        if (!is_grease(ext_type)) {
          if (!first_ext) append_char(result, '-');
          append_int(result, ext_type);
          first_ext = false;
        }

        if (ext_type == TLS_EXT_SUPPORTED_GROUPS) {
          groups_payload = ext_data;
          groups_payload_len = ext_len;
        } else if (ext_type == TLS_EXT_EC_POINT_FORMATS) {
          formats_payload = ext_data;
          formats_payload_len = ext_len;
        } else if (ext_type == TLS_EXT_SERVER_NAME) {
          if (ext_len >= 5) {
            const uint16_t sni_list_len = read_u16_be(ext_data);
            if (ext_len >= 2 + sni_list_len && sni_list_len >= 3) {
              const uint8_t name_type = ext_data[2];
              const uint16_t name_len = read_u16_be(ext_data + 3);

              if (AETHON_LIKELY(name_type == TLS_SNI_HOST_NAME &&
                                5 + name_len <= ext_len && name_len > 0)) {
                result.sni = std::string_view(
                    reinterpret_cast<const char *>(ext_data + 5), name_len);
              }
            }
          }
        }

        offset += ext_len;
      }
    }
  }

  append_char(result, ',');
  if (groups_payload && groups_payload_len >= 2) {
    const uint16_t groups_len = read_u16_be(groups_payload);
    if (groups_len + 2 <= groups_payload_len && (groups_len % 2 == 0)) {
      bool first_group = true;
      for (size_t i = 0; i + 2 <= groups_len; i += 2) {
        const uint16_t group = read_u16_be(groups_payload + 2 + i);
        if (is_grease(group)) continue;
        if (!first_group) append_char(result, '-');
        append_int(result, group);
        first_group = false;
      }
    }
  }

  append_char(result, ',');
  if (formats_payload && formats_payload_len >= 1) {
    const uint8_t formats_len = formats_payload[0];
    if (formats_len + 1 <= formats_payload_len) {
      for (size_t i = 0; i < formats_len; ++i) {
        if (i > 0) append_char(result, '-');
        append_int(result, formats_payload[1 + i]);
      }
    }
  }

  return result;
}

} // namespace aethon::tls