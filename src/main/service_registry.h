

/*

SSL_OP_NO_COMPRESSION: In TLS, compressing plaintext before encrypting allows attackers to steal session cookies by measuring packet sizes (the famous CRIME and BREACH attacks). This flag completely disables compression.

  
SSL_OP_CIPHER_SERVER_PREFERENCE: When a client connects, it presents a list of ciphers. This flag ensures your server chooses the strongest hardware-accelerated cipher (AES-GCM), rather than letting a client pick a weaker cipher.


cpp
SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

  

  
Sets the security floor.

  
Why this is critical: Old protocols (SSL 3.0, TLS 1.0, TLS 1.1) have broken mathematics and known vulnerabilities (POODLE, BEAST, SWEET32).

  
This single line ensures your server only communicates using modern, unbreakable cryptography: TLS 1.2 or TLS 1.3.


*/
#pragma once

#include "../../aethon/aethon.h"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/types.h>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include "../../aethon/single_thread_hasmap.h"



namespace aethon::service {

struct ServiceConfig {
  std::string identifier;
  std::string cert_path;
  std::string key_path;
  uint16_t backend_port{0};
  SSL_CTX *ssl_ctx{nullptr};

  ~ServiceConfig() {
    if (ssl_ctx) {
      SSL_CTX_free(ssl_ctx);
      ssl_ctx = nullptr;
    }
  }
};

inline SSL_CTX *create_ssl_context(const std::string &cert_path,
                                     const std::string &key_path) {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
      return nullptr;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION |
                                 SSL_OP_CIPHER_SERVER_PREFERENCE);
    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(),
                                     SSL_FILETYPE_PEM) <= 0) {
      SSL_CTX_free(ctx);
      return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <=
        0) {
      SSL_CTX_free(ctx);
      return nullptr;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
      SSL_CTX_free(ctx);
      return nullptr;
    }
    return ctx;
  }


class alignas(implementation::hardware_destructive_interference_size) ServiceRegistry{
    private:
        static constexpr size_t MAX_SERVICES = 256;
        alignas(implementation::hardware_destructive_interference_size) std::array<ServiceConfig, MAX_SERVICES> services_{};
        size_t service_count_{0};

        using ServiceMap = aethon::SingleThreadHashMap<uint64_t, const ServiceConfig *,0>;
        ServiceMap domain_map_{MAX_SERVICES * 2};
        ServiceMap ip_port_map_{MAX_SERVICES * 2};

        AETHON_ALWAYS_INLINE static uint64_t hash_domain(std::string_view sv) noexcept {
            uint64_t hash = 14695981039346656037ULL;
            for (char c : sv) {
                char lower = (c >= 'A' && c <= 'Z') ? static_cast<char>(c | 0x20) : c;
                hash ^= static_cast<uint64_t>(lower);
                hash *= 1099511628211ULL;
            }
            return hash ? hash : 1ULL;
        }

        AETHON_ALWAYS_INLINE static uint64_t make_ip_port_key(uint32_t ip, uint16_t port) noexcept {
            uint64_t key = (static_cast<uint64_t>(ip) << 16) | static_cast<uint64_t>(port);
            return key ? key : 1ULL;
        }


    public:
        ServiceRegistry () = default;

        bool register_domain(std::string_view domain, const std::string &cert, const std::string &key,uint16_t backend_port){
            if(service_count_ >= MAX_SERVICES){
                return false;
            }


            SSL_CTX * ctx = create_ssl_context(cert,key);
            if(!ctx) return false;

            size_t idx = service_count_++;
            services_[idx].identifier = std::string(domain);
            services_[idx].cert_path = cert;
            services_[idx].key_path = key;
            services_[idx].backend_port = backend_port;
            services_[idx].ssl_ctx = ctx;

            const ServiceConfig *ptr = &services_[idx];

            uint64_t d_hash = hash_domain(domain);
            domain_map_.insert(d_hash,ptr);

            return true;

        }

        bool register_ip_port(const std::string &ip_str, uint16_t port, const std::string &cert, const std::string &key, uint16_t backend_port){
            if (service_count_ >= MAX_SERVICES) {
            return false;
            }
            struct in_addr addr;
            if (inet_pton(AF_INET, ip_str.c_str(), &addr) <= 0) {
                return false;
            }
            SSL_CTX *ctx = create_ssl_context(cert, key);
            if (!ctx) {
                return false;
            }
            size_t idx = service_count_++;
            services_[idx].identifier = ip_str + ":" + std::to_string(port);
            services_[idx].cert_path = cert;
            services_[idx].key_path = key;
            services_[idx].backend_port = backend_port;
            services_[idx].ssl_ctx = ctx;
            const ServiceConfig *ptr = &services_[idx];
            uint64_t key_val = make_ip_port_key(addr.s_addr, port);
            ip_port_map_.insert(key_val, ptr);
            return true;
        }


        AETHON_ALWAYS_INLINE const ServiceConfig *find_by_ip_port(uint32_t ip, uint16_t port)
        const noexcept{
            uint64_t key = make_ip_port_key(ip, port);
            const ServiceConfig * const * res = ip_port_map_.find(key);
            return res ? *res : nullptr;
        }

        AETHON_ALWAYS_INLINE const ServiceConfig * find_by_domain(std::string_view domain) const noexcept {
            if(AETHON_UNLIKELY(domain.empty() || domain.size() > 255)){
                return nullptr;
            }

            uint64_t d_hash = hash_domain(domain);
            const ServiceConfig * const *res = domain_map_.find(d_hash);
            if(res){
                return *res;
            }

            size_t dot_pos = domain.find('.');
            while (dot_pos != std::string_view::npos) {
                std::string_view parent = domain.substr(dot_pos + 1);
                if (parent.find('.') == std::string_view::npos) {
                    break;
                }
                uint64_t p_hash = hash_domain(parent);
                res = domain_map_.find(p_hash);
                if (res) {
                    return *res;
                }
                dot_pos = domain.find('.', dot_pos + 1);
            }
            return nullptr;

        }

        size_t load_from_file(const std::string &filepath) {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            return 0;
        }
        std::string line;
        size_t loaded = 0;
        while (std::getline(file, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) {
                line.pop_back();
            }
            size_t start = 0;
            while (start < line.size() && (line[start] == ' ' || line[start] == '\t')) {
                ++start;
            }
            if (start >= line.size() || line[start] == '#') {
                continue;
            }
            std::istringstream iss(line.substr(start));
            std::string id, cert, key;
            uint16_t backend_port = 0;
            if (!(iss >> id >> cert >> key >> backend_port)) {
                continue;
            }
            size_t colon = id.find(':');
            if (colon != std::string::npos) {
                std::string ip_str = id.substr(0, colon);
                uint16_t listen_port = static_cast<uint16_t>(std::stoi(id.substr(colon + 1)));
                if (register_ip_port(ip_str, listen_port, cert, key, backend_port)) {
                    ++loaded;
                }
            } else {
                if (register_domain(id, cert, key, backend_port)) {
                    ++loaded;
                }
            }
        }
        return loaded;
    }

    AETHON_ALWAYS_INLINE size_t size() const noexcept {
        return service_count_;
    }
        

}  ;



} // namespace aethon::service