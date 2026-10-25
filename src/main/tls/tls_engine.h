#pragma once
#include <cstdint>
#include <cstddef>
#include <array>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include "aethon/aethon.h"

namespace aethon::tls {
    enum class TlsSessionStatus : uint8_t {
    IDLE = 0,
    HANDSHAKE,
    ESTABLISHED,
    ERROR_STATE,
    CLOSED
    };

    class TlsConnection{
        private:
            SSL *ssl_{nullptr};
            BIO *in_bio_{nullptr};
            BIO *out_bio_{nullptr};
            TlsSessionStatus status_{TlsSessionStatus::IDLE};

        public:
            TlsConnection () = default;
            
             void reset() noexcept {
                if (ssl_) {
                    SSL_free(ssl_);
                    ssl_ = nullptr;
                    in_bio_ = nullptr;
                    out_bio_ = nullptr;
                }
                status_ = TlsSessionStatus::IDLE;
            }

            ~TlsConnection(){
                reset();
            }

            TlsConnection(const TlsConnection &) = delete;
            TlsConnection &operator=(const TlsConnection &) = delete;

            TlsConnection (TlsConnection && other) noexcept 
            :ssl_(other.ssl_), in_bio_(other.in_bio_),out_bio_(other.out_bio_),status_(other.status_){
                 other.ssl_ = nullptr;
                other.in_bio_ = nullptr;
                other.out_bio_ = nullptr;
                other.status_ = TlsSessionStatus::IDLE;
            }

            TlsConnection &operator=(TlsConnection &&other) noexcept {
                if(this!=&other){
                    reset();
                    ssl_ = other.ssl_;
                    in_bio_ = other.in_bio_;
                    out_bio_ = other.out_bio_;
                    status_ = other.status_;
                    other.ssl_ = nullptr;
                    other.in_bio_ = nullptr;
                    other.out_bio_ = nullptr;
                    other.status_ = TlsSessionStatus::IDLE;
                }
                return *this;
            }

            AETHON_ALWAYS_INLINE TlsSessionStatus status() const noexcept {
                return status_;
            }
            AETHON_ALWAYS_INLINE bool is_established() const noexcept {
                return status_ == TlsSessionStatus::ESTABLISHED;
            }

            // Ciphertext received from the network but not yet decrypted (partial TLS records)
            AETHON_ALWAYS_INLINE size_t pending_input() const noexcept {
                return in_bio_ ? BIO_ctrl_pending(in_bio_) : 0;
            }
            

            bool init(SSL_CTX * ctx) noexcept {
                reset();
                if(!ctx){
                    return false;
                }
                ssl_ = SSL_new(ctx);
                if(!ssl_){
                    return false;
                }
                in_bio_ = BIO_new(BIO_s_mem());
                out_bio_ = BIO_new(BIO_s_mem());

                if(!in_bio_ || !out_bio_){
                    reset();
                    return false;
                }
                // when memory buffer is full return -1 
                BIO_set_mem_eof_return(in_bio_, -1);
                BIO_set_mem_eof_return(out_bio_, -1);

                SSL_set_bio(ssl_, in_bio_, out_bio_);
                SSL_set_accept_state(ssl_);
                status_ = TlsSessionStatus::HANDSHAKE;
                return true;

            }


            AETHON_ALWAYS_INLINE int feed_network_data(const uint8_t *data, size_t len) noexcept {
                if(AETHON_UNLIKELY(!in_bio_ || !data || len == 0)) return 0;
                return BIO_write(in_bio_, data, static_cast<int>(len));
            }

            bool step_handshake() noexcept {
                if(AETHON_UNLIKELY(!ssl_ || status_ != TlsSessionStatus::HANDSHAKE)){
                    return false;
                }

                int ret = SSL_do_handshake(ssl_);
                if(ret== 1){
                    status_ = TlsSessionStatus::ESTABLISHED;
                    return true;
                }

                int err  = SSL_get_error(ssl_, ret);
                if(err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE){
                    return true;
                }

                status_ = TlsSessionStatus::ERROR_STATE;
                return false;
            }


            // read the output buffer for seding 
            AETHON_ALWAYS_INLINE int read_pending_tx(uint8_t *out_buf, size_t max_len) noexcept {
                if(AETHON_UNLIKELY(!out_bio_ || !out_buf || max_len ==0)){
                    return 0;
                }
                int ret = BIO_read(out_bio_, out_buf, static_cast<int>(max_len));
                return (ret > 0) ? ret : 0;
            }

            AETHON_ALWAYS_INLINE int decrypt(uint8_t * plain_buf, size_t max_len) noexcept {
                if(AETHON_UNLIKELY(!ssl_ || status_ != TlsSessionStatus::ESTABLISHED || !plain_buf|| max_len ==0)){
                    return 0;
                }
                
                // read from the input biffer and write the decrpyed data into the palin_buf_
                int ret = SSL_read(ssl_, plain_buf, static_cast<int>(max_len));
                if(ret  > 0) return ret;

                int err = SSL_get_error(ssl_, ret);
                // either the input data is empty or there is some data in output 
                if(err == SSL_ERROR_WANT_READ || err== SSL_ERROR_WANT_WRITE){
                    return 0;
                }

                // client close the connection
                if(err == SSL_ERROR_ZERO_RETURN){
                    status_ = TlsSessionStatus::CLOSED;
                    return 0;
                }

                status_ = TlsSessionStatus::ERROR_STATE;
                return  -1;
            }

            AETHON_ALWAYS_INLINE int encrypt(const uint8_t *plain_buf, size_t len) noexcept {
                if(AETHON_UNLIKELY(!ssl_ || status_ !=TlsSessionStatus::ESTABLISHED || !plain_buf || len ==0)) return 0;
                
                return SSL_write(ssl_, plain_buf, static_cast<int>(len));
            }


    };
};