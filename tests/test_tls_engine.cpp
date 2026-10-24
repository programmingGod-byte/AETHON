#include <iostream>
#include <vector>
#include <chrono>
#include <cassert>
#include <cstring>
#include <hs/hs.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "tls/tls_engine.h"
#include "tls/service_registry.h"

static SSL_CTX* create_client_ctx() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    return ctx;
}

static void drive_handshake(SSL* client_ssl, BIO* client_out, BIO* client_in, aethon::tls::TlsConnection& server_conn) {
    uint8_t buffer[16384];
    while (!server_conn.is_established() || !SSL_is_init_finished(client_ssl)) {
        int client_ret = SSL_connect(client_ssl);
        int client_err = (client_ret <= 0) ? SSL_get_error(client_ssl, client_ret) : SSL_ERROR_NONE;

        int client_bytes = BIO_read(client_out, buffer, sizeof(buffer));
        if (client_bytes > 0) {
            server_conn.feed_network_data(buffer, client_bytes);
        }

        server_conn.step_handshake();
        int server_bytes = server_conn.read_pending_tx(buffer, sizeof(buffer));
        if (server_bytes > 0) {
            BIO_write(client_in, buffer, server_bytes);
        }

        if (client_ret <= 0) {
            if (client_err != SSL_ERROR_WANT_READ && client_err != SSL_ERROR_WANT_WRITE && client_err != SSL_ERROR_NONE) {
                std::cerr << "Client handshake error: " << client_err << std::endl;
                break;
            }
        }
    }
}

int main() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    aethon::service::ServiceRegistry registry;
    if (!registry.register_domain("localhost", "certs/server.crt", "certs/server.key", 8080)) {
        std::cerr << "Failed to register service" << std::endl;
        return 1;
    }

    const auto* service = registry.find_by_domain("localhost");
    assert(service != nullptr);

    aethon::tls::TlsConnection server_conn;
    assert(server_conn.init(service->ssl_ctx));

    SSL_CTX* client_ctx = create_client_ctx();
    SSL* client_ssl = SSL_new(client_ctx);
    BIO* client_in = BIO_new(BIO_s_mem());
    BIO* client_out = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(client_in, -1);
    BIO_set_mem_eof_return(client_out, -1);
    SSL_set_bio(client_ssl, client_in, client_out);

    std::cout << "[1] Performing in-memory TLS Handshake..." << std::endl;
    drive_handshake(client_ssl, client_out, client_in, server_conn);

    if (server_conn.is_established()) {
        std::cout << "    TLS Session ESTABLISHED successfully!" << std::endl;
    } else {
        std::cerr << "    TLS Handshake failed!" << std::endl;
        return 1;
    }

    std::cout << "[2] Initializing Hyperscan DPI Engine..." << std::endl;
    const char* patterns[] = {"/etc/passwd", "eval\\(", "UNION SELECT"};
    const unsigned int flags[] = {HS_FLAG_CASELESS, HS_FLAG_CASELESS, HS_FLAG_CASELESS};
    const unsigned int ids[] = {1001, 1002, 1003};

    hs_database_t* db = nullptr;
    hs_compile_error_t* compile_err = nullptr;
    if (hs_compile_multi(patterns, flags, ids, 3, HS_MODE_BLOCK, nullptr, &db, &compile_err) != HS_SUCCESS) {
        std::cerr << "Hyperscan compile failed: " << compile_err->message << std::endl;
        hs_free_compile_error(compile_err);
        return 1;
    }

    hs_scratch_t* scratch = nullptr;
    if (hs_alloc_scratch(db, &scratch) != HS_SUCCESS) {
        std::cerr << "Failed to allocate scratch" << std::endl;
        hs_free_database(db);
        return 1;
    }

    std::cout << "[3] Sending encrypted attack payload: 'GET /etc/passwd HTTP/1.1'..." << std::endl;
    const char* attack_payload = "GET /etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n";
    SSL_write(client_ssl, attack_payload, static_cast<int>(strlen(attack_payload)));

    uint8_t wire_buf[16384];
    int wire_len = BIO_read(client_out, wire_buf, sizeof(wire_buf));
    assert(wire_len > 0);

    server_conn.feed_network_data(wire_buf, wire_len);

    uint8_t decrypted_buf[16384];
    int dec_len = server_conn.decrypt(decrypted_buf, sizeof(decrypted_buf));
    assert(dec_len > 0);

    std::string decrypted_str(reinterpret_cast<char*>(decrypted_buf), dec_len);
    std::cout << "    Decrypted bytes: " << dec_len << std::endl;
    std::cout << "    Plaintext content: " << decrypted_str.substr(0, 24) << "..." << std::endl;

    bool hs_hit = false;
    hs_scan(db, reinterpret_cast<const char*>(decrypted_buf), dec_len, 0, scratch,
            [](unsigned int id, unsigned long long from, unsigned long long to, unsigned int flags, void* ctx) -> int {
                (void)from;
                (void)to;
                (void)flags;
                *reinterpret_cast<bool*>(ctx) = true;
                std::cout << "    [DPI ALERT] Hyperscan signature matched! Rule ID: " << id << std::endl;
                return 0;
            }, &hs_hit);

    assert(hs_hit);
    std::cout << "    DPI Inspection: SUCCESS" << std::endl;

    std::cout << "[4] Decryption Throughput Benchmark..." << std::endl;
    std::vector<uint8_t> large_payload(64 * 1024, 'A');
    std::memcpy(large_payload.data(), attack_payload, strlen(attack_payload));

    SSL_write(client_ssl, large_payload.data(), static_cast<int>(large_payload.size()));
    wire_len = BIO_read(client_out, wire_buf, sizeof(wire_buf));
    server_conn.feed_network_data(wire_buf, wire_len);

    constexpr size_t ITERATIONS = 10000;
    auto start = std::chrono::high_resolution_clock::now();
    for (size_t i = 0; i < ITERATIONS; ++i) {
        server_conn.feed_network_data(wire_buf, wire_len);
        server_conn.decrypt(decrypted_buf, sizeof(decrypted_buf));
    }
    auto end = std::chrono::high_resolution_clock::now();
    double secs = std::chrono::duration<double>(end - start).count();
    double total_bytes = static_cast<double>(large_payload.size()) * ITERATIONS;
    double gbps = (total_bytes * 8.0) / (secs * 1e9);

    std::cout << "    Processed: " << (total_bytes / (1024 * 1024)) << " MB in " << secs << " s" << std::endl;
    std::cout << "    Decryption Speed: " << gbps << " Gbps" << std::endl;

    hs_free_scratch(scratch);
    hs_free_database(db);
    SSL_free(client_ssl);
    SSL_CTX_free(client_ctx);
    return 0;
}
