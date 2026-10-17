#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

static std::atomic<bool> g_running{true};
static std::atomic<uint64_t> g_total_packets{0};
static std::atomic<uint64_t> g_total_bytes{0};
static std::atomic<uint64_t> g_total_attacks{0};

static inline uint16_t compute_ip_checksum(const void *buf, size_t len) noexcept {
    const auto *p = static_cast<const uint16_t *>(buf);
    uint32_t sum = 0;
    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1) {
        sum += *reinterpret_cast<const uint8_t *>(p);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

static inline uint16_t tcp_checksum(const struct iphdr *iph, const struct tcphdr *tcph, const uint8_t *payload, size_t payload_len) noexcept {
    uint32_t sum = 0;
    sum += (iph->saddr >> 16) & 0xFFFF;
    sum += iph->saddr & 0xFFFF;
    sum += (iph->daddr >> 16) & 0xFFFF;
    sum += iph->daddr & 0xFFFF;
    sum += htons(IPPROTO_TCP);
    sum += htons(static_cast<uint16_t>(sizeof(struct tcphdr) + payload_len));

    const auto *p = reinterpret_cast<const uint16_t *>(tcph);
    for (size_t i = 0; i < sizeof(struct tcphdr) / 2; ++i) {
        sum += p[i];
    }
    if (payload && payload_len > 0) {
        p = reinterpret_cast<const uint16_t *>(payload);
        size_t rem = payload_len;
        while (rem > 1) {
            sum += *p++;
            rem -= 2;
        }
        if (rem == 1) {
            sum += *reinterpret_cast<const uint8_t *>(p);
        }
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

static void sig_handler(int) {
    g_running.store(false, std::memory_order_relaxed);
}

void chaos_worker(int thread_id, const char *dst_ip_str) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET((thread_id % 4) + 1, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        return;
    }

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dst_addr;
    std::memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    inet_pton(AF_INET, dst_ip_str, &dst_addr.sin_addr);

    constexpr size_t BATCH = 64;
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    alignas(64) uint8_t packet_pool[BATCH][1500];

    const char *malicious_payloads[] = {
        "SELECT user,password from mysql.user;",
        "UNION SELECT 1,2,3,table_name FROM information_schema.tables",
        "<script>alert(document.cookie)</script>",
        "UNION+select+'BENCHMARK(10000000,SHA1(1))"
    };
    constexpr size_t NUM_EXPLOITS = 4;

    for (size_t i = 0; i < BATCH; ++i) {
        uint8_t *pkt = packet_pool[i];
        auto *iph = reinterpret_cast<struct iphdr *>(pkt);
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->id = htons(static_cast<uint16_t>(1000 + i));
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->saddr = htonl((10 << 24) | ((thread_id + 1) << 16) | static_cast<uint32_t>(i + 1));
        iph->daddr = dst_addr.sin_addr.s_addr;

        size_t pkt_len = 0;
        size_t mode = i % 4;

        if (mode == 0) {
            iph->protocol = IPPROTO_TCP;
            pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
            iph->tot_len = htons(static_cast<uint16_t>(pkt_len));
            iph->check = 0;
            iph->check = compute_ip_checksum(iph, sizeof(struct iphdr));

            auto *tcph = reinterpret_cast<struct tcphdr *>(pkt + sizeof(struct iphdr));
            std::memset(tcph, 0, sizeof(struct tcphdr));
            tcph->source = htons(static_cast<uint16_t>(10000 + (thread_id * 1000) + i));
            tcph->dest = htons(80);
            tcph->seq = htonl(100000 + (i * 1000));
            tcph->doff = 5;
            tcph->syn = 1;
            tcph->window = htons(65535);
            tcph->check = 0;
            tcph->check = tcp_checksum(iph, tcph, nullptr, 0);
        } else if (mode == 1) {
            iph->protocol = IPPROTO_TCP;
            const char *exploit = malicious_payloads[i % NUM_EXPLOITS];
            size_t payload_len = std::strlen(exploit);
            pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
            iph->tot_len = htons(static_cast<uint16_t>(pkt_len));
            iph->check = 0;
            iph->check = compute_ip_checksum(iph, sizeof(struct iphdr));

            auto *tcph = reinterpret_cast<struct tcphdr *>(pkt + sizeof(struct iphdr));
            std::memset(tcph, 0, sizeof(struct tcphdr));
            tcph->source = htons(static_cast<uint16_t>(10000 + (thread_id * 1000) + i));
            tcph->dest = htons(80);
            tcph->seq = htonl(100000 + (i * 1000) + 1);
            tcph->ack_seq = htonl(1);
            tcph->doff = 5;
            tcph->psh = 1;
            tcph->ack = 1;
            tcph->window = htons(65535);

            uint8_t *payload = pkt + sizeof(struct iphdr) + sizeof(struct tcphdr);
            std::memcpy(payload, exploit, payload_len);

            tcph->check = 0;
            tcph->check = tcp_checksum(iph, tcph, payload, payload_len);
        } else if (mode == 2) {
            iph->protocol = IPPROTO_UDP;
            constexpr size_t payload_len = 500;
            pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
            iph->tot_len = htons(static_cast<uint16_t>(pkt_len));
            iph->check = 0;
            iph->check = compute_ip_checksum(iph, sizeof(struct iphdr));

            auto *udph = reinterpret_cast<struct udphdr *>(pkt + sizeof(struct iphdr));
            udph->source = htons(static_cast<uint16_t>(20000 + (thread_id * 1000) + i));
            udph->dest = htons(8080);
            udph->len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + payload_len));
            udph->check = 0;

            uint8_t *payload = pkt + sizeof(struct iphdr) + sizeof(struct udphdr);
            std::memset(payload, 'M', payload_len);
        } else {
            iph->protocol = IPPROTO_TCP;
            constexpr size_t payload_len = 1350;
            pkt_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len;
            iph->tot_len = htons(static_cast<uint16_t>(pkt_len));
            iph->check = 0;
            iph->check = compute_ip_checksum(iph, sizeof(struct iphdr));

            auto *tcph = reinterpret_cast<struct tcphdr *>(pkt + sizeof(struct iphdr));
            std::memset(tcph, 0, sizeof(struct tcphdr));
            tcph->source = htons(static_cast<uint16_t>(30000 + (thread_id * 1000) + i));
            tcph->dest = htons(80);
            tcph->seq = htonl(500000 + (i * 2000));
            tcph->ack_seq = htonl(1);
            tcph->doff = 5;
            tcph->ack = 1;
            tcph->window = htons(65535);

            uint8_t *payload = pkt + sizeof(struct iphdr) + sizeof(struct tcphdr);
            std::memset(payload, 'J', payload_len);

            tcph->check = 0;
            tcph->check = tcp_checksum(iph, tcph, payload, payload_len);
        }

        iovs[i].iov_base = pkt;
        iovs[i].iov_len = pkt_len;

        std::memset(&msgs[i], 0, sizeof(struct mmsghdr));
        msgs[i].msg_hdr.msg_name = &dst_addr;
        msgs[i].msg_hdr.msg_namelen = sizeof(dst_addr);
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    uint64_t local_attacks = 0;
    while (g_running.load(std::memory_order_relaxed)) {
        int sent = sendmmsg(sock, msgs, BATCH, 0);
        if (sent > 0) {
            uint64_t bytes = 0;
            for (int k = 0; k < sent; ++k) {
                bytes += iovs[k].iov_len;
                if ((k % 4) == 1) {
                    local_attacks++;
                }
            }
            g_total_packets.fetch_add(sent, std::memory_order_relaxed);
            g_total_bytes.fetch_add(bytes, std::memory_order_relaxed);
        }
    }
    g_total_attacks.fetch_add(local_attacks, std::memory_order_relaxed);
    close(sock);
}

int main(int argc, char **argv) {
    std::signal(SIGINT, sig_handler);
    std::signal(SIGTERM, sig_handler);

    const char *target_ip = (argc > 1) ? argv[1] : "192.168.50.1";
    int num_threads = (argc > 2) ? std::atoi(argv[2]) : 4;

    std::cout << "========================================================\n";
    std::cout << "         AETHON ADVERSARIAL CHAOS TORTURE TEST          \n";
    std::cout << "========================================================\n";
    std::cout << "Target IP    : " << target_ip << "\n";
    std::cout << "Worker Cores : " << num_threads << " (pinned across CPU cores)\n";
    std::cout << "Batch Vector : 64 packets per sendmmsg syscall\n";
    std::cout << "Workload     : 25% SYN Handshakes | 25% Active Injected Exploits\n";
    std::cout << "               25% UDP Medium MTU | 25% TCP Jumbo Data (1.4KB)\n";
    std::cout << "Packet Sizes : Variable IMIX (64B to 1410B)\n";
    std::cout << "Threats      : Real SQL Injections, MySQL dumps, XSS Injections\n";
    std::cout << "Press Ctrl+C to stop the torture test.\n";
    std::cout << "========================================================\n";

    std::vector<std::thread> workers;
    for (int i = 0; i < num_threads; ++i) {
        workers.emplace_back(chaos_worker, i, target_ip);
    }

    uint64_t last_packets = 0;
    uint64_t last_bytes = 0;

    while (g_running.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint64_t cur_packets = g_total_packets.load(std::memory_order_relaxed);
        uint64_t cur_bytes = g_total_bytes.load(std::memory_order_relaxed);

        uint64_t pps = cur_packets - last_packets;
        uint64_t bps = cur_bytes - last_bytes;
        double mbps = (bps * 8.0) / 1000000.0;
        double gbps = mbps / 1000.0;

        std::cout << "\r[Torture] Speed: " << pps << " pps | "
                  << std::fixed << std::setprecision(2) << gbps << " Gbps (" << mbps << " Mbps) | "
                  << "Total: " << cur_packets << " pkts" << std::flush;

        last_packets = cur_packets;
        last_bytes = cur_bytes;
    }

    for (auto &w : workers) {
        w.join();
    }

    std::cout << "\n[Torture] Finished. Total pkts: " << g_total_packets.load()
              << " | Total Injected Attacks: " << g_total_attacks.load() << "\n";
    return 0;
}
