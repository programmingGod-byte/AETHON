#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <iomanip>
#include <cstring>

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sched.h>
#include <pthread.h>

// Align on 64-byte boundary to prevent false sharing
alignas(64) std::atomic<uint64_t> total_packets{0};
alignas(64) std::atomic<uint64_t> total_bytes{0};
std::atomic<bool> global_exit{false};

void stats_printer() {
  uint64_t last_packets = 0;
  uint64_t last_bytes = 0;

  while (!global_exit.load(std::memory_order_relaxed)) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    uint64_t current_packets = total_packets.load(std::memory_order_relaxed);
    uint64_t current_bytes = total_bytes.load(std::memory_order_relaxed);

    uint64_t pps = current_packets - last_packets;
    uint64_t bps = current_bytes - last_bytes;

    double mbps = (bps * 8.0) / 1000000.0;

    std::cout << "\r[Stats] Speed: " << pps << " pps | " 
              << std::fixed << std::setprecision(2) << mbps << " Mbps" << std::flush;

    last_packets = current_packets;
    last_bytes = current_bytes;
  }
  std::cout << "\n";
}

int main(int argc, char **argv) {
  const char *ifname = (argc > 1) ? argv[1] : "veth0";

  std::cout << "Starting Standard Raw Socket Baseline on interface: " << ifname << "\n";
  std::cout << "Warning: If eBPF/AF_XDP is still running, it may steal packets first!\n";

  // Create standard AF_PACKET raw socket
  int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock < 0) {
    perror("socket creation failed");
    return 1;
  }

  // Get interface index
  struct ifreq ifr;
  std::memset(&ifr, 0, sizeof(ifr));
  std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
    perror("ioctl SIOCGIFINDEX failed");
    close(sock);
    return 1;
  }
  int ifindex = ifr.ifr_ifindex;

  // Bind socket to interface
  struct sockaddr_ll sll;
  std::memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifindex;
  if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind failed");
    close(sock);
    return 1;
  }

  // Set Promiscuous mode to ensure we receive all packets
  struct packet_mreq mr;
  std::memset(&mr, 0, sizeof(mr));
  mr.mr_ifindex = ifindex;
  mr.mr_type = PACKET_MR_PROMISC;
  if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0) {
    perror("setsockopt PACKET_MR_PROMISC failed");
    // continue anyway, might not be fatal
  }

  // Spawn stats thread
  std::thread printer(stats_printer);

  // Buffer for reading
  char buffer[4096];
  
  std::cout << "Listening for packets. Press Ctrl+C to stop...\n";

  // Single-threaded packet reading loop
  while (true) {
    int len = recvfrom(sock, buffer, sizeof(buffer), 0, nullptr, nullptr);
    if (len > 0) {
      total_packets.fetch_add(1, std::memory_order_relaxed);
      total_bytes.fetch_add(len, std::memory_order_relaxed);
    } else if (len < 0) {
      perror("recvfrom error");
      break;
    }
  }

  global_exit.store(true);
  printer.join();
  close(sock);
  return 0;
}

