#pragma once

#include "aethon/aethon.h"
#include "common.h"
#include <arpa/inet.h>
#include <array>
#include <asm-generic/socket.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <linux/bpf.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <optional>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

namespace aethon {
namespace xdp {

/*
 * ============================================================================
 * Templated XDP Configuration
 * ============================================================================
 * Easily customize UMEM buffer frame count, frame size, ring descriptor counts,
 * fallback ring capacity, and batch processing budget via template parameters.
 */
template <
    size_t NumFrames = 4096,
    size_t FrameSize = 2048,
    size_t RxRingSize = 2048,
    size_t TxRingSize = 2048,
    size_t FillRingSize = 2048,
    size_t CompRingSize = 2048,
    size_t MaxQueues = 64,
    size_t FallbackCapacity = 4096,
    size_t BatchSize = 64
>
struct XdpConfig {
  static_assert((NumFrames & (NumFrames - 1)) == 0, "NumFrames must be power of 2");
  static_assert((FrameSize & (FrameSize - 1)) == 0, "FrameSize must be power of 2");
  static_assert((RxRingSize & (RxRingSize - 1)) == 0, "RxRingSize must be power of 2");
  static_assert((TxRingSize & (TxRingSize - 1)) == 0, "TxRingSize must be power of 2");
  static_assert((FillRingSize & (FillRingSize - 1)) == 0, "FillRingSize must be power of 2");
  static_assert((CompRingSize & (CompRingSize - 1)) == 0, "CompRingSize must be power of 2");
  static_assert((FallbackCapacity & (FallbackCapacity - 1)) == 0, "FallbackCapacity must be power of 2");
  static_assert(FillRingSize <= NumFrames, "FillRingSize cannot exceed NumFrames");

  static constexpr size_t NUM_FRAMES = NumFrames;
  static constexpr size_t FRAME_SIZE = FrameSize;
  static constexpr size_t UMEM_SIZE = NumFrames * FrameSize;
  static constexpr size_t RX_RING_SIZE = RxRingSize;
  static constexpr size_t TX_RING_SIZE = TxRingSize;
  static constexpr size_t FQ_RING_SIZE = FillRingSize;
  static constexpr size_t CQ_RING_SIZE = CompRingSize;
  static constexpr size_t MAX_QUEUES = MaxQueues;
  static constexpr size_t FALLBACK_CAPACITY = FallbackCapacity;
  static constexpr size_t BATCH_SIZE = BatchSize;
};

using DefaultXdpConfig = XdpConfig<>;

// Zero-copy, stack-allocated, power-of-two circular fallback ring (0 malloc, 0 memmove)
template <size_t Capacity = 2048>
struct alignas(implementation::hardware_destructive_interference_size) FallbackRing {
  static_assert((Capacity & (Capacity - 1)) == 0, "Capacity must be power of 2");
  static constexpr size_t MASK = Capacity - 1;

  uint64_t ring[Capacity];
  uint32_t head{0};
  uint32_t tail{0};

  AETHON_ALWAYS_INLINE bool empty() const noexcept { return head == tail; }
  AETHON_ALWAYS_INLINE size_t size() const noexcept { return head - tail; }

  AETHON_ALWAYS_INLINE bool full() const noexcept { return (head - tail) >= Capacity; }

  AETHON_ALWAYS_INLINE bool push(uint64_t addr) noexcept {
    if (AETHON_UNLIKELY(full())) return false;
    ring[head++ & MASK] = addr;
    return true;
  }

  AETHON_ALWAYS_INLINE uint64_t get(size_t offset = 0) const noexcept {
    return ring[(tail + offset) & MASK];
  }

  AETHON_ALWAYS_INLINE void advance(size_t count) noexcept {
    tail += count;
  }
};

// UMEM information per queue
struct aethon_umen_info {
  struct xsk_ring_prod fq; // Fill Ring (User -> Kernel/NIC)
  struct xsk_ring_cons cq; // Completion Ring (Kernel/NIC -> User)

  struct xsk_umem *umen{nullptr};
  void *buffer{nullptr};
};

// 64-byte aligned to prevent False Sharing / Cache Bouncing across CPU cores
struct alignas(implementation::hardware_destructive_interference_size)
    aethon_xsk_socket_info {
  struct xsk_ring_cons rx; // RX Ring (Kernel/NIC -> User)
  struct xsk_ring_prod tx; // TX Ring (User -> Kernel/NIC)

  struct xsk_socket *xsk{nullptr};
  struct aethon_umen_info *umen{nullptr};
};

// Each queue slot occupies its own dedicated 64-byte cache line
struct alignas(
    implementation::hardware_constructive_interference_size) QueueSlot {
  aethon_xsk_socket_info *socket_info{nullptr};
};
// Query available NIC queues using ethtool ioctl
inline int get_nic_queue_count(const char *ifname) {
  struct ethtool_channels channels {};
  channels.cmd = ETHTOOL_GCHANNELS;
  struct ifreq ifr {};

  std::strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
  ifr.ifr_data = reinterpret_cast<char *>(&channels);
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    return 1; // Fallback to 1 queue if socket fails
  }

  if (ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
    close(fd);
    return channels.combined_count > 0 ? channels.combined_count
                                       : channels.rx_count;
  }
  close(fd);
  return 1;
}

inline bool raise_memory_locking() {
  struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0) {
    return false;
  }
  return true;
}


template <typename Config = DefaultXdpConfig>
class AFXDPEngine {
public:
  using config_type = Config;

  AFXDPEngine() = default;

  ~AFXDPEngine() {
    cleanup();
  }

  // Non-copyable
  AFXDPEngine(const AFXDPEngine &) = delete;
  AFXDPEngine &operator=(const AFXDPEngine &) = delete;

  // Move-constructible
  AFXDPEngine(AFXDPEngine &&other) noexcept
      : ifname_(std::move(other.ifname_)),
        ifindex_(other.ifindex_),
        total_active_queues_(other.total_active_queues_),
        bpf_obj_(other.bpf_obj_),
        xsk_sockets_(other.xsk_sockets_) {
    other.bpf_obj_ = nullptr;
    other.total_active_queues_ = 0;
    for (auto &slot : other.xsk_sockets_) {
      slot.socket_info = nullptr;
    }
  }

  bool setup(const char *ifname,
             const char *prog_name = "src/main/xdp_kern_prog.o",
             const char *prog_section_name = "aethon_xdp_prog_main",
             enum xdp_attach_mode xdp_running_mode = XDP_MODE_SKB,
             const char *xdp_xsk_map_name = "aethon_xsks_map",
             const char *queue_config_map_name = "queue_config_map") {
    ifname_ = ifname;
    ifindex_ = if_nametoindex(ifname);
    if (ifindex_ == 0) {
      std::cerr << "Error: Cannot find interface " << ifname << "\n";
      return false;
    }

    if (!raise_memory_locking()) {
      std::cerr << "Warning: Could not raise RLIMIT_MEMLOCK\n";
    }

    int nic_queues = get_nic_queue_count(ifname);
    int core_count = std::thread::hardware_concurrency();
    int available_worker_cores = core_count > 1 ? core_count - 1 : 1;

    int num_queues = std::min(nic_queues, available_worker_cores);
    if (num_queues > static_cast<int>(Config::MAX_QUEUES)) {
      num_queues = static_cast<int>(Config::MAX_QUEUES);
    }
    total_active_queues_ = num_queues;

    // Adjust NIC channels via ethtool (silenced on virtual interfaces like veth)
    std::string ethtool_cmd = "ethtool -L " + std::string(ifname) +
                              " combined " + std::to_string(num_queues) + " >/dev/null 2>&1";
    system(ethtool_cmd.c_str());

    // Automatically locate eBPF object whether executed from project root or build/src
    std::string resolved_prog = prog_name ? prog_name : "";
    if (resolved_prog.empty() || access(resolved_prog.c_str(), F_OK) != 0) {
      const char *fallbacks[] = {
          "src/main/xdp_kern_prog.o",
          "../../src/main/xdp_kern_prog.o",
          "../src/main/xdp_kern_prog.o",
          "./xdp_kern_prog.o",
          "/home/shivam/Desktop/learning/advanceCpp/Aethon/src/main/xdp_kern_prog.o"
      };
      for (const char *fb : fallbacks) {
        if (access(fb, F_OK) == 0) {
          resolved_prog = fb;
          break;
        }
      }
    }

    // 1. Load eBPF Object
    bpf_obj_ = bpf_object__open_file(resolved_prog.c_str(), NULL);
    if (!bpf_obj_ || bpf_object__load(bpf_obj_)) {
      std::cerr << "Error: Cannot open or load eBPF program from " << resolved_prog << "\n";
      return false;
    }

    // Pass queue count to eBPF map
    struct bpf_map *config_map =
        bpf_object__find_map_by_name(bpf_obj_, queue_config_map_name);
    if (config_map) {
      int config_map_fd = bpf_map__fd(config_map);
      uint32_t key = 0;
      uint32_t val = num_queues;
      bpf_map_update_elem(config_map_fd, &key, &val, BPF_ANY);
      std::cout << "[AFXDPEngine] Configured " << num_queues
                << " queues in eBPF config map\n";
    }

    struct bpf_program *bpf_prog =
        bpf_object__find_program_by_name(bpf_obj_, prog_section_name);
    if (!bpf_prog) {
      std::cerr << "Error: Cannot find program " << prog_section_name << "\n";
      return false;
    }

    int prog_fd = bpf_program__fd(bpf_prog);
    int err = bpf_xdp_attach(ifindex_, prog_fd, xdp_running_mode, NULL);
    if (err < 0) {
      std::cerr << "Error: Cannot attach eBPF program to interface " << ifname << "\n";
      return false;
    }

    struct bpf_map *map =
        bpf_object__find_map_by_name(bpf_obj_, xdp_xsk_map_name);
    if (!map) {
      std::cerr << "Error: Cannot find map " << xdp_xsk_map_name << "\n";
      return false;
    }

    int xsk_map_fd = bpf_map__fd(map);
    if (xsk_map_fd < 0) {
      std::cerr << "Error: Cannot get map fd for " << xdp_xsk_map_name << "\n";
      return false;
    }

    // 2. Setup AF_XDP sockets for EACH queue
    for (int q = 0; q < total_active_queues_; ++q) {
      auto umen_opt = configure_umen();
      if (!umen_opt) {
        std::cerr << "Error: Failed to configure UMEM for queue " << q << "\n";
        return false;
      }
      auto *umen_info = umen_opt.value();

      auto *sock_info = static_cast<aethon_xsk_socket_info *>(
          calloc(1, sizeof(aethon_xsk_socket_info)));

      struct xsk_socket_config xsk_config {
        .rx_size = static_cast<uint32_t>(Config::RX_RING_SIZE),
        .tx_size = static_cast<uint32_t>(Config::TX_RING_SIZE),
        .libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = static_cast<uint32_t>(xdp_running_mode),
        .bind_flags = XDP_COPY
      };

      err = xsk_socket__create(&sock_info->xsk, ifname, q, umen_info->umen,
                               &sock_info->rx, &sock_info->tx, &xsk_config);
      if (err) {
        std::cerr << "Error: Failed to create xsk_socket on queue " << q << "\n";
        return false;
      }

      sock_info->umen = umen_info;

      int xsk_fd = xsk_socket__fd(sock_info->xsk);
      int prefer_busy_bool = 1;
      // give the polling priority to this application thread instead of kernel background ksoftirqd daemon
      setsockopt(xsk_fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, &prefer_busy_bool,
                 sizeof(prefer_busy_bool));

      int busy_poll_usec = 50;
      setsockopt(xsk_fd, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_usec,
                 sizeof(busy_poll_usec)); // if no packet arrive after 50 micros make the thread sleep after pooling

      // kernel grab BATCH_SIZE no of packet and deliver it to the thread and then again run in the loop
      int budget = static_cast<int>(Config::BATCH_SIZE);
      setsockopt(xsk_fd, SOL_SOCKET, SO_BUSY_POLL_BUDGET, &budget,
                 sizeof(budget));
              

      int map_update_err = bpf_map_update_elem(xsk_map_fd, &q, &xsk_fd, 0);
      if (map_update_err < 0) {
        std::cerr << "Error: Failed to update BPF XSK map with socket fd\n";
        return false;
      }

      // Populate Fill Ring with initial UMEM frames
      uint32_t idx = 0;
      uint32_t reserve_size = static_cast<uint32_t>(
          std::min(Config::FQ_RING_SIZE, Config::NUM_FRAMES));
      int fq_res = xsk_ring_prod__reserve(&umen_info->fq, reserve_size, &idx);
      if (fq_res == static_cast<int>(reserve_size)) {
        for (uint32_t i = 0; i < reserve_size; ++i) {
          *xsk_ring_prod__fill_addr(&umen_info->fq, idx++) =
              i * Config::FRAME_SIZE;
        }
        xsk_ring_prod__submit(&umen_info->fq, reserve_size);
      } else {
        std::cerr << "Warning: Failed to reserve " << reserve_size
                  << " slots in Fill Ring (got " << fq_res << ") on queue " << q
                  << "\n";
      }

      xsk_sockets_[q].socket_info = sock_info;
    }

    std::cout << "[AFXDPEngine] Initialized " << total_active_queues_
              << " queues (UMEM: " << (Config::UMEM_SIZE / (1024 * 1024))
              << " MB/queue, Frames: " << Config::NUM_FRAMES
              << " x " << Config::FRAME_SIZE << " B, RX Ring: " << Config::RX_RING_SIZE
              << ", FQ: " << Config::FQ_RING_SIZE << ")\n";
    return true;
  }

  void cleanup() {
    for (int q = 0; q < total_active_queues_; ++q) {
      auto *sock_info = xsk_sockets_[q].socket_info;
      if (sock_info) {
        if (sock_info->xsk) {
          xsk_socket__delete(sock_info->xsk);
        }
        if (sock_info->umen) {
          if (sock_info->umen->umen) {
            xsk_umem__delete(sock_info->umen->umen);
          }
          if (sock_info->umen->buffer) {
            free(sock_info->umen->buffer);
          }
          free(sock_info->umen);
        }
        free(sock_info);
        xsk_sockets_[q].socket_info = nullptr;
      }
    }
    if (bpf_obj_ && ifindex_ > 0) {
      bpf_xdp_detach(ifindex_, 0, NULL);
      bpf_object__close(bpf_obj_);
      bpf_obj_ = nullptr;
    }
    total_active_queues_ = 0;
  }

  int active_queues() const noexcept { return total_active_queues_; }
  const std::string &interface() const noexcept { return ifname_; }

  aethon_xsk_socket_info *get_socket(int queue_id) noexcept {
    if (queue_id < 0 || queue_id >= total_active_queues_) {
      return nullptr;
    }
    return xsk_sockets_[queue_id].socket_info;
  }

private:
  std::optional<aethon_umen_info *> configure_umen() {
    auto *umen = static_cast<aethon_umen_info *>(calloc(1, sizeof(*umen)));
    if (!umen) {
      return std::nullopt;
    }

    void *bufs = nullptr;
    int ret = posix_memalign(&bufs, getpagesize(), Config::UMEM_SIZE);
    if (ret) {
      free(umen);
      return std::nullopt;
    }

    struct xsk_umem_config umem_cfg {
      .fill_size = static_cast<uint32_t>(Config::FQ_RING_SIZE),
      .comp_size = static_cast<uint32_t>(Config::CQ_RING_SIZE),
      .frame_size = static_cast<uint32_t>(Config::FRAME_SIZE),
      .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
      .flags = 0
    };

    int code = xsk_umem__create(&umen->umen, bufs, Config::UMEM_SIZE, &umen->fq,
                                &umen->cq, &umem_cfg);
    if (code) {
      free(bufs);
      free(umen);
      return std::nullopt;
    }

    umen->buffer = bufs;
    return umen;
  }

  std::string ifname_;
  unsigned int ifindex_{0};
  int total_active_queues_{0};
  struct bpf_object *bpf_obj_{nullptr};
  std::array<QueueSlot, Config::MAX_QUEUES> xsk_sockets_{};
};

using DefaultEngine = AFXDPEngine<DefaultXdpConfig>;

} // namespace xdp
} // namespace aethon
