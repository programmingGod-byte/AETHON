#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <iostream>
#include <mutex>
#include <pthread.h>
#include <sched.h>
#include <thread>
#include <unordered_map>
#include <vector>
#include <x86intrin.h>

#include "FastHashMap.h"
#include "FastVector.h"
#include "mpmcQueue.h"
#include "spscQueue.cpp"

static constexpr size_t QUEUE_NUM_OPS = 10'000'000;
static constexpr size_t VECTOR_NUM_OPS = 100'000'000;
static constexpr size_t MAP_NUM_OPS = 10'000'000;
static constexpr size_t QUEUE_CAPACITY = 65536;

inline uint64_t rdtsc() {
  unsigned int aux;
  return __rdtscp(&aux);
}

template <typename T> inline void do_not_optimize(T &&value) {
  asm volatile("" : : "g"(value) : "memory");
}

void set_thread_affinity_and_rt_priority(int core_id) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core_id, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

  sched_param param;
  param.sched_priority = 99;
  pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);
}

namespace QueueBenchmarks {

void benchmark_std_deque() {
  std::cout << "\n----------------------------------------\n";
  std::cout << "  Benchmarking std::deque + mutex (10M Ops) [Pinned Core 2 & 3]\n";
  std::cout << "----------------------------------------\n";

  std::deque<uint64_t> deq;
  std::mutex mtx;

  uint64_t start_cycles = rdtsc();

  std::thread producer([&]() {
    set_thread_affinity_and_rt_priority(2);
    for (uint64_t i = 0; i < QUEUE_NUM_OPS; ++i) {
      std::lock_guard<std::mutex> lock(mtx);
      deq.push_back(i);
    }
  });

  std::thread consumer([&]() {
    set_thread_affinity_and_rt_priority(3);
    uint64_t items_read = 0;
    while (items_read < QUEUE_NUM_OPS) {
      bool popped = false;
      uint64_t val = 0;
      {
        std::lock_guard<std::mutex> lock(mtx);
        if (!deq.empty()) {
          val = deq.front();
          deq.pop_front();
          popped = true;
          ++items_read;
        }
      }
      if (!popped) {
        AETHON_PAUSE_CPU_INSTRUCTION;
      }
    }
  });

  producer.join();
  consumer.join();

  uint64_t end_cycles = rdtsc();
  uint64_t total_cycles = end_cycles - start_cycles;
  double avg_cycles_per_op = static_cast<double>(total_cycles) / QUEUE_NUM_OPS;

  std::cout << "std::deque Total CPU Cycles: " << total_cycles << " cycles\n";
  std::cout << "std::deque Avg Cycles / Op : " << avg_cycles_per_op << " cycles/op\n";
}

void benchmark_spsc() {
  std::cout << "\n----------------------------------------\n";
  std::cout << "  Benchmarking SPSC Queue (10M Ops) [Pinned Core 2 & 3]\n";
  std::cout << "----------------------------------------\n";

  aethon::detail::ProducerConsumerQueue<uint64_t> queue(QUEUE_CAPACITY);

  uint64_t start_cycles = rdtsc();

  std::thread producer([&]() {
    set_thread_affinity_and_rt_priority(2);
    for (uint64_t i = 0; i < QUEUE_NUM_OPS; ++i) {
      while (!queue.write(i)) {
        AETHON_PAUSE_CPU_INSTRUCTION;
      }
    }
  });

  std::thread consumer([&]() {
    set_thread_affinity_and_rt_priority(3);
    uint64_t val = 0;
    for (uint64_t i = 0; i < QUEUE_NUM_OPS; ++i) {
      while (!queue.read(val)) {
        AETHON_PAUSE_CPU_INSTRUCTION;
      }
    }
  });

  producer.join();
  consumer.join();

  uint64_t end_cycles = rdtsc();
  uint64_t total_cycles = end_cycles - start_cycles;
  double avg_cycles_per_op = static_cast<double>(total_cycles) / QUEUE_NUM_OPS;

  std::cout << "SPSC Total CPU Cycles: " << total_cycles << " cycles\n";
  std::cout << "SPSC Avg Cycles / Op : " << avg_cycles_per_op << " cycles/op\n";
}

void benchmark_mpmc() {
  std::cout << "\n----------------------------------------\n";
  std::cout << "  Benchmarking MPMC Queue (10M Ops) [Pinned Core 2 & 3]\n";
  std::cout << "----------------------------------------\n";

  aethon::MpmcQueue<uint64_t> queue(QUEUE_CAPACITY);

  uint64_t start_cycles = rdtsc();

  std::thread producer([&]() {
    set_thread_affinity_and_rt_priority(2);
    for (uint64_t i = 0; i < QUEUE_NUM_OPS; ++i) {
      queue.write(i);
    }
  });

  std::thread consumer([&]() {
    set_thread_affinity_and_rt_priority(3);
    uint64_t val = 0;
    for (uint64_t i = 0; i < QUEUE_NUM_OPS; ++i) {
      queue.read(val);
    }
  });

  producer.join();
  consumer.join();

  uint64_t end_cycles = rdtsc();
  uint64_t total_cycles = end_cycles - start_cycles;
  double avg_cycles_per_op = static_cast<double>(total_cycles) / QUEUE_NUM_OPS;

  std::cout << "MPMC Total CPU Cycles: " << total_cycles << " cycles\n";
  std::cout << "MPMC Avg Cycles / Op : " << avg_cycles_per_op << " cycles/op\n";
}

} // namespace QueueBenchmarks

namespace VectorBenchmarks {

void benchmark_std_array() {
  std::cout << "\n----------------------------------------\n";
  std::cout << "  Benchmarking std::array (100M Short-Lived Arrays) [Pinned Core 2]\n";
  std::cout << "----------------------------------------\n";

  set_thread_affinity_and_rt_priority(2);

  uint64_t start_cycles = rdtsc();

  for (size_t i = 0; i < VECTOR_NUM_OPS; ++i) {
    std::array<uint64_t, 4> arr;
    arr[0] = i;
    arr[1] = i + 1;
    arr[2] = i + 2;
    arr[3] = i + 3;
    do_not_optimize(arr.data());
  }

  uint64_t end_cycles = rdtsc();
  uint64_t total_cycles = end_cycles - start_cycles;
  double avg_cycles_per_op = static_cast<double>(total_cycles) / VECTOR_NUM_OPS;

  std::cout << "std::array Total Cycles: " << total_cycles << " cycles\n";
  std::cout << "std::array Avg Cycles / Array (4 items): "
            << avg_cycles_per_op << " cycles/op\n";
}

void benchmark_std_vector() {
  std::cout << "\n----------------------------------------\n";
  std::cout << "  Benchmarking std::vector (100M Short-Lived Vectors) [Pinned Core 2]\n";
  std::cout << "----------------------------------------\n";

  set_thread_affinity_and_rt_priority(2);

  uint64_t start_cycles = rdtsc();

  for (size_t i = 0; i < VECTOR_NUM_OPS; ++i) {
    std::vector<uint64_t> vec;
    vec.push_back(i);
    vec.push_back(i + 1);
    vec.push_back(i + 2);
    vec.push_back(i + 3);
    do_not_optimize(vec.data());
  }

  uint64_t end_cycles = rdtsc();
  uint64_t total_cycles = end_cycles - start_cycles;
  double avg_cycles_per_op = static_cast<double>(total_cycles) / VECTOR_NUM_OPS;

  std::cout << "std::vector Total Cycles: " << total_cycles << " cycles\n";
  std::cout << "std::vector Avg Cycles / Vector (4 items): "
            << avg_cycles_per_op << " cycles/op\n";
}

void benchmark_aethon_small_vector() {
  std::cout << "\n----------------------------------------\n";
  std::cout << "  Benchmarking aethon::SmallVector (100M Short-Lived Vectors) [Pinned Core 2]\n";
  std::cout << "----------------------------------------\n";

  set_thread_affinity_and_rt_priority(2);

  uint64_t start_cycles = rdtsc();

  for (size_t i = 0; i < VECTOR_NUM_OPS; ++i) {
    aethon::SmallVector<uint64_t, 4> vec;
    vec.push_back(i);
    vec.push_back(i + 1);
    vec.push_back(i + 2);
    vec.push_back(i + 3);
    do_not_optimize(vec.data());
  }

  uint64_t end_cycles = rdtsc();
  uint64_t total_cycles = end_cycles - start_cycles;
  double avg_cycles_per_op = static_cast<double>(total_cycles) / VECTOR_NUM_OPS;

  std::cout << "aethon::SmallVector Total Cycles: " << total_cycles << " cycles\n";
  std::cout << "aethon::SmallVector Avg Cycles / Vector (4 items): "
            << avg_cycles_per_op << " cycles/op\n";
}

} // namespace VectorBenchmarks

namespace HashMapBenchmarks {

void benchmark_std_unordered_map() {
  std::cout << "\n----------------------------------------\n";
  std::cout << "  Benchmarking std::unordered_map + mutex (10M Concurrent Ops, 4 Threads)\n";
  std::cout << "----------------------------------------\n";

  std::unordered_map<uint64_t, uint64_t> map;
  std::mutex mtx;

  constexpr size_t THREADS = 4;
  constexpr size_t OPS_PER_THREAD = MAP_NUM_OPS / THREADS;
  std::vector<std::thread> threads;

  uint64_t start_cycles = rdtsc();

  for (size_t t = 0; t < THREADS; ++t) {
    threads.emplace_back([&, t]() {
      set_thread_affinity_and_rt_priority(t % 4);
      for (size_t i = 0; i < OPS_PER_THREAD; ++i) {
        uint64_t key = (t * OPS_PER_THREAD) + i + 1;
        std::lock_guard<std::mutex> lock(mtx);
        map[key] = key * 10;
      }
    });
  }

  for (auto &th : threads) {
    th.join();
  }

  uint64_t end_cycles = rdtsc();
  uint64_t total_cycles = end_cycles - start_cycles;
  double avg_cycles_per_op = static_cast<double>(total_cycles) / MAP_NUM_OPS;

  std::cout << "std::unordered_map Total Cycles: " << total_cycles << " cycles\n";
  std::cout << "std::unordered_map Avg Cycles / Insert: "
            << avg_cycles_per_op << " cycles/op\n";
}

void benchmark_aethon_lockfree_hashmap() {
  std::cout << "\n----------------------------------------\n";
  std::cout << "  Benchmarking aethon::LockFreeHashMap (10M Concurrent Ops, 4 Threads)\n";
  std::cout << "----------------------------------------\n";

  aethon::LockFreeHashMap<uint64_t, uint64_t> map(16777216);

  constexpr size_t THREADS = 4;
  constexpr size_t OPS_PER_THREAD = MAP_NUM_OPS / THREADS;
  std::vector<std::thread> threads;

  uint64_t start_cycles = rdtsc();

  for (size_t t = 0; t < THREADS; ++t) {
    threads.emplace_back([&, t]() {
      set_thread_affinity_and_rt_priority(t % 4);
      for (size_t i = 0; i < OPS_PER_THREAD; ++i) {
        uint64_t key = (t * OPS_PER_THREAD) + i + 1;
        map.insert(key, key * 10);
      }
    });
  }

  for (auto &th : threads) {
    th.join();
  }

  uint64_t end_cycles = rdtsc();
  uint64_t total_cycles = end_cycles - start_cycles;
  double avg_cycles_per_op = static_cast<double>(total_cycles) / MAP_NUM_OPS;

  std::cout << "aethon::LockFreeHashMap Total Cycles: " << total_cycles << " cycles\n";
  std::cout << "aethon::LockFreeHashMap Avg Cycles / Insert: "
            << avg_cycles_per_op << " cycles/op\n";
}

} // namespace HashMapBenchmarks

int main() {
  std::cout << "=====================================================\n";
  std::cout << "  AETHON HIGH-PERFORMANCE SUITE RDTSC BENCHMARKS    \n";
  std::cout << "=====================================================\n";

  // 1. Lock-Free Queue Benchmarks
  QueueBenchmarks::benchmark_std_deque();
  QueueBenchmarks::benchmark_spsc();
  QueueBenchmarks::benchmark_mpmc();

  // 2. Small Buffer Optimization Vector Benchmarks
  VectorBenchmarks::benchmark_std_array();
  VectorBenchmarks::benchmark_std_vector();
  VectorBenchmarks::benchmark_aethon_small_vector();

  // 3. Lock-Free Concurrent Hash Map Benchmarks
  HashMapBenchmarks::benchmark_std_unordered_map();
  HashMapBenchmarks::benchmark_aethon_lockfree_hashmap();

  std::cout << "\n=====================================================\n";
  std::cout << "  ALL BENCHMARKS COMPLETED SUCCESSFULLY!            \n";
  std::cout << "=====================================================\n";
  return 0;
}
