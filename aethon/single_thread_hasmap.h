#pragma once

#include "aethon/aethon.h"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace aethon {

template <typename T> struct SingleThreadDefaultHash {
  AETHON_ALWAYS_INLINE size_t operator()(T key) const noexcept {
    uint64_t x = static_cast<uint64_t>(key);
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return static_cast<size_t>(x);
  }
};

template <> struct SingleThreadDefaultHash<std::string> {
  AETHON_ALWAYS_INLINE size_t
  operator()(const std::string &key) const noexcept {
    uint64_t hash = 14695981039346656037ULL;
    for (char c : key) {
      hash ^= static_cast<uint64_t>(c);
      hash *= 1099511628211ULL;
    }
    return static_cast<size_t>(hash);
  }
};


template <typename Key, typename Value, Key EmptyKey = Key{},
          typename Hash = SingleThreadDefaultHash<Key>>
class SingleThreadHashMap {
public:
  // Align Cell to avoid split cacheline accesses
  struct alignas(implementation::hardware_destructive_interference_size) Cell {
    Key key{EmptyKey};
    Value val{};

    Cell() = default;
  };

private:
  Cell *cells_{nullptr};
  size_t capacity_{0};
  size_t mask_{0};
  Hash hasher_{};
  size_t size_{0};

  AETHON_ALWAYS_INLINE size_t hash_key(const Key &key) const noexcept {
    return hasher_(key);
  }

public:
  explicit SingleThreadHashMap(size_t capacity = 1024) : size_(0) {
    AETHON_SAFE_CHECK((capacity & (capacity - 1)) == 0,
                      "SingleThreadHashMap capacity must be a power of 2!");

    capacity_ = capacity;
    mask_ = capacity_ - 1;
    cells_ = implementation::smart_allocate<Cell, implementation::hardware_destructive_interference_size>(capacity_);
    for (size_t i = 0; i < capacity_; ++i) {
      new (&cells_[i]) Cell();
    }
  }

  ~SingleThreadHashMap() {
    if (cells_) {
      if constexpr (!std::is_trivially_destructible<Value>::value) {
        for (size_t i = 0; i < capacity_; ++i) {
          if (cells_[i].key != EmptyKey) {
            cells_[i].val.~Value();
          }
        }
      }
      std::free(cells_);
      cells_ = nullptr;
    }
  }

  SingleThreadHashMap(const SingleThreadHashMap &) = delete;
  SingleThreadHashMap &operator=(const SingleThreadHashMap &) = delete;

  SingleThreadHashMap(SingleThreadHashMap &&other) noexcept
      : cells_(other.cells_), capacity_(other.capacity_), mask_(other.mask_),
        hasher_(std::move(other.hasher_)), size_(other.size_) {
    other.cells_ = nullptr;
    other.capacity_ = 0;
    other.mask_ = 0;
    other.size_ = 0;
  }

  SingleThreadHashMap &operator=(SingleThreadHashMap &&other) noexcept {
    if (this != &other) {
      if (cells_) {
        std::free(cells_);
      }
      cells_ = other.cells_;
      capacity_ = other.capacity_;
      mask_ = other.mask_;
      hasher_ = std::move(other.hasher_);
      size_ = other.size_;

      other.cells_ = nullptr;
      other.capacity_ = 0;
      other.mask_ = 0;
      other.size_ = 0;
    }
    return *this;
  }

  template <typename... Args>
  AETHON_ALWAYS_INLINE bool emplace(const Key &key, Args &&...args) {
    AETHON_SAFE_CHECK(key != EmptyKey,
                      "Cannot insert sentinel EmptyKey into SingleThreadHashMap!");

    size_t idx = hash_key(key) & mask_;
    size_t probes = 0;

    while (AETHON_LIKELY(probes < capacity_)) {
      AETHON_BUILTIN_PREFETCH(&cells_[(idx + 1) & mask_], 1, 3);
      const Key &k = cells_[idx].key;

      if (AETHON_LIKELY(k == EmptyKey)) {
        cells_[idx].key = key;
        cells_[idx].val = Value(std::forward<Args>(args)...);
        ++size_;
        return true; // Newly inserted
      }

      if (AETHON_UNLIKELY(k == key)) {
        cells_[idx].val = Value(std::forward<Args>(args)...);
        return false; // Updated existing key
      }

      idx = (idx + 1) & mask_;
      ++probes;
    }

    return false;
  }

  AETHON_ALWAYS_INLINE bool insert(const Key &key, const Value &val) {
    return emplace(key, val);
  }

  AETHON_ALWAYS_INLINE bool insert(const Key &key, Value &&val) {
    return emplace(key, std::move(val));
  }

  AETHON_ALWAYS_INLINE Value *find(const Key &key) noexcept {
    AETHON_SAFE_CHECK(key != EmptyKey, "Cannot search for EmptyKey!");

    size_t idx = hash_key(key) & mask_;
    size_t probes = 0;
    const size_t max_search = std::min(capacity_, static_cast<size_t>(64));

    while (AETHON_LIKELY(probes < max_search)) {
      AETHON_BUILTIN_PREFETCH(&cells_[(idx + 1) & mask_], 0, 3);
      const Key &k = cells_[idx].key;

      if (k == key) {
        return &cells_[idx].val;
      }

      if (k == EmptyKey) {
        return nullptr; 
      }

      idx = (idx + 1) & mask_;
      ++probes;
    }

    return nullptr;
  }

  AETHON_ALWAYS_INLINE const Value *find(const Key &key) const noexcept {
    return const_cast<SingleThreadHashMap *>(this)->find(key);
  }

  AETHON_ALWAYS_INLINE bool contains(const Key &key) const noexcept {
    return find(key) != nullptr;
  }

  AETHON_ALWAYS_INLINE bool erase(const Key &key) noexcept {
    AETHON_SAFE_CHECK(key != EmptyKey, "Cannot erase EmptyKey!");

    size_t i = hash_key(key) & mask_;
    size_t probes = 0;

    while (AETHON_LIKELY(probes < capacity_)) {
      if (cells_[i].key == key) {
        break; // Found the target slot
      }
      if (cells_[i].key == EmptyKey) {
        return false; // Key does not exist in table
      }
      i = (i + 1) & mask_;
      ++probes;
    }

    if (AETHON_UNLIKELY(probes >= capacity_)) {
      return false;
    }

    size_t j = i; // 'i' is current empty hole

    while (true) {
      j = (j + 1) & mask_;

      if (cells_[j].key == EmptyKey || j == i) {
        break;
      }

      size_t k = hash_key(cells_[j].key) & mask_;

      bool can_shift = false;
      if (i <= j) {
        can_shift = (k <= i || k > j);
      } else {
        can_shift = (k <= i && k > j);
      }

      if (can_shift) {
        cells_[i].key = cells_[j].key;
        cells_[i].val = std::move(cells_[j].val);

        i = j; // 'j' is the new hole to be filled
      }
    }

    cells_[i].key = EmptyKey;
    if constexpr (!std::is_trivially_destructible<Value>::value) {
      cells_[i].val.~Value();
    }
    cells_[i].val = Value{};

    --size_;
    return true;
  }

  AETHON_ALWAYS_INLINE size_t size() const noexcept { return size_; }
  AETHON_ALWAYS_INLINE size_t capacity() const noexcept { return capacity_; }
  AETHON_ALWAYS_INLINE bool empty() const noexcept { return size_ == 0; }
  AETHON_ALWAYS_INLINE size_t mask() const noexcept { return mask_; }

  AETHON_ALWAYS_INLINE Cell *cells() noexcept { return cells_; }
  AETHON_ALWAYS_INLINE const Cell *cells() const noexcept { return cells_; }
};

} // namespace aethon
