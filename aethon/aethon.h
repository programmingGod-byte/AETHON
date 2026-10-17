#pragma once
#include <bits/stdc++.h>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <sys/syscall.h>
#include <type_traits>
#include <unistd.h>
#include <linux/futex.h>

inline void safe_write_all() {}

template <typename... Rest>
inline void safe_write_all(const char *str, Rest... rest) {
  if (str) {
    ::write(STDERR_FILENO, str, std::strlen(str));
  }
  safe_write_all(rest...);
}

#define AETHON_SAFE_CHECK(expr, ...)                                           \
  do {                                                                         \
    if (!static_cast<bool>(expr)) {                                            \
      safe_write_all("[ASSERT FAILED] (" #expr ") in ", __FILE__, ":",         \
                     __func__, ": ", __VA_ARGS__, "\n");                       \
      ::abort();                                                               \
    }                                                                          \
  } while (false)

#ifdef __x86_64__
#define AETHON_PAUSE_CPU_INSTRUCTION __builtin_ia32_pause();
#else
#define AETHON_PAUSE_CPU_INSTRUCTION
#endif

#ifdef _MSC_VER
constexpr auto kMscVer = _MSC_VER;
#else
constexpr auto kMscVer = 0;
#endif

#if defined(__linux__)
constexpr bool kIsLinux = true;
#else
constexpr bool kIsLinux = false;
#endif

#ifdef __GNUC__
#define AETHON_ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
#define AETHON_ALWAYS_INLINE inline
#endif

#ifdef __GNUC__
#define AETHON_NO_INLINE inline __attribute__((__noinline__))
#else
#define AETHON_NO_INLINE
#endif

#ifdef __GNUC__
#define AETHON_ATTR_VISIBILITY_HIDDEN __attribute__((__visibility__("hidden")))
#else
#define AETHON_ATTR_VISIBILITY_HIDDEN
#endif

#define AETHON_ERASE AETHON_ALWAYS_INLINE AETHON_ATTR_VISIBILITY_HIDDEN

#if defined(__clang__)
    #define AETHON_PRAGMA(x) _Pragma(#x)
    #define AETHON_UNROLL(n) AETHON_PRAGMA(clang loop unroll_count(n))
#elif defined(__GNUC__)
    #define AETHON_PRAGMA(x) _Pragma(#x)
    #define AETHON_UNROLL(n) AETHON_PRAGMA(GCC unroll n)
#elif defined(_MSC_VER)
    #define AETHON_UNROLL(n) __pragma(loop(unroll))
#else
    #define AETHON_UNROLL(n)
#endif

#if defined(__has_feature)
#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__) ||       \
    __has_feature(hwaddress_sanitizer)
#define AETHON_SANITIZE_ADDRESS 1
#endif
#endif

#ifdef AETHON_SANITIZE_ADDRESS
#if defined(__clang__)
#if __has_attribute(__no_sanitize__)
#define AETHON_DISABLE_ADDRESS_SANITIZER                                       \
  __attribute__((__no_sanitize__("address"), __noinline__))                    \
  __attribute__((__no_sanitize__("hwaddress"), __noinline__))
#elif __has_attribute(__no_address_safety_analysis__)
#define AETHON_DISABLE_ADDRESS_SANITIZER                                       \
  __attribute__((__no_address_safety_analysis__, __noinline__))
#elif __has_attribute(__no_sanitize_address__)
#define AETHON_DISABLE_ADDRESS_SANITIZER                                       \
  __attribute__((__no_sanitize_address__, __noinline__))
#endif
#elif defined(__GNUC__)
#define AETHON_DISABLE_ADDRESS_SANITIZER                                       \
  __attribute__((__no_address_safety_analysis__, __noinline__))
#elif defined(_MSC_VER)
#define AETHON_DISABLE_ADDRESS_SANITIZER __declspec(no_sanitize_address)
#endif
#endif
#ifndef AETHON_DISABLE_ADDRESS_SANITIZER
#define AETHON_DISABLE_ADDRESS_SANITIZER
#endif

#if defined(__has_builtin)
#define AETHON_HAS_BUILTIN(x) __has_builtin(x)
#else
#define AETHON_HAS_BUILTIN(x) 0
#endif

#ifndef __has_cpp_attribute
#define AETHON_HAS_CPP_ATTRIBUTE(x) 0
#else
#define AETHON_HAS_CPP_ATTRIBUTE(x) __has_cpp_attribute(x)
#endif

#if AETHON_HAS_BUILTIN(__builtin_unpredictable)
#define AETHON_BUILTIN_UNPREDICTABLE(exp) __builtin_unpredictable(exp)
#else
#define AETHON_BUILTIN_UNPREDICTABLE(exp) (exp)
#endif

#if AETHON_HAS_BUILTIN(__builtin_expect)
#define AETHON_BUILTIN_EXPECT(exp, c)                                          \
  __builtin_expect(static_cast<bool>(exp), c)
#else
#define AETHON_BUILTIN_EXPECT(exp, c) (exp)
#endif

#if AETHON_HAS_BUILTIN(__builtin_expect_with_probability)
#define AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(exp, c, p)                      \
  __builtin_expect_with_probability(exp, c, p)
#else
#define AETHON_BUILTIN_EXPECT_WITH_PROBABILITY(exp, c, p) (exp)
#endif

#if AETHON_HAS_BUILTIN(__builtin_prefetch)
#define AETHON_BUILTIN_PREFETCH(addr, rw, locality)                            \
  __builtin_prefetch((addr), (rw), (locality))
#else
#define AETHON_BUILTIN_PREFETCH(addr, rw, locality) ((void)0)
#endif

#define AETHON_LIKELY(...) AETHON_BUILTIN_EXPECT((__VA_ARGS__), 1)
#define AETHON_UNLIKELY(...) AETHON_BUILTIN_EXPECT((__VA_ARGS__), 0)


// call in tail call return next_step();
#if AETHON_HAS_CPP_ATTRIBUTE(gnu::musttail)
#define AETHON_ATTR_MUSTTAIL [[gnu::musttail]]
#elif AETHON_HAS_CPP_ATTRIBUTE(clang::musttail)
#define AETHON_ATTR_MUSTTAIL [[clang::musttail]]
#elif AETHON_HAS_CPP_ATTRIBUTE(msvc::musttail)
#define AETHON_ATTR_MUSTTAIL [[msvc::musttail]]
#else
#define AETHON_ATTR_MUSTTAIL
#endif

// in cpp every object must have a unique memory address and every type must have a size of at least 1 byte 
/*
struct StatelessAllocator {}  ---? 1 byte
struct Buffer {
    [[no_unique_address]] StatelessAllocator alloc; // Takes 0 bytes!
    int* data;
    size_t size;
};
*/
#if AETHON_HAS_CPP_ATTRIBUTE(no_unique_address)
#define AETHON_ATTR_NO_UNIQUE_ADDRESS [[no_unique_address]]
#elif AETHON_HAS_CPP_ATTRIBUTE(msvc::no_unique_address)
#define AETHON_ATTR_NO_UNIQUE_ADDRESS [[msvc::no_unique_address]]
#else
#define AETHON_ATTR_NO_UNIQUE_ADDRESS
#endif

#if AETHON_HAS_CPP_ATTRIBUTE(gnu::flatten)
#define AETHON_ATTR_GNU_FLATTEN [[gnu::flatten]]
#else
#define AETHON_ATTR_GNU_FLATTEN
#endif

#if AETHON_HAS_CPP_ATTRIBUTE(gnu::cold)
#define AETHON_ATTR_GNU_COLD [[gnu::cold]]
#else
#define AETHON_ATTR_GNU_COLD
#endif

namespace Trait {

template <typename...> inline constexpr bool always_false = false;
template <typename...> struct tag_t {};
template <typename... T> inline constexpr tag_t<T...> tag{};

template <auto...> struct vtag_t {};
template <auto... V> inline constexpr vtag_t<V...> vtag{};

template <template <typename...> class, typename>
inline constexpr bool is_instantiation_of_v = false;
template <template <typename...> class C, typename... T>
inline constexpr bool is_instantiation_of_v<C, C<T...>> = true;

template <typename T1, typename T2>
constexpr std::size_t get_type_size(tag_t<T1, T2>) {
  return sizeof(T1) + sizeof(T2);
}

template <auto V1, auto V2> constexpr auto get_value_sum(vtag_t<V1, V2>) {
  return V1 + V2;
}

template <typename T> inline constexpr bool is_bounded_array_v = false;
template <typename T, std::size_t S>
inline constexpr bool is_bounded_array_v<T[S]> = true;

template <typename T> inline constexpr bool is_unbounded_array_v = false;
template <typename T> inline constexpr bool is_unbounded_array_v<T[]> = true;

} // namespace Trait

namespace implementation {

// if the value at memory adrr adrr is val put the thread to sleep until someone wakeup me
// sizeof(std::mutex) = 40 bytes suze
AETHON_ALWAYS_INLINE void futex_wait(std::atomic<uint32_t>*addr, uint32_t val){
  syscall(SYS_futex,reinterpret_cast<int*>(addr),FUTEX_WAIT_PRIVATE,val,nullptr,nullptr,0);
}

AETHON_ALWAYS_INLINE void futex_wake(std::atomic<uint32_t>* addr) {
    syscall(SYS_futex, reinterpret_cast<int*>(addr), FUTEX_WAKE_PRIVATE, 1, nullptr, nullptr, 0);
}

constexpr std::size_t register_pass_max_size =
    (kMscVer ? 1u : 2u) * sizeof(void *);

template <typename T>
constexpr bool is_register_pass_v =
    (sizeof(T) <= register_pass_max_size && std::is_trivially_copyable_v<T>);

template <typename T> constexpr bool is_register_pass_v<T &> = true;
template <typename T> constexpr bool is_register_pass_v<T &&> = true;

template <typename T>
using register_pass_t =
    std::conditional_t<is_register_pass_v<T>, T const, T const &>;

template <typename T>
using register_pass_t_modify = std::conditional<is_register_pass_v<T>, T, T &>;

constexpr bool has_extended_alignment =
    kIsLinux && sizeof(void *) >= sizeof(std::uint64_t);

template <typename... Ts> struct max_align_t_ {
  static constexpr std::size_t value() {
    std::size_t const values[] = {0u, alignof(Ts)...};
    std::size_t r = 0u;

    for (auto const v : values) {
      r = r < v ? v : r;
    }
    return r;
  }
};

constexpr std::size_t max_align_v_ =
    max_align_t_<long double, double, float, long long int, long int, int,
                 short int, bool, char, char16_t, char32_t, wchar_t, void *,
                 std::max_align_t>::value();

template <typename T, std::size_t Alignment = alignof(T)>
T *smart_allocate(std::size_t count = 1) {
  std::size_t total_bytes = sizeof(T) * count;
  void *raw_ptr = nullptr;

  if constexpr (Alignment <= max_align_v_) {
    raw_ptr = std::malloc(total_bytes);
  } else {
    std::size_t padded_bytes = (total_bytes + Alignment - 1) & ~(Alignment - 1);
    raw_ptr = std::aligned_alloc(Alignment, padded_bytes);
  }

  if (!raw_ptr) {
    throw std::bad_alloc();
  }

  return static_cast<T *>(raw_ptr);
}

#if defined(__cpp_lib_hardware_interference_size)
constexpr std::size_t hardware_constructive_interference_size =
    std::hardware_constructive_interference_size;
constexpr std::size_t hardware_destructive_interference_size =
    std::hardware_destructive_interference_size;
#else
constexpr std::size_t hardware_destructive_interference_size = 64;
constexpr std::size_t hardware_constructive_interference_size = 64;
#endif

constexpr std::size_t cacheline_align_v =
    has_extended_alignment ? hardware_constructive_interference_size
                           : max_align_v_;

struct alignas(cacheline_align_v) cacheline_align_t {};

constexpr std::size_t cacheline_disalign_v =
    has_extended_alignment ? hardware_destructive_interference_size
                           : max_align_v_;

struct alignas(cacheline_disalign_v) cacheline_disalign_t {};

struct valid_align_value_fn {
  static_assert(sizeof(std::size_t) <= sizeof(std::uintptr_t));
  constexpr bool operator()(std::size_t align) const noexcept {
    return align && !(align & (align - 1));
  }
  constexpr bool operator()(std::align_val_t align) const noexcept {
    return operator()(static_cast<std::size_t>(align));
  }
};

inline constexpr valid_align_value_fn valid_align_value;

struct align_floor_fn {
  constexpr std::uintptr_t operator()(std::uintptr_t x,
                                      std::size_t alignment) const {
    assert(valid_align_value(alignment));
    return x & ~(alignment - 1);
  }

  template <typename T> T *operator()(T *x, std::size_t alignment) const {
    auto asUint = reinterpret_cast<std::uintptr_t>(x);
    asUint = (*this)(asUint, alignment);
    return reinterpret_cast<T *>(asUint);
  }
};
inline constexpr align_floor_fn align_floor;

struct align_ceil_fn {
  constexpr std::uintptr_t operator()(std::uintptr_t x,
                                      std::size_t alignment) const {
    assert(valid_align_value(alignment));
    auto alignmentAsInt = static_cast<std::intptr_t>(alignment);
    return (x + alignmentAsInt - 1) & (-alignmentAsInt);
  }

  template <typename T> T *operator()(T *x, std::size_t alignment) const {
    auto asUint = reinterpret_cast<std::uintptr_t>(x);
    asUint = (*this)(asUint, alignment);
    return reinterpret_cast<T *>(asUint);
  }
};
inline constexpr align_ceil_fn align_ceil;

AETHON_DISABLE_ADDRESS_SANITIZER
inline void custom_unaligned_raw_memory_access(void *ptr) {
  std::uintptr_t addr = reinterpret_cast<std::uintptr_t>(ptr);
  (void)addr;
}

inline int factorial_tail(int n, int acc = 1) {
  if (n <= 1)
    return acc;
  AETHON_ATTR_MUSTTAIL return factorial_tail(n - 1, n * acc);
}

} // namespace implementation

namespace variableTemplates {
template <typename T> constexpr bool is_pointer = false;
template <typename T> constexpr bool is_pointer<T *> = true;
} // namespace variableTemplates
