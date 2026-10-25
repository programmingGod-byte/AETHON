#pragma once
#include "aethon/aethon.h"

#ifndef AETHON_ALWAYS_INLINE
#if defined(__GNUC__) || defined(__clang__)
#define AETHON_ALWAYS_INLINE inline __attribute__((__always_inline__))
#else
#define AETHON_ALWAYS_INLINE inline
#endif
#endif
#include "hs_common.h"
#include "hs_compile.h"
#include "hs_runtime.h"
#include <chrono>
#include <cstdlib>
#include "rule_parser.h"
#include <cstddef>
#include <hs/hs.h>
#include <cstdint>
#include <memory>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <iostream>
#include <functional>
#include "aethon/function.h"
#include "aethon/single_thread_hasmap.h"

namespace aethon {
    namespace scan {
        

        struct AttackAlert {
            uint32_t sid{0};
            const rules::AethonRule *rule{nullptr};
            uint64_t match_offset{0};
            const uint8_t *payload{nullptr};
            size_t payload_len{0};
            bool blocking{false};      // the rule resets the connection (false: log only)
        };

        // Result of compiling a rule set, for startup logs and tests
        struct CompileStats {
            size_t candidates{0};
            size_t compiled{0};
            size_t blocking{0};
            size_t skipped_invalid{0};   // regex Hyperscan does not support (e.g. backreferences)
            size_t skipped_weak{0};      // can match fewer than kMinPatternBytes bytes: would hit random data
            double compile_ms{0};
            size_t database_bytes{0};
            size_t stream_state_bytes{0};// per-connection memory for streaming scans
            bool from_cache{false};      // loaded from the serialized-DB cache instead of compiled
        };

        // Shortest match allowed for rules from third-party sets. Random uploads contain any given
        // 4-byte sequence about once per 4 GB / 5 MB ~ 1000 uploads; 6+ bytes make that negligible.
        inline constexpr unsigned kMinPatternBytes = 6;

        using AlertCallback = aethon::Function<void(const AttackAlert &)>;
        using RuleMap = aethon::SingleThreadHashMap<uint32_t, const rules::AethonRule*, 0>;

        struct MatchContext {
            const RuleMap *rule_map{nullptr};
            const AlertCallback *alert_cb{nullptr};
            const uint8_t *payload{nullptr};
            size_t payload_len{0};
            size_t match_count{0};
        };

        static int on_match_event(unsigned int id, unsigned long long from,
                                  unsigned long long to, unsigned int flags,
                                  void *context) noexcept {
            (void)from;
            (void)flags;
            auto *ctx = reinterpret_cast<MatchContext *>(context);
            if (AETHON_UNLIKELY(!ctx)) {
                return 0;
            }

            if (AETHON_LIKELY(ctx->rule_map)) {
                const auto *found = ctx->rule_map->find(id);
                if (AETHON_LIKELY(found != nullptr && *found != nullptr)) {
                    const rules::AethonRule *rule = *found;

                    if (!rule->contents.empty()) {
                        const auto &first = rule->contents[0];
                        // Real byte length: pattern is an escaped regex ("\\x0d" is one byte)
                        size_t pat_len = first.bytes.size();

                        if (first.offset >= 0) {
                            size_t min_end = static_cast<size_t>(first.offset) + pat_len;
                            if (to < min_end) {
                                return 0;
                            }
                        }

                        if (first.depth >= 0) {
                            size_t start_base = (first.offset >= 0) ? static_cast<size_t>(first.offset) : 0;
                            size_t max_end = start_base + static_cast<size_t>(first.depth);
                            if (to > max_end) {
                                return 0;
                            }
                        }
                    }

                    if (rule->block) {
                        ctx->match_count++;      // only blocking rules reset the connection
                    }
                    if (ctx->alert_cb && *(ctx->alert_cb)) {
                        AttackAlert alert;
                        alert.blocking = rule->block;
                        alert.sid = id;
                        alert.match_offset = to;
                        alert.payload = ctx->payload;
                        alert.payload_len = ctx->payload_len;
                        alert.rule = rule;
                        (*(ctx->alert_cb))(alert);
                    }
                }
            }
            return 0;
        }

        class HyperscanWorker;

        class alignas(implementation::hardware_destructive_interference_size) HyperscanEngine {
            public:
                using RuleMap = scan::RuleMap;

            private:
                hs_database_t * db_{nullptr};
                hs_scratch_t * scratch_{nullptr};

                std::unique_ptr<RuleMap> rule_map_{nullptr};
                AlertCallback alert_cb_{};

                static size_t next_power_of_two(size_t n) noexcept {
                    if (n < 64) return 64;
                    --n;
                    n |= n >> 1;
                    n |= n >> 2;
                    n |= n >> 4;
                    n |= n >> 8;
                    n |= n >> 16;
                    n |= n >> 32;
                    return n + 1;
                }

            public:
                HyperscanEngine() = default;
                ~HyperscanEngine(){
                    clear();
                }

                void clear() noexcept{
                    if(scratch_){
                        hs_free_scratch(scratch_);
                        scratch_ = nullptr;
                    }
                    if(db_){
                        hs_free_database(db_);
                        db_ = nullptr;
                    }
                }

                HyperscanEngine(const HyperscanEngine &) = delete;
                HyperscanEngine &operator=(const HyperscanEngine&) = delete;

                void set_alert_callback(AlertCallback cb) noexcept {
                   alert_cb_ = std::move(cb);
                }

                bool compile_rules(const rules::RuleDatabase &rule_db) {
                    CompileStats st;
                    return compile_rules(rule_db, st);
                }

            private:
                // Turns the rule set into the (id, flag, pattern) lists for hs_compile_multi and
                // (re)builds rule_map_. Deterministic, so its hash keys the compiled-DB cache.
                void select_patterns(const rules::RuleDatabase &rule_db, CompileStats &st,
                                     std::vector<std::string> &pattern_strings,
                                     std::vector<unsigned int> &flags,
                                     std::vector<unsigned int> &ids) {
                    const auto &all_rules = rule_db.rules();
                    size_t n = all_rules.size();
                    rule_map_ = std::make_unique<RuleMap>(next_power_of_two(n * 2));
                    pattern_strings.reserve(n); flags.reserve(n); ids.reserve(n);

                    for (const auto &r : all_rules) {
                        std::string pattern;
                        unsigned int flag = HS_FLAG_SINGLEMATCH | HS_FLAG_DOTALL;

                        if (!r.contents.empty()) {
                            pattern = r.contents[0].pattern;
                            if (r.contents[0].nocase) flag |= HS_FLAG_CASELESS;
                            for (size_t c = 1; c < r.contents.size(); ++c) {
                                const auto &nxt = r.contents[c];
                                int d = (nxt.distance >= 0) ? nxt.distance : 0;
                                int w = (nxt.within >= 0)   ? nxt.within   : 100;
                                if (d > 500) d = 500;
                                if (w > 1000) w = 1000;
                                if (w < d) w = d + 100;
                                pattern += ".{" + std::to_string(d) + "," + std::to_string(w) + "}";
                                pattern += nxt.pattern;
                                if (nxt.nocase) flag |= HS_FLAG_CASELESS;
                            }
                        } else if (r.has_pcre && !r.pcre_regex.empty()) {
                            pattern = r.pcre_regex;
                            if (r.pcre_nocase) flag |= HS_FLAG_CASELESS;
                        }
                        if (pattern.empty()) continue;
                        ++st.candidates;

                        // Weak-pattern filter from the literal content length (cheap).
                        if (!r.trusted) {
                            size_t longest = 0;
                            for (const auto &c : r.contents) longest = std::max(longest, c.bytes.size());
                            if (r.contents.empty()) longest = 0;      // pcre-only: unknown width
                            if (longest < kMinPatternBytes) { ++st.skipped_weak; continue; }
                        }
                        if (rule_map_->find(r.sid)) continue;          // duplicate SID across files
                        rule_map_->insert(r.sid, &r);
                        st.blocking += r.block;
                        pattern_strings.push_back(std::move(pattern));
                        flags.push_back(flag);
                        ids.push_back(r.sid);
                    }
                }

                static uint64_t pattern_set_hash(const std::vector<std::string> &pats,
                                                 const std::vector<unsigned int> &flags,
                                                 const std::vector<unsigned int> &ids) {
                    uint64_t h = 1469598103934665603ULL;
                    auto mix = [&](const void *p, size_t len) {
                        const uint8_t *b = static_cast<const uint8_t *>(p);
                        for (size_t i = 0; i < len; ++i) { h ^= b[i]; h *= 1099511628211ULL; }
                    };
                    for (size_t i = 0; i < pats.size(); ++i) {
                        mix(pats[i].data(), pats[i].size());
                        mix(&flags[i], sizeof(unsigned int));
                        mix(&ids[i], sizeof(unsigned int));
                        h ^= 0x9E3779B97F4A7C15ULL;    // separator
                    }
                    return h;
                }

            public:
                // Compile, caching the serialized database on disk. On the next run with the same
                // rules the ~40 s Hyperscan compile is replaced by a few-ms deserialize.
                // cache_dir "" disables caching.
                bool compile_or_load(const rules::RuleDatabase &rule_db, const std::string &cache_dir,
                                     CompileStats &st) {
                    clear();
                    st = CompileStats{};
                    if (rule_db.empty()) return false;
                    const auto t0 = std::chrono::steady_clock::now();

                    std::vector<std::string> pattern_strings;
                    std::vector<unsigned int> flags, ids;
                    select_patterns(rule_db, st, pattern_strings, flags, ids);
                    if (pattern_strings.empty()) { clear(); return false; }

                    std::string cache_file;
                    if (!cache_dir.empty()) {
                        std::error_code ec;
                        std::filesystem::create_directories(cache_dir, ec);
                        char name[64];
                        std::snprintf(name, sizeof(name), "/hsdb_%016llx.bin",
                                      static_cast<unsigned long long>(pattern_set_hash(pattern_strings, flags, ids)));
                        cache_file = cache_dir + name;
                        if (FILE *fp = std::fopen(cache_file.c_str(), "rb")) {
                            std::fseek(fp, 0, SEEK_END);
                            long sz = std::ftell(fp);
                            std::fseek(fp, 0, SEEK_SET);
                            std::vector<char> buf(sz > 0 ? static_cast<size_t>(sz) : 0);
                            size_t rd = buf.empty() ? 0 : std::fread(buf.data(), 1, buf.size(), fp);
                            std::fclose(fp);
                            if (rd == buf.size() && !buf.empty() &&
                                hs_deserialize_database(buf.data(), buf.size(), &db_) == HS_SUCCESS &&
                                hs_alloc_scratch(db_, &scratch_) == HS_SUCCESS) {
                                st.compiled = pattern_strings.size();
                                st.from_cache = true;
                                hs_database_size(db_, &st.database_bytes);
                                hs_stream_size(db_, &st.stream_state_bytes);
                                st.compile_ms = std::chrono::duration<double, std::milli>(
                                    std::chrono::steady_clock::now() - t0).count();
                                return true;
                            }
                            clear();
                            if (db_) { hs_free_database(db_); db_ = nullptr; }
                        }
                    }

                    if (!compile_selected(pattern_strings, flags, ids, st)) { clear(); return false; }

                    if (!cache_file.empty()) {
                        char *bytes = nullptr; size_t len = 0;
                        if (hs_serialize_database(db_, &bytes, &len) == HS_SUCCESS && bytes) {
                            if (FILE *fp = std::fopen(cache_file.c_str(), "wb")) {
                                std::fwrite(bytes, 1, len, fp);
                                std::fclose(fp);
                            }
                            std::free(bytes);
                        }
                    }
                    st.compile_ms = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t0).count();
                    return true;
                }

                // Compiles every usable rule into one streaming database. Each expression is
                // validated first, so a single unsupported regex cannot disable all inspection.
                bool compile_rules(const rules::RuleDatabase &rule_db, CompileStats &st) {
                    clear();
                    st = CompileStats{};
                    if (rule_db.empty()) return false;
                    const auto t0 = std::chrono::steady_clock::now();

                    std::vector<std::string> pattern_strings;
                    std::vector<unsigned int> flags, ids;
                    select_patterns(rule_db, st, pattern_strings, flags, ids);
                    bool ok = compile_selected(pattern_strings, flags, ids, st);
                    st.compile_ms = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t0).count();
                    if (!ok) clear();
                    return ok;
                }

            private:
                bool compile_selected(std::vector<std::string> &pattern_strings,
                                      std::vector<unsigned int> &flags,
                                      std::vector<unsigned int> &ids, CompileStats &st) {
                    // Rare: an expression passes validation but fails in the combined compile.
                    // Drop the reported expression and retry instead of losing the whole database.
                    for (int attempt = 0; attempt < 64 && !pattern_strings.empty(); ++attempt) {
                        std::vector<const char *> expressions;
                        expressions.reserve(pattern_strings.size());
                        for (const auto &p : pattern_strings) {
                            expressions.push_back(p.c_str());
                        }

                        hs_compile_error_t *compile_err = nullptr;
                        hs_error_t err = hs_compile_multi(
                            expressions.data(),
                            flags.data(),
                            ids.data(),
                            static_cast<unsigned int>(expressions.size()),
                            HS_MODE_STREAM,
                            nullptr,
                            &db_,
                            &compile_err
                        );
                        if (err == HS_SUCCESS) {
                            break;
                        }
                        int bad = compile_err ? compile_err->expression : -1;
                        std::cerr << "[Hyperscan Compile Error] expression " << bad << ": "
                                  << (compile_err ? compile_err->message : "unknown") << std::endl;
                        if (compile_err) hs_free_compile_error(compile_err);
                        db_ = nullptr;
                        if (bad < 0 || static_cast<size_t>(bad) >= pattern_strings.size()) {
                            break;
                        }
                        ++st.skipped_invalid;
                        pattern_strings.erase(pattern_strings.begin() + bad);
                        flags.erase(flags.begin() + bad);
                        ids.erase(ids.begin() + bad);
                    }

                    if (!db_) {
                        clear();
                        return false;
                    }

                    hs_error_t err = hs_alloc_scratch(db_, &scratch_);
                    if (err != HS_SUCCESS) {
                        clear();
                        return false;
                    }

                    st.compiled = pattern_strings.size();
                    hs_database_size(db_, &st.database_bytes);
                    hs_stream_size(db_, &st.stream_state_bytes);
                    return true;
                }

            public:
                AETHON_ALWAYS_INLINE bool scan(const uint8_t * __restrict__ payload,
                                               size_t payload_len) noexcept 
                {
                    if (AETHON_UNLIKELY(!db_ || !scratch_ || !payload || payload_len == 0)) {
                        return false;
                    }

                    AETHON_BUILTIN_PREFETCH(payload, 0, 3);

                    MatchContext ctx;
                    ctx.rule_map    = rule_map_.get();
                    ctx.alert_cb    = &alert_cb_;
                    ctx.payload     = payload;
                    ctx.payload_len = payload_len;
                    ctx.match_count = 0;

                    hs_error_t err = hs_scan(
                        db_,
                        reinterpret_cast<const char *>(payload),
                        static_cast<unsigned int>(payload_len),
                        0,
                        scratch_,
                        on_match_event,
                        &ctx
                    );

                    return (err == HS_SUCCESS) && (ctx.match_count > 0);
                }

                AETHON_ALWAYS_INLINE bool is_ready() const noexcept {
                    return db_ != nullptr && scratch_ != nullptr;
                }

                AETHON_ALWAYS_INLINE size_t rule_count() const noexcept {
                    return rule_map_ ? rule_map_->size() : 0;
                }

                HyperscanWorker create_worker() const;
        };

        class alignas(implementation::hardware_destructive_interference_size) HyperscanWorker {
        private:
            const hs_database_t *db_{nullptr};
            hs_scratch_t *scratch_{nullptr};
            const HyperscanEngine::RuleMap *rule_map_{nullptr};
            const AlertCallback *alert_cb_{nullptr};

        public:
            HyperscanWorker() = default;

            HyperscanWorker(const hs_database_t *db, hs_scratch_t *scratch, 
                            const HyperscanEngine::RuleMap *rule_map, const AlertCallback *cb)
                : db_(db), scratch_(scratch), rule_map_(rule_map), alert_cb_(cb) {}

            ~HyperscanWorker() {
                if (scratch_) {
                    hs_free_scratch(scratch_);
                    scratch_ = nullptr;
                }
            }

            HyperscanWorker(const HyperscanWorker &) = delete;
            HyperscanWorker &operator=(const HyperscanWorker &) = delete;

            HyperscanWorker(HyperscanWorker &&o) noexcept
                : db_(o.db_), scratch_(o.scratch_), rule_map_(o.rule_map_), alert_cb_(o.alert_cb_) {
                o.scratch_ = nullptr;
                o.db_ = nullptr;
                o.rule_map_ = nullptr;
                o.alert_cb_ = nullptr;
            }

            HyperscanWorker &operator=(HyperscanWorker &&o) noexcept {
                if (this != &o) {
                    if (scratch_) {
                        hs_free_scratch(scratch_);
                    }
                    db_ = o.db_;
                    scratch_ = o.scratch_;
                    rule_map_ = o.rule_map_;
                    alert_cb_ = o.alert_cb_;
                    o.scratch_ = nullptr;
                    o.db_ = nullptr;
                    o.rule_map_ = nullptr;
                    o.alert_cb_ = nullptr;
                }
                return *this;
            }

            AETHON_ALWAYS_INLINE bool scan(const uint8_t * __restrict__ payload, 
                                           size_t payload_len) noexcept 
            {
                if (AETHON_UNLIKELY(!db_ || !scratch_ || !payload || payload_len == 0)) {
                    return false;
                }

                hs_stream_t *stream = nullptr;
                if (AETHON_UNLIKELY(hs_open_stream(db_, 0, &stream) != HS_SUCCESS)) {
                    return false;
                }

                bool matched = scan_stream(stream, payload, payload_len);
                hs_close_stream(stream, scratch_, nullptr, nullptr);
                return matched;
            }

            AETHON_ALWAYS_INLINE bool scan_stream(hs_stream_t *stream, const uint8_t * __restrict__ payload, size_t payload_len) noexcept {
                if (AETHON_UNLIKELY(!stream || !scratch_ || !payload || payload_len == 0)) {
                    return false;
                }

                AETHON_BUILTIN_PREFETCH(payload, 0, 3);

                MatchContext ctx;
                ctx.rule_map    = rule_map_;
                ctx.alert_cb    = alert_cb_;
                ctx.payload     = payload;
                ctx.payload_len = payload_len;
                ctx.match_count = 0;

                hs_error_t err = hs_scan_stream(
                    stream,
                    reinterpret_cast<const char *>(payload),
                    static_cast<unsigned int>(payload_len),
                    0,
                    scratch_,
                    on_match_event,
                    &ctx
                );

                return (err == HS_SUCCESS) && (ctx.match_count > 0);
            }

            AETHON_ALWAYS_INLINE hs_stream_t* open_stream() const noexcept {
                if (AETHON_UNLIKELY(!db_)) return nullptr;
                hs_stream_t *stream = nullptr;
                if (hs_open_stream(db_, 0, &stream) != HS_SUCCESS) {
                    return nullptr;
                }
                return stream;
            }



            AETHON_ALWAYS_INLINE bool is_ready() const noexcept {
                return db_ != nullptr && scratch_ != nullptr;
            }
        };

        inline HyperscanWorker HyperscanEngine::create_worker() const {
            if (!db_ || !scratch_) {
                return HyperscanWorker{};
            }
            hs_scratch_t *worker_scratch = nullptr;
            hs_error_t err = hs_clone_scratch(scratch_, &worker_scratch);
            if (err != HS_SUCCESS) {
                return HyperscanWorker{};
            }
            return HyperscanWorker(db_, worker_scratch, rule_map_.get(), &alert_cb_);
        }


    };
};