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
        };

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
                        size_t pat_len = first.pattern.size();

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

                    ctx->match_count++;
                    if (ctx->alert_cb && *(ctx->alert_cb)) {
                        AttackAlert alert;
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
                    clear();
                    if (rule_db.empty()) {
                        return false;
                    }

                    const auto &all_rules = rule_db.rules();
                    size_t n = all_rules.size();

                    size_t capacity = next_power_of_two(n * 2);
                    rule_map_ = std::make_unique<RuleMap>(capacity);

                    std::vector<std::string> pattern_strings;
                    std::vector<const char *> expressions;
                    std::vector<unsigned int> flags;
                    std::vector<unsigned int> ids;

                    pattern_strings.reserve(n);
                    expressions.reserve(n);
                    flags.reserve(n);
                    ids.reserve(n);

                    for (const auto &r : all_rules) {
                        rule_map_->insert(r.sid, &r);

                        std::string pattern;

                        

                        unsigned int flag = HS_FLAG_SINGLEMATCH | HS_FLAG_DOTALL;

                        if (!r.contents.empty()) {
                            pattern = r.contents[0].pattern;
                            if (r.contents[0].nocase) {
                                flag |= HS_FLAG_CASELESS;
                            }

                            for (size_t c = 1; c < r.contents.size(); ++c) {
                                const auto &nxt = r.contents[c];
                                int d = (nxt.distance >= 0) ? nxt.distance : 0;
                                int w = (nxt.within >= 0)   ? nxt.within   : 100;
                                if (d > 500) d = 500;
                                if (w > 1000) w = 1000;
                                if (w < d) w = d + 100;
                                pattern += ".{" + std::to_string(d) + "," + std::to_string(w) + "}";
                                pattern += nxt.pattern;
                                if (nxt.nocase) {
                                    flag |= HS_FLAG_CASELESS;
                                }
                            }
                        } else if (r.has_pcre && !r.pcre_regex.empty()) {
                            pattern = r.pcre_regex;
                        }

                        if (!pattern.empty()) {
                            pattern_strings.push_back(std::move(pattern));
                            flags.push_back(flag);
                            ids.push_back(r.sid);
                        }
                    }

                    for (const auto &p : pattern_strings) {
                        expressions.push_back(p.c_str());
                    }

                    if (expressions.empty()) {
                        clear();
                        return false;
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

                    if (err != HS_SUCCESS) {
                        if (compile_err) {
                            std::cerr << "[Hyperscan Compile Error] ID: " 
                                      << compile_err->expression << " -> " 
                                      << compile_err->message << std::endl;
                            hs_free_compile_error(compile_err);
                        }
                        clear();
                        return false;
                    }

                    err = hs_alloc_scratch(db_, &scratch_);
                    if (err != HS_SUCCESS) {
                        clear();
                        return false;
                    }

                    return true;
                }

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