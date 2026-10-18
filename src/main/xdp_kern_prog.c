#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include "../common.h"

#define AETHON_MAX_IPS 65536
#define AETHON_MAX_QUEUE_SIZE 64
#define SECOND_NS 1000000000ULL
#define AETHON_PER_CORE_BURST 10ULL
#define AETHON_PER_CORE_REFILL_PER_SEC 2ULL
#define AETHON_MAX_XDP_RETURN_TYPE 5
#define AETHON_MAX_RATE_LIMIT_PARAMETER 3


// getting the no of queeu map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,__u32);
    __type(value,__u32);
} queue_config_map SEC(".maps");

// IP blocking map (global blocklist)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, AETHON_MAX_IPS);
    __type(key, struct aethon_ip_address);
    __type(value, __u64);
} aethon_ip_blockist SEC(".maps");

struct{
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,AETHON_MAX_IPS);
    __type(key,struct aethon_ip_address);
    __type(value,__u16);
} aethon_rate_limiter SEC(".maps");

struct{
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,AETHON_MAX_RATE_LIMIT_PARAMETER);
    __type(key,__u16);
    __type(value,__u64);
} rate_limiter_params SEC(".maps");

struct token_bucket_state{
    __u64 tokens;
    __u64 last_updated;
    __u64 drop_count;
};

struct sliding_window_state{
    __u64 last_time;
    __u64 packets;
    __u64 drop_count;
    __u64 limit;
    __u64 window; 
};
// Lockless per-CPU rate limiting state struct
struct rate_limit_state {
    struct token_bucket_state token_bucket;
    struct sliding_window_state sliding_window_limiter;
    __u64 algo;  
};

// 100% Lock-Free Per-CPU map (Zero cross-core lock contention!)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, AETHON_MAX_IPS);
    __type(key, struct aethon_ip_address);
    __type(value, struct rate_limit_state);
} aethon_ip_ratelimit SEC(".maps");

// afxdp NIC queue to AF_XDP 
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, AETHON_MAX_QUEUE_SIZE);
    __type(key, int);
    __type(value, int);
} aethon_xsks_map SEC(".maps");


// records maps (PER CLIMITER) // for all XDP actions
struct {
    __uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key,__u32);
    __type(value,struct datarec);
    __uint(max_entries,AETHON_MAX_XDP_RETURN_TYPE);
} aethon_xdp_stats_map SEC(".maps");


// function to count records
static aethon_always_inline void stats_record_count(struct xdp_md * ctx, __u32 action){
    struct datarec *rec;
    __u32 key  = action;
    rec = (struct datarec * )bpf_map_lookup_elem(&aethon_xdp_stats_map,&key);
    if(rec){
        void * data_end = (void *)(long)ctx->data_end;
        void * data = (void *)(long)ctx->data;

        __u64 bytes  = (__u64)((__u64)data_end - (__u64)data);
        rec->rx_bytes+=bytes;
        rec->rx_packets+=1;
    }
}
static aethon_always_inline int token_bucket(struct aethon_ip_address* src_ip, struct rate_limit_state* state, __u64 tokens) {
    __u64 now = bpf_ktime_get_ns();
    if (!state) {
        struct rate_limit_state init_state = {
            .token_bucket = {
                .tokens = (tokens > 0) ? (tokens - 1) : 0,
                .last_updated = now,
                .drop_count = 0
            },
            .sliding_window_limiter = {},
            .algo = 0
        };
        bpf_map_update_elem(&aethon_ip_ratelimit, src_ip, &init_state, BPF_ANY);
        return (tokens > 0) ? 1 : 0;
    } else if (state->token_bucket.last_updated == 0) {
        state->token_bucket.tokens = (tokens > 0) ? (tokens - 1) : 0;
        state->token_bucket.last_updated = now;
        state->token_bucket.drop_count = 0;
        return (tokens > 0) ? 1 : 0;
    } else {
        __u64 elapsed = now - state->token_bucket.last_updated;
        __u64 tokens_to_add = (elapsed * AETHON_PER_CORE_REFILL_PER_SEC) / SECOND_NS;
        if (tokens_to_add > 0) {
            __u64 new_tokens = state->token_bucket.tokens + tokens_to_add;
            state->token_bucket.tokens = (new_tokens > tokens) ? tokens : new_tokens;
            state->token_bucket.last_updated = now;
        }

        if (state->token_bucket.tokens == 0) {
            state->token_bucket.drop_count += 1;
            bpf_printk("RATE LIMIT EXCEEDED - DROP\n");

            if (state->token_bucket.drop_count >= 8) {
                __u64 flag = 1;
                bpf_map_update_elem(&aethon_ip_blockist, src_ip, &flag, BPF_ANY);
                bpf_printk("IP BLOCKLISTED DUE TO FLOOD\n");
            }

            return 0;
        }
        state->token_bucket.tokens -= 1;
    }
    return 1;
}

static aethon_always_inline int sliding_window_limiter(struct aethon_ip_address* src_ip, struct rate_limit_state* state, __u64 limit, __u64 window) {
    __u64 now = bpf_ktime_get_ns();
    if (!state) {
        struct rate_limit_state init_state = {
            .token_bucket = {},
            .sliding_window_limiter = {
                .limit = limit,
                .drop_count = 0,
                .packets = 1,
                .last_time = now,
                .window = window
            },
            .algo = 1
        };
        bpf_map_update_elem(&aethon_ip_ratelimit, src_ip, &init_state, BPF_ANY);
        return (limit >= 1) ? 1 : 0;
    } else if (state->sliding_window_limiter.last_time == 0 ||
               (now - state->sliding_window_limiter.last_time >= state->sliding_window_limiter.window * SECOND_NS)) {
        state->sliding_window_limiter.limit = limit;
        state->sliding_window_limiter.window = window;
        state->sliding_window_limiter.packets = 1;
        state->sliding_window_limiter.drop_count = 0;
        state->sliding_window_limiter.last_time = now;
        return (limit >= 1) ? 1 : 0;
    } else {
        if (state->sliding_window_limiter.packets >= state->sliding_window_limiter.limit) {
            state->sliding_window_limiter.drop_count++;
            bpf_printk("RATE LIMIT EXCEEDED - DROP\n");
            if (state->sliding_window_limiter.drop_count >= 8) {
                __u64 flag = 1;
                bpf_map_update_elem(&aethon_ip_blockist, src_ip, &flag, BPF_ANY);
                bpf_printk("IP BLOCKLISTED DUE TO FLOOD\n");
            }
            return 0;
        }
        state->sliding_window_limiter.packets++;
    }
    return 1;
}

SEC("xdp")
int aethon_xdp_prog_main(struct xdp_md * ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    int action = XDP_PASS;

    // 1. Parse Ethernet Header
    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end) 
        return XDP_DROP;

    // 2. Parse IP Header & Extract src_ip FIRST
    
    struct aethon_ip_address src_ip = {};
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) 
            return XDP_DROP;
        src_ip.addr.v4 = iph->saddr;
        src_ip.is_ipv6 = 0;
    } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip6h = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end) 
            return XDP_DROP;
        __builtin_memcpy(src_ip.addr.v6, ip6h->saddr.in6_u.u6_addr32, 16);
        src_ip.is_ipv6 = 1;
    } else {
        // Non-IP traffic (ARP, etc.) -> Pass
        action = XDP_PASS;
        goto out;
    }
    // 3. Check IP Blocklist First: Drop immediately if blocklisted
    if (bpf_map_lookup_elem(&aethon_ip_blockist, &src_ip)) {
        bpf_printk("IP BLOCKLISTED - DROP\n");
        action = XDP_DROP;
        goto out;
    }

    // 4. Rate Limiter Configuration & Lookup
    __u16 key_token = 1;
    __u16 key_window = 2;
    __u16 key_limit = 3;
    __u64* tokens_ptr = bpf_map_lookup_elem(&rate_limiter_params, &key_token);
    __u64* limit_ptr = bpf_map_lookup_elem(&rate_limiter_params, &key_limit);
    __u64* window_ptr = bpf_map_lookup_elem(&rate_limiter_params, &key_window);

    __u64 tokens_val = tokens_ptr ? *tokens_ptr : AETHON_PER_CORE_BURST;
    __u64 limit_val = limit_ptr ? *limit_ptr : 10;
    __u64 window_val = window_ptr ? *window_ptr : 10;

    __u16* algo_ptr = bpf_map_lookup_elem(&aethon_rate_limiter, &src_ip);
    __u16 algo = 0;
    if (!algo_ptr) {
        __u16 default_algo = 0;
        bpf_map_update_elem(&aethon_rate_limiter, &src_ip, &default_algo, BPF_ANY);
        algo = 0;
    } else {
        algo = *algo_ptr;
    }

    struct rate_limit_state* state = bpf_map_lookup_elem(&aethon_ip_ratelimit, &src_ip);
    int resp = 1;
    if (algo == 0) {
        resp = token_bucket(&src_ip, state, tokens_val);
    } else if (algo == 1) {
        resp = sliding_window_limiter(&src_ip, state, limit_val, window_val);
    } else {
        __u16 reset_algo = 0;
        bpf_map_update_elem(&aethon_rate_limiter, &src_ip, &reset_algo, BPF_ANY);
        resp = token_bucket(&src_ip, state, tokens_val);
    }

    if (!resp) {
        action = XDP_DROP;
        goto out;
    }

    

    // 5. Attack Checks (only runs if rate limiter passed)
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph_check = (struct iphdr *)(eth + 1);
        if ((void *)(iph_check + 1) <= data_end) {
            __u16 frag_off_check = bpf_ntohs(iph_check->frag_off);
            __u8 is_fragment_check = (frag_off_check & 0x3FFF) != 0 || (frag_off_check & 0x2000) != 0;

            if (is_fragment_check && iph_check->protocol == IPPROTO_TCP) {
                __u64 flag = 1;
                bpf_map_update_elem(&aethon_ip_blockist, &src_ip, &flag, BPF_ANY);
                bpf_printk("TCP FRAGMENT ATTACK BLOCKED\n");
                action = XDP_DROP;
                goto out;
            }
        }
    }

    
    // Dynamic queue routing
    __u32 key = 0;
    __u32 *num_queues_ptr  = (__u32 * )bpf_map_lookup_elem(&queue_config_map, &key);
    __u32 dynamic_num_queues = (num_queues_ptr && *num_queues_ptr > 0) ? *num_queues_ptr : 1;
    
    // Spread incoming hardware queues evenly across active worker queues
    __u32 target_queue = ctx->rx_queue_index % dynamic_num_queues;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(eth + 1);
        if ((void *)(iph + 1) > data_end) return XDP_DROP;
        __u16 frag_off = bpf_ntohs(iph->frag_off);
        __u8 is_fragment = (frag_off & 0x3FFF) != 0 || (frag_off & 0x2000) != 0;

        if (is_fragment) {
            // For IP fragments (UDP / other), route all fragments of the flow to the SAME worker queue
            __u64 ip_hash = (__u64)iph->saddr + (__u64)iph->daddr;
            target_queue = ip_hash % dynamic_num_queues;
        }
    }

    // Safety bounds check for the eBPF kernel verifier
    if (target_queue >= dynamic_num_queues) {
        target_queue = 0;
    }

    action = bpf_redirect_map(&aethon_xsks_map, target_queue, 0);

out:
    stats_record_count(ctx, action);
    return action;
}



char _license[] SEC("license") = "GPL";
