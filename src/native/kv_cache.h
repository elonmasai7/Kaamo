#ifndef KAAMO_KV_CACHE_H
#define KAAMO_KV_CACHE_H

#include <stdint.h>
#include <stddef.h>

typedef struct KVCache KVCache;

KVCache *kv_cache_create(size_t capacity_entries, size_t max_kv_bytes_each);
void kv_cache_destroy(KVCache *cache);
int kv_cache_get(
    KVCache *cache,
    uint64_t prefix_hash,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len
);
int kv_cache_set(
    KVCache *cache,
    uint64_t prefix_hash,
    const uint8_t *kv,
    size_t kv_len,
    int64_t ttl_ms
);
void kv_cache_evict_lru(KVCache *cache);

#endif
