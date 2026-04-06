#ifndef KAAMO_CACHE_H
#define KAAMO_CACHE_H

#include <stdint.h>
#include <stddef.h>

typedef struct Cache Cache;

Cache *cache_create(size_t capacity_entries, size_t max_value_size);
void cache_destroy(Cache *cache);
int cache_get(
    Cache *cache,
    uint64_t key,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len
);
int cache_set(
    Cache *cache,
    uint64_t key,
    const uint8_t *value,
    size_t value_len,
    int64_t ttl_ms
);
void cache_evict_expired(Cache *cache);

#endif
