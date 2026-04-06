#include "kv_cache.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint64_t prefix_hash;
    uint8_t *kv_bytes;
    size_t kv_size;
    int64_t expires_at_ms;
    uint64_t access_count;
    int in_use;
} KVCacheEntry;

struct KVCache {
    KVCacheEntry *entries;
    size_t capacity_entries;
    size_t max_kv_bytes_each;
    uint64_t tick;
    pthread_mutex_t mutex;
};

static int64_t kv_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return ((int64_t) ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

KVCache *kv_cache_create(size_t capacity_entries, size_t max_kv_bytes_each) {
    KVCache *cache = calloc(1, sizeof(KVCache));
    if (cache == NULL) {
        return NULL;
    }
    cache->entries = calloc(capacity_entries, sizeof(KVCacheEntry));
    if (cache->entries == NULL) {
        free(cache);
        return NULL;
    }
    cache->capacity_entries = capacity_entries;
    cache->max_kv_bytes_each = max_kv_bytes_each;
    if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
        free(cache->entries);
        free(cache);
        return NULL;
    }
    return cache;
}

void kv_cache_destroy(KVCache *cache) {
    if (cache == NULL) {
        return;
    }
    pthread_mutex_lock(&cache->mutex);
    size_t idx = 0;
    while (idx < cache->capacity_entries) {
        free(cache->entries[idx].kv_bytes);
        cache->entries[idx].kv_bytes = NULL;
        idx += 1;
    }
    pthread_mutex_unlock(&cache->mutex);
    pthread_mutex_destroy(&cache->mutex);
    free(cache->entries);
    free(cache);
}

static KVCacheEntry *kv_find(KVCache *cache, uint64_t prefix_hash) {
    size_t idx = 0;
    while (idx < cache->capacity_entries) {
        KVCacheEntry *entry = &cache->entries[idx];
        if (entry->in_use && entry->prefix_hash == prefix_hash) {
            return entry;
        }
        idx += 1;
    }
    return NULL;
}

static KVCacheEntry *kv_find_victim(KVCache *cache) {
    KVCacheEntry *victim = NULL;
    size_t idx = 0;
    while (idx < cache->capacity_entries) {
        KVCacheEntry *entry = &cache->entries[idx];
        if (!entry->in_use) {
            return entry;
        }
        if (victim == NULL || entry->access_count < victim->access_count) {
            victim = entry;
        }
        idx += 1;
    }
    return victim;
}

int kv_cache_get(
    KVCache *cache,
    uint64_t prefix_hash,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len
) {
    if (cache == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    pthread_mutex_lock(&cache->mutex);
    KVCacheEntry *entry = kv_find(cache, prefix_hash);
    if (entry == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return 1;
    }
    if (entry->expires_at_ms < kv_now_ms()) {
        free(entry->kv_bytes);
        memset(entry, 0, sizeof(KVCacheEntry));
        pthread_mutex_unlock(&cache->mutex);
        return 1;
    }
    if (entry->kv_size > out_capacity) {
        pthread_mutex_unlock(&cache->mutex);
        return -2;
    }
    memcpy(out, entry->kv_bytes, entry->kv_size);
    *out_len = entry->kv_size;
    cache->tick += 1;
    entry->access_count = cache->tick;
    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

int kv_cache_set(
    KVCache *cache,
    uint64_t prefix_hash,
    const uint8_t *kv,
    size_t kv_len,
    int64_t ttl_ms
) {
    if (cache == NULL || kv == NULL || kv_len == 0) {
        return -1;
    }
    if (kv_len > cache->max_kv_bytes_each) {
        return -2;
    }
    pthread_mutex_lock(&cache->mutex);
    KVCacheEntry *entry = kv_find(cache, prefix_hash);
    if (entry == NULL) {
        entry = kv_find_victim(cache);
    }
    if (entry == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -3;
    }
    uint8_t *copy = malloc(kv_len);
    if (copy == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -4;
    }
    memcpy(copy, kv, kv_len);
    free(entry->kv_bytes);
    entry->kv_bytes = copy;
    entry->kv_size = kv_len;
    entry->prefix_hash = prefix_hash;
    entry->expires_at_ms = kv_now_ms() + ttl_ms;
    cache->tick += 1;
    entry->access_count = cache->tick;
    entry->in_use = 1;
    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

void kv_cache_evict_lru(KVCache *cache) {
    if (cache == NULL) {
        return;
    }
    pthread_mutex_lock(&cache->mutex);
    KVCacheEntry *victim = kv_find_victim(cache);
    if (victim != NULL && victim->in_use) {
        free(victim->kv_bytes);
        memset(victim, 0, sizeof(KVCacheEntry));
    }
    pthread_mutex_unlock(&cache->mutex);
}

