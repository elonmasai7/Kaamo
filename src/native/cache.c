#include "cache.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef struct {
    uint64_t key;
    uint8_t *value;
    size_t value_len;
    int64_t expires_at_ms;
    uint64_t access_tick;
    int in_use;
} CacheEntry;

struct Cache {
    CacheEntry *entries;
    size_t capacity_entries;
    size_t max_value_size;
    uint64_t tick;
    pthread_mutex_t mutex;
};

static int64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return ((int64_t) ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

static CacheEntry *find_entry(Cache *cache, uint64_t key) {
    size_t idx = 0;
    while (idx < cache->capacity_entries) {
        CacheEntry *entry = &cache->entries[idx];
        if (entry->in_use && entry->key == key) {
            return entry;
        }
        idx += 1;
    }
    return NULL;
}

static CacheEntry *find_free_or_lru(Cache *cache) {
    CacheEntry *best = NULL;
    size_t idx = 0;
    while (idx < cache->capacity_entries) {
        CacheEntry *entry = &cache->entries[idx];
        if (!entry->in_use) {
            return entry;
        }
        if (best == NULL || entry->access_tick < best->access_tick) {
            best = entry;
        }
        idx += 1;
    }
    return best;
}

Cache *cache_create(size_t capacity_entries, size_t max_value_size) {
    Cache *cache = calloc(1, sizeof(Cache));
    if (cache == NULL) {
        return NULL;
    }
    cache->entries = calloc(capacity_entries, sizeof(CacheEntry));
    if (cache->entries == NULL) {
        free(cache);
        return NULL;
    }
    cache->capacity_entries = capacity_entries;
    cache->max_value_size = max_value_size;
    if (pthread_mutex_init(&cache->mutex, NULL) != 0) {
        free(cache->entries);
        free(cache);
        return NULL;
    }
    return cache;
}

void cache_destroy(Cache *cache) {
    if (cache == NULL) {
        return;
    }
    pthread_mutex_lock(&cache->mutex);
    size_t idx = 0;
    while (idx < cache->capacity_entries) {
        free(cache->entries[idx].value);
        cache->entries[idx].value = NULL;
        idx += 1;
    }
    pthread_mutex_unlock(&cache->mutex);
    pthread_mutex_destroy(&cache->mutex);
    free(cache->entries);
    free(cache);
}

int cache_get(
    Cache *cache,
    uint64_t key,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len
) {
    if (cache == NULL || out == NULL || out_len == NULL) {
        return -1;
    }
    pthread_mutex_lock(&cache->mutex);
    CacheEntry *entry = find_entry(cache, key);
    if (entry == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return 1;
    }
    if (entry->expires_at_ms < now_ms()) {
        free(entry->value);
        memset(entry, 0, sizeof(CacheEntry));
        pthread_mutex_unlock(&cache->mutex);
        return 1;
    }
    if (entry->value_len > out_capacity) {
        pthread_mutex_unlock(&cache->mutex);
        return -2;
    }
    memcpy(out, entry->value, entry->value_len);
    *out_len = entry->value_len;
    cache->tick += 1;
    entry->access_tick = cache->tick;
    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

int cache_set(
    Cache *cache,
    uint64_t key,
    const uint8_t *value,
    size_t value_len,
    int64_t ttl_ms
) {
    if (cache == NULL || value == NULL || value_len == 0) {
        return -1;
    }
    if (value_len > cache->max_value_size) {
        return -2;
    }
    pthread_mutex_lock(&cache->mutex);
    CacheEntry *entry = find_entry(cache, key);
    if (entry == NULL) {
        entry = find_free_or_lru(cache);
    }
    if (entry == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -3;
    }
    uint8_t *copy = malloc(value_len);
    if (copy == NULL) {
        pthread_mutex_unlock(&cache->mutex);
        return -4;
    }
    memcpy(copy, value, value_len);
    free(entry->value);
    entry->value = copy;
    entry->value_len = value_len;
    entry->key = key;
    entry->expires_at_ms = now_ms() + ttl_ms;
    cache->tick += 1;
    entry->access_tick = cache->tick;
    entry->in_use = 1;
    pthread_mutex_unlock(&cache->mutex);
    return 0;
}

void cache_evict_expired(Cache *cache) {
    if (cache == NULL) {
        return;
    }
    pthread_mutex_lock(&cache->mutex);
    const int64_t now = now_ms();
    size_t idx = 0;
    while (idx < cache->capacity_entries) {
        CacheEntry *entry = &cache->entries[idx];
        if (entry->in_use && entry->expires_at_ms < now) {
            free(entry->value);
            memset(entry, 0, sizeof(CacheEntry));
        }
        idx += 1;
    }
    pthread_mutex_unlock(&cache->mutex);
}

