#include "throttle.h"

#include <pthread.h>
#include <stdlib.h>
#include <time.h>

struct TokenBucket {
    double capacity;
    double tokens;
    double refill_per_second;
    int64_t last_refill_ms;
    pthread_mutex_t mutex;
};

static int64_t tb_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return 0;
    }
    return ((int64_t) ts.tv_sec * 1000) + (ts.tv_nsec / 1000000);
}

TokenBucket *token_bucket_create(double capacity, double refill_per_second) {
    TokenBucket *bucket = calloc(1, sizeof(TokenBucket));
    if (bucket == NULL) {
        return NULL;
    }
    bucket->capacity = capacity;
    bucket->tokens = capacity;
    bucket->refill_per_second = refill_per_second;
    bucket->last_refill_ms = tb_now_ms();
    if (pthread_mutex_init(&bucket->mutex, NULL) != 0) {
        free(bucket);
        return NULL;
    }
    return bucket;
}

void token_bucket_destroy(TokenBucket *bucket) {
    if (bucket == NULL) {
        return;
    }
    pthread_mutex_destroy(&bucket->mutex);
    free(bucket);
}

int token_bucket_allow(TokenBucket *bucket, double tokens) {
    if (bucket == NULL || tokens <= 0.0) {
        return 0;
    }
    pthread_mutex_lock(&bucket->mutex);
    const int64_t now = tb_now_ms();
    const double elapsed_seconds = (double) (now - bucket->last_refill_ms) / 1000.0;
    double replenished = bucket->tokens + (elapsed_seconds * bucket->refill_per_second);
    if (replenished > bucket->capacity) {
        replenished = bucket->capacity;
    }
    bucket->tokens = replenished;
    bucket->last_refill_ms = now;
    int allowed = 0;
    if (bucket->tokens >= tokens) {
        bucket->tokens -= tokens;
        allowed = 1;
    }
    pthread_mutex_unlock(&bucket->mutex);
    return allowed;
}

