#ifndef KAAMO_THROTTLE_H
#define KAAMO_THROTTLE_H

#include <stdint.h>

typedef struct TokenBucket TokenBucket;

TokenBucket *token_bucket_create(double capacity, double refill_per_second);
void token_bucket_destroy(TokenBucket *bucket);
int token_bucket_allow(TokenBucket *bucket, double tokens);

#endif
