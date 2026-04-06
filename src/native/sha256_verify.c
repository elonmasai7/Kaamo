#include <openssl/evp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KAAMO_SHA256_DIGEST_LENGTH 32

static int to_hex(const unsigned char *digest, char *output, size_t output_len) {
    static const char hex[] = "0123456789abcdef";
    if (output_len < (KAAMO_SHA256_DIGEST_LENGTH * 2) + 1) {
        return -1;
    }
    size_t idx = 0;
    while (idx < KAAMO_SHA256_DIGEST_LENGTH) {
        output[idx * 2] = hex[(digest[idx] >> 4) & 0x0F];
        output[(idx * 2) + 1] = hex[digest[idx] & 0x0F];
        idx += 1;
    }
    output[KAAMO_SHA256_DIGEST_LENGTH * 2] = '\0';
    return 0;
}

int sha256_file_verify(const char *path, const char *expected_hex) {
    if (path == NULL || expected_hex == NULL) {
        return -1;
    }
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return -2;
    }
    unsigned char digest[KAAMO_SHA256_DIGEST_LENGTH];
    unsigned char buffer[65536];
    unsigned int digest_len = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        fclose(file);
        return -3;
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return -3;
    }
    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return -4;
        }
    }
    if (ferror(file)) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return -5;
    }
    fclose(file);
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1 || digest_len != KAAMO_SHA256_DIGEST_LENGTH) {
        EVP_MD_CTX_free(ctx);
        return -6;
    }
    EVP_MD_CTX_free(ctx);
    char actual_hex[(KAAMO_SHA256_DIGEST_LENGTH * 2) + 1];
    if (to_hex(digest, actual_hex, sizeof(actual_hex)) != 0) {
        return -7;
    }
    return strcmp(actual_hex, expected_hex) == 0 ? 1 : 0;
}
