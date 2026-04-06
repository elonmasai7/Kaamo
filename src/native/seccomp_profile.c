#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *KAAMO_SECCOMP_PROFILE =
    "{"
    "\"defaultAction\":\"SCMP_ACT_ERRNO\","
    "\"architectures\":[\"SCMP_ARCH_X86_64\",\"SCMP_ARCH_X86\",\"SCMP_ARCH_AARCH64\"],"
    "\"syscalls\":["
      "{\"names\":[\"read\",\"write\",\"close\",\"mmap\",\"munmap\",\"mprotect\",\"brk\"],\"action\":\"SCMP_ACT_ALLOW\"},"
      "{\"names\":[\"futex\",\"clock_gettime\",\"exit\",\"exit_group\"],\"action\":\"SCMP_ACT_ALLOW\"},"
      "{\"names\":[\"connect\",\"sendto\",\"recvfrom\",\"sendmsg\",\"recvmsg\"],\"action\":\"SCMP_ACT_ALLOW\"},"
      "{\"names\":[\"epoll_wait\",\"epoll_ctl\",\"epoll_create1\"],\"action\":\"SCMP_ACT_ALLOW\"},"
      "{\"names\":[\"openat\",\"newfstatat\",\"lseek\"],\"action\":\"SCMP_ACT_ALLOW\"}"
    "]"
    "}";

size_t seccomp_profile_size(void) {
    return strlen(KAAMO_SECCOMP_PROFILE);
}

int seccomp_profile_copy(char *buffer, size_t buffer_len) {
    const size_t needed = strlen(KAAMO_SECCOMP_PROFILE) + 1;
    if (buffer == NULL || buffer_len < needed) {
        return -1;
    }
    memcpy(buffer, KAAMO_SECCOMP_PROFILE, needed);
    return 0;
}

