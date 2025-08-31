// 模式匹配和移除实现
#include <base.hpp>

#include "magiskboot.hpp"

#define MATCH(p) else if (strncmp(s + skip, p, sizeof(p) - 1) == 0) skip += (sizeof(p) - 1)

// 跳过验证模式
static int skip_verity_pattern(const char *s) {
    int skip = s[0] == ',';

    if (0) {}
    MATCH("verifyatboot");
    MATCH("verify");
    MATCH("avb_keys");
    MATCH("avb");
    MATCH("support_scfs");
    MATCH("fsverity");
    else return -1;

    if (s[skip] == '=') {
        while (!strchr(" \n,", s[skip]))
            ++skip;
    }
    return skip;
}

// 跳过加密模式
static int skip_encryption_pattern(const char *s) {
    int skip = s[0] == ',';

    if (0) {}
    MATCH("forceencrypt");
    MATCH("forcefdeorfbe");
    MATCH("fileencryption");
    else return -1;

    if (s[skip] == '=') {
        while (!strchr(" \n,", s[skip]))
            ++skip;
    }
    return skip;
}

// 移除匹配模式的通用函数
static uint32_t remove_pattern(char *src, uint32_t size, int(*pattern_skip)(const char *)) {
    int orig_sz = size;
    int write = 0;
    for (int read = 0; read < orig_sz;) {
        if (int skip = pattern_skip(src + read); skip > 0) {
            fprintf(stderr, "Remove pattern [%.*s]\n", skip, src + read);
            size -= skip;
            read += skip;
        } else {
            src[write++] = src[read++];
        }
    }
    memset(src + write, 0, orig_sz - write);  // 清零剩余空间
    return size;
}

// 修补验证相关的模式
uint32_t patch_verity(void *buf, uint32_t size) {
    return remove_pattern(static_cast<char *>(buf), size, skip_verity_pattern);
}

uint32_t patch_encryption(void *buf, uint32_t size) {
    return remove_pattern(static_cast<char *>(buf), size, skip_encryption_pattern);
}
