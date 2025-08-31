// 十六进制修补工具实现
#include <sys/mman.h>

#include <base.hpp>

#include "magiskboot.hpp"

using namespace std;

// 十六进制字符串转字节数组
static void hex2byte(const char *hex, uint8_t *buf) {
    char high, low;
    for (int i = 0, length = strlen(hex); i < length; i += 2) {
        high = toupper(hex[i]) - '0';
        low = toupper(hex[i + 1]) - '0';
        buf[i / 2] = ((high > 9 ? high - 7 : high) << 4) + (low > 9 ? low - 7 : low);
    }
}

// 十六进制修补函数
int hexpatch(const char *file, const char *from, const char *to) {
    int patched = 1;

    auto m = mmap_data(file, true);

    vector<uint8_t> pattern(strlen(from) / 2);
    vector<uint8_t> patch(strlen(to) / 2);

    hex2byte(from, pattern.data());     // 将源模式转换为字节
    hex2byte(to, patch.data());         // 将目标模式转换为字节

    uint8_t * const end = m.buf + m.sz;
    for (uint8_t *curr = m.buf; curr < end; curr += pattern.size()) {
        curr = static_cast<uint8_t*>(memmem(curr, end - curr, pattern.data(), pattern.size()));
        if (curr == nullptr)
            return patched;
        fprintf(stderr, "Patch @ %08X [%s] -> [%s]\n", (unsigned)(curr - m.buf), from, to);
        memset(curr, 0, pattern.size());           // 清零原位置
        memcpy(curr, patch.data(), patch.size());  // 复制新数据
        patched = 0;  // 标记已修补
    }

    return patched;
}
