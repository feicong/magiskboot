// 格式定义头文件，定义各种文件格式的枚举和常量
#pragma once

#include <string_view>

// 格式类型枚举
typedef enum {
    UNKNOWN,        // 未知格式
/* 启动镜像格式 */
    CHROMEOS,       // ChromeOS格式
    AOSP,           // Android开源项目格式
    AOSP_VENDOR,    // AOSP vendor格式
    DHTB,           // DHTB格式
    BLOB_FMT,       // Blob格式
/* 压缩格式 */
    GZIP,           // Gzip压缩
    ZOPFLI,         // Zopfli压缩
    XZ,             // XZ压缩
    LZMA,           // LZMA压缩
    BZIP2,          // Bzip2压缩
    LZ4,            // LZ4压缩
    LZ4_LEGACY,     // LZ4遗留格式
    LZ4_LG,         // LZ4 LG格式
/* 不支持的压缩格式 */
    LZOP,           // LZOP压缩
/* 其他格式 */
    MTK,            // MTK格式
    DTB,            // 设备树二进制格式
    ZIMAGE,         // zImage格式
} format_t;

// 格式检查宏定义
#define COMPRESSED(fmt)      ((fmt) >= GZIP && (fmt) < LZOP)      // 检查是否为支持的压缩格式
#define COMPRESSED_ANY(fmt)  ((fmt) >= GZIP && (fmt) <= LZOP)     // 检查是否为任意压缩格式

// 缓冲区匹配宏定义
#define BUFFER_MATCH(buf, s) (memcmp(buf, s, sizeof(s) - 1) == 0)              // 缓冲区头部匹配
#define BUFFER_CONTAIN(buf, sz, s) (memmem(buf, sz, s, sizeof(s) - 1) != nullptr) // 缓冲区包含匹配

// 各种格式的魔数定义
#define BOOT_MAGIC      "ANDROID!"     // Android启动镜像魔数
#define VENDOR_BOOT_MAGIC "VNDRBOOT"   // Vendor启动镜像魔数
#define CHROMEOS_MAGIC  "CHROMEOS"     // ChromeOS魔数
#define GZIP1_MAGIC     "\x1f\x8b"     // Gzip魔数1
#define GZIP2_MAGIC     "\x1f\x9e"     // Gzip魔数2
#define LZOP_MAGIC      "\x89""LZO"    // LZOP魔数
#define XZ_MAGIC        "\xfd""7zXZ"   // XZ魔数
#define BZIP_MAGIC      "BZh"          // Bzip2魔数
#define LZ4_LEG_MAGIC   "\x02\x21\x4c\x18"  // LZ4遗留魔数
#define LZ41_MAGIC      "\x03\x21\x4c\x18"  // LZ4魔数1
#define LZ42_MAGIC      "\x04\x22\x4d\x18"  // LZ4魔数2
#define MTK_MAGIC       "\x88\x16\x88\x58"  // MTK魔数
#define DTB_MAGIC       "\xd0\x0d\xfe\xed"  // 设备树魔数
#define LG_BUMP_MAGIC   "\x41\xa9\xe4\x67\x74\x4d\x1d\x1b\xa4\x29\xf2\xec\xea\x65\x52\x79"  // LG Bump魔数
#define DHTB_MAGIC      "\x44\x48\x54\x42\x01\x00\x00\x00"  // DHTB魔数
#define SEANDROID_MAGIC "SEANDROIDENFORCE"
#define TEGRABLOB_MAGIC "-SIGNED-BY-SIGNBLOB-"
#define NOOKHD_RL_MAGIC "Red Loader"
#define NOOKHD_GL_MAGIC "Green Loader"
#define NOOKHD_GR_MAGIC "Green Recovery"
#define NOOKHD_EB_MAGIC "eMMC boot.img+secondloader"
#define NOOKHD_ER_MAGIC "eMMC recovery.img+secondloader"
#define NOOKHD_PRE_HEADER_SZ 1048576
#define ACCLAIM_MAGIC   "BauwksBoot"
#define ACCLAIM_PRE_HEADER_SZ 262144
#define AMONET_MICROLOADER_MAGIC "microloader"
#define AMONET_MICROLOADER_SZ 1024
#define AVB_FOOTER_MAGIC "AVBf"
#define AVB_MAGIC "AVB0"
#define ZIMAGE_MAGIC "\x18\x28\x6f\x01"

class Fmt2Name {
public:
    const char *operator[](format_t fmt);
};

class Fmt2Ext {
public:
    const char *operator[](format_t fmt);
};

class Name2Fmt {
public:
    format_t operator[](std::string_view name);
};

format_t check_fmt(const void *buf, size_t len);

extern Name2Fmt name2fmt;
extern Fmt2Name fmt2name;
extern Fmt2Ext fmt2ext;
