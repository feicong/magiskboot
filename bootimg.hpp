// Android Boot镜像处理相关头文件定义
#pragma once

#include <stdint.h>
#include <utility>
#include <bitset>
#include "format.hpp"

/******************
 * 特殊头部结构定义
 *****************/

struct mtk_hdr {
    uint32_t magic;         /* MTK魔数 */
    uint32_t size;          /* 内容大小 */
    char name[32];          /* 头部类型 */

    char padding[472];      /* 填充到512字节 */
} __attribute__((packed));

struct dhtb_hdr {
    char magic[8];          /* DHTB魔数 */
    uint8_t checksum[40];   /* 载荷SHA256校验和，完整镜像 + SEANDROIDENFORCE + 0xFFFFFFFF */
    uint32_t size;          /* 载荷大小，完整镜像 + SEANDROIDENFORCE + 0xFFFFFFFF */

    char padding[460];      /* 填充到512字节 */
} __attribute__((packed));

struct blob_hdr {
    char secure_magic[20];  /* "-SIGNED-BY-SIGNBLOB-" 安全签名标识 */
    uint32_t datalen;       /* 0x00000000 数据长度 */
    uint32_t signature;     /* 0x00000000 签名 */
    char magic[16];         /* "MSM-RADIO-UPDATE" MSM无线电更新标识 */
    uint32_t hdr_version;   /* 0x00010000 头部版本 */
    uint32_t hdr_size;      /* 头部大小 */
    uint32_t part_offset;   /* 与大小相同的偏移量 */
    uint32_t num_parts;     /* 分区数量 */
    uint32_t unknown[7];    /* 全部为0x00000000的未知字段 */
    char name[4];           /* 分区名称 */
    uint32_t offset;        /* 该分区在blob中的起始偏移 */
    uint32_t size;          /* 数据大小 */
    uint32_t version;       /* 0x00000001 版本 */
} __attribute__((packed));

struct zimage_hdr {
    uint32_t code[9];       /* 代码段 */
    uint32_t magic;         /* zImage魔数 */
    uint32_t start;         /* zImage绝对加载/运行地址 */
    uint32_t end;           /* zImage结束地址 */
    uint32_t endian;        /* 字节序标志 */
    // 可能还有更多字段，但我们不关心
} __attribute__((packed));

/**************
 * AVB头部结构
 **************/

#define AVB_FOOTER_MAGIC_LEN 4      // AVB页脚魔数长度
#define AVB_MAGIC_LEN 4             // AVB魔数长度  
#define AVB_RELEASE_STRING_SIZE 48  // AVB发布字符串大小

// https://android.googlesource.com/platform/external/avb/+/refs/heads/android11-release/libavb/avb_footer.h
// AVB页脚结构定义
struct AvbFooter {
    uint8_t magic[AVB_FOOTER_MAGIC_LEN];    // AVB页脚魔数
    uint32_t version_major;                 // 主版本号
    uint32_t version_minor;                 // 次版本号
    uint64_t original_image_size;           // 原始镜像大小
    uint64_t vbmeta_offset;                 // VBMeta偏移量
    uint64_t vbmeta_size;                   // VBMeta大小
    uint8_t reserved[28];                   // 保留字段
} __attribute__((packed));

// https://android.googlesource.com/platform/external/avb/+/refs/heads/android11-release/libavb/avb_vbmeta_image.h
// AVB VBMeta镜像头部结构定义
struct AvbVBMetaImageHeader {
    uint8_t magic[AVB_MAGIC_LEN];                       // AVB魔数
    uint32_t required_libavb_version_major;             // 所需libavb主版本号
    uint32_t required_libavb_version_minor;             // 所需libavb次版本号
    uint64_t authentication_data_block_size;            // 认证数据块大小
    uint64_t auxiliary_data_block_size;                 // 辅助数据块大小
    uint32_t algorithm_type;                            // 算法类型
    uint64_t hash_offset;                               // 哈希偏移量
    uint64_t hash_size;                                 // 哈希大小
    uint64_t signature_offset;                          // 签名偏移量
    uint64_t signature_size;                            // 签名大小
    uint64_t public_key_offset;                         // 公钥偏移量
    uint64_t public_key_size;                           // 公钥大小
    uint64_t public_key_metadata_offset;                // 公钥元数据偏移量
    uint64_t public_key_metadata_size;                  // 公钥元数据大小
    uint64_t descriptors_offset;                        // 描述符偏移量
    uint64_t descriptors_size;                          // 描述符大小
    uint64_t rollback_index;                            // 回滚索引
    uint32_t flags;                                     // 标志位
    uint32_t rollback_index_location;                   // 回滚索引位置
    uint8_t release_string[AVB_RELEASE_STRING_SIZE];    // 发布字符串
    uint8_t reserved[80];                               // 保留字段
} __attribute__((packed));

/*********************
 * Boot镜像头部结构定义
 *********************/

// https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/android12-release/include/bootimg/bootimg.h

#define BOOT_MAGIC_SIZE 8               // Boot魔数大小
#define BOOT_NAME_SIZE 16               // Boot名称大小
#define BOOT_ID_SIZE 32                 // Boot ID大小
#define BOOT_ARGS_SIZE 512              // Boot参数大小
#define BOOT_EXTRA_ARGS_SIZE 1024       // Boot额外参数大小
#define VENDOR_BOOT_ARGS_SIZE 2048      // 厂商Boot参数大小
#define VENDOR_RAMDISK_NAME_SIZE 32     // 厂商Ramdisk名称大小
#define VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE 16  // 厂商Ramdisk表条目板ID大小

/* 当boot镜像头部版本为0-2时，boot镜像的结构如下:
 *
 * +-----------------+
 * | boot header     | 1 页
 * +-----------------+
 * | kernel          | n 页
 * +-----------------+
 * | ramdisk         | m 页
 * +-----------------+
 * | second stage    | o 页
 * +-----------------+
 * | extra blob      | x 页 (非标准)
 * +-----------------+
 * | recovery dtbo   | p 页
 * +-----------------+
 * | dtb             | q 页
 * +-----------------+
 *
 * n = (kernel_size + page_size - 1) / page_size
 * m = (ramdisk_size + page_size - 1) / page_size
 * o = (second_size + page_size - 1) / page_size
 * p = (recovery_dtbo_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 * x = (extra_size + page_size - 1) / page_size
 */

// Boot镜像头部v0通用结构
struct boot_img_hdr_v0_common {
    char magic[BOOT_MAGIC_SIZE];        // Boot魔数

    uint32_t kernel_size;               // 内核大小（字节）
    uint32_t kernel_addr;               // 内核物理加载地址

    uint32_t ramdisk_size;              // Ramdisk大小（字节）
    uint32_t ramdisk_addr;              // Ramdisk物理加载地址

    uint32_t second_size;               // 第二阶段大小（字节）
    uint32_t second_addr;               // 第二阶段物理加载地址
} __attribute__((packed));

// Boot镜像头部v0结构，继承自通用结构
struct boot_img_hdr_v0 : public boot_img_hdr_v0_common {
    uint32_t tags_addr;                 // 内核标签物理地址

    // 在AOSP头部中，此字段用于页面大小。
    // 对于三星PXA头部，此字段的用途未知；
    // 但是，其值不太可能被视为页面大小。
    // 我们使用这个事实来确定这是AOSP还是PXA头部。
    union {
        uint32_t unknown;               // 未知字段
        uint32_t page_size;             // 我们假设的flash页面大小
    };

    // 在头部v1中，此字段用于头部版本
    // 然而，在一些设备如三星上，此字段用于存储DTB
    // 我们根据其值来区别对待此字段
    union {
        uint32_t header_version;        // 头部版本
        uint32_t extra_size;            // 额外blob大小（字节）
    };

    // 操作系统版本和安全补丁级别。
    // 对于版本"A.B.C"和补丁级别"Y-M-D":
    //   (A、B、C各7位；(Y-2000)7位，M 4位)
    //   os_version = A[31:25] B[24:18] C[17:11] (Y-2000)[10:4] M[3:0]
    uint32_t os_version;                // 操作系统版本

    char name[BOOT_NAME_SIZE];          // ASCII产品名称
    char cmdline[BOOT_ARGS_SIZE];       // 命令行参数
    char id[BOOT_ID_SIZE];              // 时间戳/校验和/sha1等

    // 补充命令行数据；保留在这里以保持
    // 与旧版本mkbootimg的二进制兼容性。
    char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];  // 额外命令行参数
} __attribute__((packed));

// Boot镜像头部v1结构，继承自v0
struct boot_img_hdr_v1 : public boot_img_hdr_v0 {
    uint32_t recovery_dtbo_size;        // 恢复DTBO/ACPIO镜像大小（字节）
    uint64_t recovery_dtbo_offset;      // boot镜像中恢复dtbo/acpio的偏移量
    uint32_t header_size;               // 头部大小
} __attribute__((packed));

// Boot镜像头部v2结构，继承自v1
struct boot_img_hdr_v2 : public boot_img_hdr_v1 {
    uint32_t dtb_size;                  // DTB镜像大小（字节）
    uint64_t dtb_addr;                  // DTB镜像物理加载地址
} __attribute__((packed));

// 特殊的三星头部结构
struct boot_img_hdr_pxa : public boot_img_hdr_v0_common {
    uint32_t extra_size;                // 额外blob大小（字节）
    uint32_t unknown;                   // 未知字段
    uint32_t tags_addr;                 // 内核标签物理地址
    uint32_t page_size;                 // 我们假设的flash页面大小

    char name[24];                      // ASCII产品名称
    char cmdline[BOOT_ARGS_SIZE];       // 命令行参数
    char id[BOOT_ID_SIZE];              // 时间戳/校验和/sha1等

    char extra_cmdline[BOOT_EXTRA_ARGS_SIZE];  // 额外命令行参数
} __attribute__((packed));

/* 当boot镜像头部版本为3-4时，boot镜像的结构如下:
 *
 * +---------------------+
 * | boot header         | 4096 bytes
 * +---------------------+
 * | kernel              | m 页
 * +---------------------+
 * | ramdisk             | n 页
 * +---------------------+
 * | boot signature      | g 页
 * +---------------------+
 *
 * m = (kernel_size + 4096 - 1) / 4096
 * n = (ramdisk_size + 4096 - 1) / 4096
 * g = (signature_size + 4096 - 1) / 4096
 *
 * 页面大小固定为4096字节。
 *
 * 厂商boot镜像的结构如下:
 *
 * +------------------------+
 * | vendor boot header     | o 页
 * +------------------------+
 * | vendor ramdisk section | p 页
 * +------------------------+
 * | dtb                    | q 页
 * +------------------------+
 * | vendor ramdisk table   | r 页
 * +------------------------+
 * | bootconfig             | s 页
 * +------------------------+
 *
 * o = (2128 + page_size - 1) / page_size
 * p = (vendor_ramdisk_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 * r = (vendor_ramdisk_table_size + page_size - 1) / page_size
 * s = (vendor_bootconfig_size + page_size - 1) / page_size
 *
 * 注意在厂商boot镜像版本4中，可以在厂商boot镜像中包含多个厂商ramdisk。
 * 引导加载程序可以在运行时选择要加载的ramdisk子集。为了帮助引导加载程序选择
 * ramdisk，每个ramdisk都标有类型标签和一组硬件标识符，描述此ramdisk适用的
 * 主板、soc或平台。
 *
 * 厂商ramdisk段由多个ramdisk镜像连接组成，vendor_ramdisk_size是该段的大小，
 * 即厂商boot镜像中包含的所有ramdisk的总大小。
 *
 * 厂商ramdisk表保存每个ramdisk的大小、偏移、类型、名称和硬件标识符。
 * 类型字段表示其内容的类型。厂商ramdisk名称是唯一的。硬件标识符在每个表
 * 条目的board_id字段中指定。board_id字段由无符号整数字向量组成，编码方案
 * 由硬件厂商定义。
 *
 * 对于不同类型的ramdisk，有：
 *    - VENDOR_RAMDISK_TYPE_NONE 表示值未指定。
 *    - VENDOR_RAMDISK_TYPE_PLATFORM ramdisk包含平台特定位，因此引导加载程序
 *      应始终将这些加载到内存中。
 *    - VENDOR_RAMDISK_TYPE_RECOVERY ramdisk包含恢复资源，因此引导加载程序
 *      应在启动到恢复模式时加载这些。
 *    - VENDOR_RAMDISK_TYPE_DLKM ramdisk包含动态可加载内核模块。
 *
 * 厂商boot镜像版本4还在镜像末尾添加了bootconfig段。此段包含在构建时已知的
 * Boot Configuration参数。引导加载程序负责在进入内核之前将此段直接放在通用
 * ramdisk之后，然后是bootconfig尾部。
 */

// Boot镜像头部v3结构
struct boot_img_hdr_v3 {
    uint8_t magic[BOOT_MAGIC_SIZE];     // Boot魔数

    uint32_t kernel_size;               // 内核大小（字节）
    uint32_t ramdisk_size;              // Ramdisk大小（字节）
    uint32_t os_version;                // 操作系统版本
    uint32_t header_size;               // 头部大小
    uint32_t reserved[4];               // 保留字段

    uint32_t header_version;            // 头部版本

    char cmdline[BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE];  // 命令行参数
} __attribute__((packed));

// 厂商Boot镜像头部v3结构
struct boot_img_hdr_vnd_v3 {
    // 必须是VENDOR_BOOT_MAGIC
    uint8_t magic[BOOT_MAGIC_SIZE];     // 厂商Boot魔数
    // 厂商boot镜像头部版本
    uint32_t header_version;            // 头部版本
    uint32_t page_size;                 // 我们假设的flash页面大小
    uint32_t kernel_addr;               // 内核物理加载地址
    uint32_t ramdisk_addr;              // Ramdisk物理加载地址
    uint32_t ramdisk_size;              // Ramdisk大小（字节）
    char cmdline[VENDOR_BOOT_ARGS_SIZE];  // 厂商命令行参数
    uint32_t tags_addr;                 // 内核标签物理地址（如果需要）
    char name[BOOT_NAME_SIZE];          // ASCII产品名称
    uint32_t header_size;               // 头部大小
    uint32_t dtb_size;                  // DTB镜像大小（字节）
    uint64_t dtb_addr;                  // DTB镜像物理加载地址
} __attribute__((packed));

// Boot镜像头部v4结构，继承自v3
struct boot_img_hdr_v4 : public boot_img_hdr_v3 {
    uint32_t signature_size;            // 签名大小（字节）
} __attribute__((packed));

// 厂商Boot镜像头部v4结构，继承自厂商v3
struct boot_img_hdr_vnd_v4 : public boot_img_hdr_vnd_v3 {
    uint32_t vendor_ramdisk_table_size;       // 厂商ramdisk表大小（字节）
    uint32_t vendor_ramdisk_table_entry_num;  // 厂商ramdisk表条目数量
    uint32_t vendor_ramdisk_table_entry_size; // 厂商ramdisk表条目大小（字节）
    uint32_t bootconfig_size;                 // bootconfig段大小（字节）
} __attribute__((packed));

// 厂商Ramdisk表条目v4结构
struct vendor_ramdisk_table_entry_v4 {
    uint32_t ramdisk_size;              // ramdisk镜像大小（字节）
    uint32_t ramdisk_offset;            // 厂商ramdisk段中ramdisk镜像的偏移量
    uint32_t ramdisk_type;              // ramdisk类型
    uint8_t ramdisk_name[VENDOR_RAMDISK_NAME_SIZE]; // ASCII ramdisk名称

    // 描述此ramdisk预期加载的主板、soc或平台的硬件标识符
    uint32_t board_id[VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE];  // 主板ID
} __attribute__((packed));

/*******************************
 * 多态通用头部结构
 *******************************/

// 声明变量的宏定义
#define decl_var(name, len) \
virtual uint##len##_t &name() { j##len = 0; return j##len; }
// 声明值的宏定义
#define decl_val(name, type) \
virtual type name() { return 0; }

// 动态镜像头部基类
struct dyn_img_hdr {

    const bool is_vendor;               // 是否为厂商镜像

    // 标准条目
    decl_var(kernel_size, 32)           // 内核大小
    decl_var(ramdisk_size, 32)          // Ramdisk大小
    decl_var(second_size, 32)           // 第二阶段大小
    decl_val(page_size, uint32_t)       // 页面大小
    decl_val(header_version, uint32_t)  // 头部版本
    decl_var(extra_size, 32)            // 额外大小
    decl_var(os_version, 32)            // 操作系统版本
    decl_val(name, char *)              // 名称
    decl_val(cmdline, char *)           // 命令行参数
    decl_val(id, char *)                // ID
    decl_val(extra_cmdline, char *)     // 额外命令行参数
    uint32_t kernel_dt_size = 0;        // 内核设备树大小

    // v1/v2 特定字段
    decl_var(recovery_dtbo_size, 32)    // 恢复DTBO大小
    decl_var(recovery_dtbo_offset, 64)  // 恢复DTBO偏移
    decl_var(header_size, 32)           // 头部大小
    decl_var(dtb_size, 32)              // DTB大小

    // v4 特定字段
    decl_val(signature_size, uint32_t)              // 签名大小
    decl_val(vendor_ramdisk_table_size, uint32_t)   // 厂商ramdisk表大小
    decl_val(bootconfig_size, uint32_t)             // bootconfig大小

    // 虚析构函数，释放原始数据内存
    virtual ~dyn_img_hdr() {
        free(raw);
    }

    virtual size_t hdr_size() = 0;                  // 纯虚函数：获取头部大小
    virtual size_t hdr_space() { return page_size(); }  // 虚函数：获取头部空间大小
    virtual dyn_img_hdr *clone() = 0;               // 纯虚函数：克隆对象

    const void *raw_hdr() const { return raw; }     // 获取原始头部数据
    void print();                                   // 打印头部信息
    void dump_hdr_file();                          // 导出头部文件
    void load_hdr_file();                          // 加载头部文件

protected:
    // 联合体，用于不同类型的头部指针
    union {
        boot_img_hdr_v2 *v2_hdr;        /* AOSP v2 头部 */
        boot_img_hdr_v4 *v4_hdr;        /* AOSP v4 头部 */
        boot_img_hdr_vnd_v4 *v4_vnd;    /* AOSP 厂商 v4 头部 */
        boot_img_hdr_pxa *hdr_pxa;      /* 三星 PXA 头部 */
        void *raw;                      /* 原始指针 */
    };
    dyn_img_hdr(bool b) : is_vendor(b) {}   // 受保护构造函数

private:
    // 引用的垃圾变量
    static uint32_t j32;
    static uint64_t j64;
};

#undef decl_var
#undef decl_val

// 实现类的宏定义
#define __impl_cls(name, hdr)           \
protected: name() = default;            \
public:                                 \
name(const void *ptr) {                 \
    raw = malloc(sizeof(hdr));          \
    memcpy(raw, ptr, sizeof(hdr));      \
}                                       \
size_t hdr_size() override {            \
    return sizeof(hdr);                 \
}                                       \
dyn_img_hdr *clone() override {         \
    auto p = new name(raw);             \
    p->kernel_dt_size = kernel_dt_size; \
    return p;                           \
};

// 实现值的宏定义
#define __impl_val(name, hdr_name) \
decltype(std::declval<dyn_img_hdr>().name()) name() override { return hdr_name->name; }

// 动态镜像头部Boot基类
struct dyn_img_hdr_boot : public dyn_img_hdr {
protected:
    dyn_img_hdr_boot() : dyn_img_hdr(false) {}  // 非厂商镜像
};

#define impl_cls(ver)  __impl_cls(dyn_img_##ver, boot_img_hdr_##ver)
#define impl_val(name) __impl_val(name, v2_hdr)

// 动态镜像通用类
struct dyn_img_common : public dyn_img_hdr_boot {
    impl_val(kernel_size)               // 内核大小
    impl_val(ramdisk_size)              // Ramdisk大小
    impl_val(second_size)               // 第二阶段大小
};

// 动态镜像v0类
struct dyn_img_v0 : public dyn_img_common {
    impl_cls(v0)                        // 实现v0类

    impl_val(page_size)                 // 页面大小
    impl_val(extra_size)                // 额外大小
    impl_val(os_version)                // 操作系统版本
    impl_val(name)                      // 名称
    impl_val(cmdline)                   // 命令行参数
    impl_val(id)                        // ID
    impl_val(extra_cmdline)             // 额外命令行参数
};

// 动态镜像v1类，继承自v0
struct dyn_img_v1 : public dyn_img_v0 {
    impl_cls(v1)                        // 实现v1类

    impl_val(header_version)            // 头部版本
    impl_val(recovery_dtbo_size)        // 恢复DTBO大小
    impl_val(recovery_dtbo_offset)      // 恢复DTBO偏移
    impl_val(header_size)               // 头部大小

    uint32_t &extra_size() override { return dyn_img_hdr::extra_size(); }  // 重写额外大小
};

// 动态镜像v2类，继承自v1
struct dyn_img_v2 : public dyn_img_v1 {
    impl_cls(v2)                        // 实现v2类

    impl_val(dtb_size)                  // DTB大小
};

#undef impl_val
#define impl_val(name) __impl_val(name, hdr_pxa)

// 动态镜像PXA类（三星特殊格式），继承自通用类
struct dyn_img_pxa : public dyn_img_common {
    impl_cls(pxa)                       // 实现PXA类

    impl_val(extra_size)                // 额外大小
    impl_val(page_size)                 // 页面大小
    impl_val(name)                      // 名称
    impl_val(cmdline)                   // 命令行参数
    impl_val(id)                        // ID
    impl_val(extra_cmdline)             // 额外命令行参数
};

#undef impl_val
#define impl_val(name) __impl_val(name, v4_hdr)

// 动态镜像v3类，继承自Boot基类
struct dyn_img_v3 : public dyn_img_hdr_boot {
    impl_cls(v3)                        // 实现v3类

    impl_val(kernel_size)               // 内核大小
    impl_val(ramdisk_size)              // Ramdisk大小
    impl_val(os_version)                // 操作系统版本
    impl_val(header_size)               // 头部大小
    impl_val(header_version)            // 头部版本
    impl_val(cmdline)                   // 命令行参数

    // 使API兼容
    uint32_t page_size() override { return 4096; }  // 固定页面大小为4096
    char *extra_cmdline() override { return &v4_hdr->cmdline[BOOT_ARGS_SIZE]; }  // 获取额外命令行
};

// 动态镜像v4类，继承自v3
struct dyn_img_v4 : public dyn_img_v3 {
    impl_cls(v4)                        // 实现v4类

    impl_val(signature_size)            // 签名大小
};

// 动态镜像厂商头部基类
struct dyn_img_hdr_vendor : public dyn_img_hdr {
protected:
    dyn_img_hdr_vendor() : dyn_img_hdr(true) {}  // 厂商镜像
};

#undef impl_val
#define impl_val(name) __impl_val(name, v4_vnd)

// 动态镜像厂商v3类
struct dyn_img_vnd_v3 : public dyn_img_hdr_vendor {
    impl_cls(vnd_v3)                    // 实现厂商v3类

    impl_val(header_version)            // 头部版本
    impl_val(page_size)                 // 页面大小
    impl_val(ramdisk_size)              // Ramdisk大小
    impl_val(cmdline)                   // 命令行参数
    impl_val(name)                      // 名称
    impl_val(header_size)               // 头部大小
    impl_val(dtb_size)                  // DTB大小

    size_t hdr_space() override { return align_to(hdr_size(), page_size()); }  // 对齐到页面大小

    // 使API兼容
    char *extra_cmdline() override { return &v4_vnd->cmdline[BOOT_ARGS_SIZE]; }  // 获取额外命令行
};

// 动态镜像厂商v4类，继承自厂商v3
struct dyn_img_vnd_v4 : public dyn_img_vnd_v3 {
    impl_cls(vnd_v4)                    // 实现厂商v4类

    impl_val(vendor_ramdisk_table_size) // 厂商ramdisk表大小
    impl_val(bootconfig_size)           // bootconfig大小
};

#undef __impl_cls
#undef __impl_val
#undef impl_cls
#undef impl_val

/******************
 * 完整Boot镜像结构
 ******************/

// Boot镜像标志位枚举
enum {
    MTK_KERNEL,             // MTK内核标志
    MTK_RAMDISK,            // MTK Ramdisk标志
    CHROMEOS_FLAG,          // ChromeOS标志
    DHTB_FLAG,              // DHTB标志
    SEANDROID_FLAG,         // SEAndroid标志
    LG_BUMP_FLAG,           // LG BUMP标志
    SHA256_FLAG,            // SHA256标志
    BLOB_FLAG,              // BLOB标志
    NOOKHD_FLAG,            // NOOK HD标志
    ACCLAIM_FLAG,           // ACCLAIM标志
    AMONET_FLAG,            // AMONET标志
    AVB_FLAG,               // AVB标志
    ZIMAGE_KERNEL,          // zImage内核标志
    BOOT_FLAGS_MAX          // 标志位最大值
};

// Boot镜像主结构体
struct boot_img {
    // 整个镜像的内存映射
    mmap_data map;

    // Android镜像头部
    dyn_img_hdr *hdr;

    // 指示当前boot镜像状态的标志位
    std::bitset<BOOT_FLAGS_MAX> flags;

    // 内核、ramdisk和额外数据的格式
    format_t k_fmt = UNKNOWN;           // 内核格式
    format_t r_fmt = UNKNOWN;           // Ramdisk格式
    format_t e_fmt = UNKNOWN;           // 额外数据格式

    /*************************************************************
     * 以下指针指向只读mmap区域内
     *************************************************************/

    // MTK头部
    const mtk_hdr *k_hdr;               // MTK内核头部
    const mtk_hdr *r_hdr;               // MTK Ramdisk头部

    // parse_image后的指针/值
    // +---------------+
    // | z_hdr         | z_info.hdr_sz
    // +---------------+
    // | kernel        | hdr->kernel_size()
    // +---------------+
    // | z_info.tail   | z_info.tail_sz
    // +---------------+
    const zimage_hdr *z_hdr;            // zImage头部指针
    struct {
        uint32_t hdr_sz;                // 头部大小
        uint32_t tail_sz = 0;           // 尾部大小
        const uint8_t *tail = nullptr;  // 尾部数据指针
    } z_info;                           // zImage信息

    // 嵌入在内核中的dtb指针
    const uint8_t *kernel_dtb;

    // 镜像结尾指针
    const uint8_t *tail;                // 尾部数据指针
    size_t tail_size = 0;               // 尾部数据大小

    // AVB结构体
    const AvbFooter *avb_footer;        // AVB页脚
    const AvbVBMetaImageHeader *vbmeta; // VBMeta头部

    // 头部中定义的块指针
    const uint8_t *hdr_addr;            // 头部地址
    const uint8_t *kernel;              // 内核数据
    const uint8_t *ramdisk;             // Ramdisk数据
    const uint8_t *second;              // 第二阶段数据
    const uint8_t *extra;               // 额外数据
    const uint8_t *recovery_dtbo;       // 恢复DTBO数据
    const uint8_t *dtb;                 // DTB数据

    // 头部中定义但我们不关心的块指针
    const uint8_t *ignore;              // 忽略的数据
    size_t ignore_size = 0;             // 忽略数据大小

    boot_img(const char *);             // 构造函数，接受文件名
    ~boot_img();                        // 析构函数

    void parse_image(const uint8_t *addr, format_t type);           // 解析镜像
    dyn_img_hdr *create_hdr(const uint8_t *addr, format_t type);   // 创建头部
};