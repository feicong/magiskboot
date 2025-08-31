// 设备树二进制文件处理头文件
#pragma once

#include <stdint.h>

// 各种DTB格式的魔数定义
#define DT_TABLE_MAGIC  "\xd7\xb7\xab\x1e"  // 标准DTB表魔数
#define QCDT_MAGIC      "QCDT"               // 高通DTB魔数
#define DTBH_MAGIC      "DTBH"               // DTBH格式魔数
#define PXADT_MAGIC     "PXA-DT"             // PXA DTB魔数
#define PXA19xx_MAGIC   "PXA-19xx"           // PXA19xx魔数
#define SPRD_MAGIC      "SPRD"               // 展讯DTB魔数

// 高通DTB头部结构
struct qcdt_hdr {
    char magic[4];          /* "QCDT" 魔数 */
    uint32_t version;       /* QCDT版本 */
    uint32_t num_dtbs;      /* DTB数量 */
} __attribute__((packed));

// 高通DTB表v1结构
struct qctable_v1 {
    uint32_t cpu_info[3];   /* CPU信息 */
    uint32_t offset;        /* DTB在QCDT中的偏移 */
    uint32_t len;           /* DTB大小 */
} __attribute__((packed));

// 高通DTB表v2结构
struct qctable_v2 {
    uint32_t cpu_info[4];   /* CPU信息 */
    uint32_t offset;        /* DTB在QCDT中的偏移 */
    uint32_t len;           /* DTB大小 */
} __attribute__((packed));

// 高通DTB表v3结构
struct qctable_v3 {
    uint32_t cpu_info[8];   /* CPU信息 */
    uint32_t offset;        /* DTB在QCDT中的偏移 */
    uint32_t len;           /* DTB大小 */
} __attribute__((packed));

// DTBH头部结构
struct dtbh_hdr {
    char magic[4];          /* "DTBH" 魔数 */
    uint32_t version;       /* DTBH版本 */
    uint32_t num_dtbs;      /* DTB数量 */
} __attribute__((packed));

// BH表v2结构
struct bhtable_v2 {
    uint32_t cpu_info[5];   /* CPU信息 */
    uint32_t offset;        /* DTB在DTBH中的偏移 */
    uint32_t len;           /* DTB大小 */
    uint32_t space;         /* 0x00000020 */
} __attribute__((packed));

// PXA DTB头部结构
struct pxadt_hdr {
    char magic[6];          /* "PXA-DT" 魔数 */
    uint32_t version;       /* PXA-* 版本号 */
    uint32_t num_dtbs;      /* DTB数量 */
} __attribute__((packed));

struct pxa19xx_hdr {
    char magic[8];          /* "PXA-19xx" 魔数 */
    uint32_t version;       /* PXA-* 版本号 */
    uint32_t num_dtbs;      /* DTB数量 */
} __attribute__((packed));

struct pxatable_v1 {
    uint32_t cpu_info[2];   /* CPU信息 */
    uint32_t offset;        /* DTB在PXA格式中的偏移 */
    uint32_t len;           /* DTB大小 */
} __attribute__((packed));

struct sprd_hdr {
    char magic[4];          /* "SPRD" 魔数 */
    uint32_t version;       /* SPRD版本号 */
    uint32_t num_dtbs;      /* DTB数量 */
} __attribute__((packed));

struct sprdtable_v1 {
    uint32_t cpu_info[3];   /* CPU信息 */
    uint32_t offset;        /* DTB在SPRD格式中的偏移 */
    uint32_t len;           /* DTB大小 */
} __attribute__((packed));

/* AOSP DTB/DTBO分区布局 */

struct dt_table_header {
    uint32_t magic;             /* DT_TABLE_MAGIC 魔数 */
    uint32_t total_size;        /* 包含dt_table_header + 所有dt_table_entry的总大小 */
    uint32_t header_size;       /* sizeof(dt_table_header) 头部大小 */

    uint32_t dt_entry_size;     /* sizeof(dt_table_entry) 入口结构大小 */
    uint32_t num_dtbs;          /* dt_table_entry数量 */
    uint32_t dt_entries_offset; /* 第一个dt_table_entry的偏移 */

    uint32_t page_size;         /* 假设的flash页大小 */
    uint32_t version;           /* DTBO镜像版本 */
} __attribute__((packed));

struct dt_table_entry {
    uint32_t len;           /* DTB大小 */
    uint32_t offset;        /* DTB偏移地址 */

    uint32_t id;            /* 设备树ID */
    uint32_t rev;           /* 版本号 */
    uint32_t flags;         /* 标志位 */

    uint32_t custom[3];     /* 自定义字段 */
} __attribute__((packed));
