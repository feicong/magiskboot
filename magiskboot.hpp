// Magiskboot主要接口定义
#pragma once

#include <sys/types.h>

// 文件名常量定义
#define HEADER_FILE     "header"         // 头部文件
#define KERNEL_FILE     "kernel"         // 内核文件
#define RAMDISK_FILE    "ramdisk.cpio"   // Ramdisk文件
#define SECOND_FILE     "second"         // 第二分区文件
#define EXTRA_FILE      "extra"          // 额外文件
#define KER_DTB_FILE    "kernel_dtb"     // 内核DTB文件
#define RECV_DTBO_FILE  "recovery_dtbo"  // 恢复DTBO文件
#define DTB_FILE        "dtb"            // DTB文件
#define NEW_BOOT        "new-boot.img"   // 新的boot镜像

// 函数声明
int unpack(const char *image, bool skip_decomp = false, bool hdr = false);  // 解包
void repack(const char *src_img, const char *out_img, bool skip_comp = false);  // 重新打包
int split_image_dtb(const char *filename);  // 分离镜像DTB
int hexpatch(const char *file, const char *from, const char *to);  // 十六进制修补
int cpio_commands(int argc, char *argv[]);  // CPIO命令
int dtb_commands(int argc, char *argv[]);   // DTB命令

uint32_t patch_verity(void *buf, uint32_t size);       // 修补验证
uint32_t patch_encryption(void *buf, uint32_t size);   // 修补加密
bool check_env(const char *name);                      // 检查环境变量
