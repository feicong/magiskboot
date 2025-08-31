// MagiskBoot主程序文件
#include <mincrypt/sha.h>
#include <base.hpp>
#include <getopt.h>
#include <unistd.h>

#include "magiskboot.hpp"
#include "compress.hpp"

using namespace std;

// 打印支持的压缩格式
static void print_formats() {
    for (int fmt = GZIP; fmt < LZOP; ++fmt) {
        fprintf(stderr, "%s ", fmt2name[(format_t) fmt]);
    }
}

// 显示使用帮助信息
static void usage(char *arg0) {
    fprintf(stderr,
R"EOF(MagiskBoot - Boot镜像修改工具

用法: %s <操作> [参数...]

支持的操作:
  unpack [-n] [-h] <bootimg>
    将<bootimg>解包为各个组件，每个组件保存为
    当前目录中相应文件名的文件。
    支持的组件: kernel, kernel_dtb, ramdisk.cpio, second,
    dtb, extra, 和 recovery_dtbo。
    默认情况下，每个组件在写入输出文件之前会
    自动进行实时解压缩。
    如果提供'-n'选项，将跳过所有解压缩操作；
    每个组件将保持原样，以原始格式导出。
    如果提供'-h'选项，boot镜像头部信息将被
    导出到文件'header'，可用于在重新打包时
    修改头部配置。
    返回值:
    0:有效    1:错误    2:chromeos

  repack [-n] <origbootimg> [outbootimg]
    使用当前目录中的文件将boot镜像组件重新打包
    为[outbootimg]，如果未指定则为'new-boot.img'。
    <origbootimg>是用于解包组件的原始boot镜像。
    默认情况下，每个组件将使用在<origbootimg>中
    检测到的相应格式自动压缩。如果当前目录中的
    组件文件已经压缩，则不会对该特定组件执行
    额外的压缩。
    如果提供'-n'选项，将跳过所有压缩操作。
    如果环境变量PATCHVBMETAFLAG设置为true，
    boot镜像的vbmeta头部中的所有禁用标志将被设置。

  hexpatch <file> <hexpattern1> <hexpattern2>
    在<file>中搜索<hexpattern1>，并替换为<hexpattern2>

  cpio <incpio> [commands...]
    对<incpio>执行cpio命令（修改就地进行）
    每个命令是一个单独的参数，为每个命令添加引号。
    支持的命令:
      exists ENTRY
        如果ENTRY存在返回0，否则返回1
      rm [-r] ENTRY
        删除ENTRY，指定[-r]递归删除
      mkdir MODE ENTRY
        以权限MODE创建目录ENTRY
      ln TARGET ENTRY
        创建指向TARGET的符号链接，名称为ENTRY
      mv SOURCE DEST
        将SOURCE移动到DEST
      add MODE ENTRY INFILE
        以权限MODE将INFILE添加为ENTRY；如果存在则替换ENTRY
      extract [ENTRY OUT]
        将ENTRY提取到OUT，或将所有条目提取到"ramdisk"目录。
        创建"cpio"配置文件以支持Windows中的模式更改。
      sync
        将"ramdisk"目录与incpio条目同步。
        从"cpio"配置读取条目模式。
        任何更改都将被捕获并导出到incpio。
      test
        测试cpio的状态
        返回值是0或以下值的按位或:
        0x1:Magisk    0x2:不支持    0x4:Sony
      patch
        应用ramdisk补丁
        使用环境变量配置: KEEPVERITY KEEPFORCEENCRYPT
      backup ORIG
        从ORIG创建ramdisk备份
      restore
        从incpio中存储的ramdisk备份恢复ramdisk
      sha1
        如果之前在ramdisk中备份，打印原始boot SHA1
  cpio pack [-c <config>] <infolder> <outcpio>
    从<infolder>条目创建<outcpio>。
    条目模式从<config>（如果未定义则为"cpio"）读取，以支持在Windows中更改模式。

  dtb <file> <action> [args...]
    对<file>执行dtb相关操作
    支持的操作:
      print [-f]
        打印dtb的所有内容用于调试
        指定[-f]仅打印fstab节点
      patch
        搜索fstab并移除verity/avb
        修改直接对文件进行就地操作
        使用环境变量配置: KEEPVERITY
      test
        测试fstab的状态
        返回值:
        0:有效    1:错误

  split <file>
    将image.*-dtb分割为kernel + kernel_dtb

  sha1 <file>
    打印<file>的SHA1校验和

  cleanup
    清理当前工作目录

  compress[=format] <infile> [outfile]
    使用[format]将<infile>压缩为[outfile]。
    <infile>/[outfile]可以是'-'表示STDIN/STDOUT。
    如果未指定[format]，则使用gzip。
    如果未指定[outfile]，则<infile>将被替换为
    另一个带有匹配文件扩展名后缀的文件。
    支持的格式: )EOF", arg0);

    print_formats();

    fprintf(stderr, R"EOF(

  decompress <infile> [outfile]
    检测格式并将<infile>解压缩为[outfile]。
    <infile>/[outfile]可以是'-'表示STDIN/STDOUT。
    如果未指定[outfile]，则<infile>将被替换为
    另一个移除其存档格式文件扩展名的文件。
    支持的格式: )EOF");

    print_formats();

    fprintf(stderr, "\n\n");
    exit(1);
}

// 主函数
int main(int argc, char *argv[]) {

    if (argc < 2)
        usage(argv[0]);

    // 为了向后兼容，跳过'--'
    string_view action(argv[1]);
    if (str_starts(action, "--"))
        action = argv[1] + 2;

    if (action == "cleanup") {
        fprintf(stderr, "正在清理...\n");
        unlink(HEADER_FILE);       // 删除头部文件
        unlink(KERNEL_FILE);       // 删除内核文件
        unlink(RAMDISK_FILE);      // 删除ramdisk文件
        unlink(SECOND_FILE);       // 删除第二阶段文件
        unlink(KER_DTB_FILE);      // 删除内核DTB文件
        unlink(EXTRA_FILE);        // 删除额外文件
        unlink(RECV_DTBO_FILE);    // 删除恢复DTBO文件
        unlink(DTB_FILE);          // 删除DTB文件
    } else if (argc > 2 && action == "sha1") {
        uint8_t sha1[SHA_DIGEST_SIZE];
        auto m = mmap_data(argv[2]);              // 映射文件到内存
        SHA_hash(m.buf, m.sz, sha1);             // 计算SHA1哈希
        for (uint8_t i : sha1)
            printf("%02x", i);                   // 打印十六进制哈希值
        printf("\n");
    } else if (argc > 2 && action == "split") {
        return split_image_dtb(argv[2]);         // 分割镜像DTB
    } else if (argc > 2 && action == "unpack") {
        int idx = 2;
        bool nodecomp = false;                   // 不解压缩标志
        bool hdr = false;                        // 导出头部标志
        for (;;) {
            if (idx >= argc)
                usage(argv[0]);
            if (argv[idx][0] != '-')
                break;
            for (char *flag = &argv[idx][1]; *flag; ++flag) {
                if (*flag == 'n')
                    nodecomp = true;             // 设置不解压缩
                else if (*flag == 'h')
                    hdr = true;                  // 设置导出头部
                else
                    usage(argv[0]);
            }
            ++idx;
        }
        return unpack(argv[idx], nodecomp, hdr); // 执行解包操作
    } else if (argc > 2 && action == "repack") {
        if (argv[2] == "-n"sv) {
            if (argc == 3)
                usage(argv[0]);
            repack(argv[3], argv[4] ? argv[4] : NEW_BOOT, true);  // 不压缩重新打包
        } else {
            repack(argv[2], argv[3] ? argv[3] : NEW_BOOT);        // 正常重新打包
        }
    } else if (argc > 2 && action == "decompress") {
        decompress(argv[2], argv[3]);            // 执行解压缩
    } else if (argc > 2 && str_starts(action, "compress")) {
        compress(action[8] == '=' ? &action[9] : "gzip", argv[2], argv[3]);  // 执行压缩
    } else if (argc > 4 && action == "hexpatch") {
        return hexpatch(argv[2], argv[3], argv[4]);  // 执行十六进制补丁
    } else if (argc > 2 && action == "cpio"sv) {
        if (cpio_commands(argc - 2, argv + 2))       // 执行CPIO命令
            usage(argv[0]);
    } else if (argc > 3 && action == "dtb") {
        if (dtb_commands(argc - 2, argv + 2))        // 执行DTB命令
            usage(argv[0]);
    } else {
        usage(argv[0]);                              // 显示使用帮助
    }

    return 0;
}
