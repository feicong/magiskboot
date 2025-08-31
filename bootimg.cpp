// Boot镜像处理实现文件
#include <functional>
#include <memory>
#include <unistd.h> // 用于lseek, close, R_OK, ftruncate
#include <fcntl.h>  // 用于O_RDONLY等，R_OK实际在unistd.h中

#include <libfdt.h>
#include <mincrypt/sha.h>
#include <mincrypt/sha256.h>
#include <base.hpp>

#include "bootimg.hpp"
#include "magiskboot.hpp"
#include "compress.hpp"

#ifndef SVB_WIN32
  // 在像macOS和Linux这样的POSIX系统中，具有现代设置时，
  // off_t通常是64位的，lseek/ftruncate处理大文件。
  // 如果代码中使用了*64符号，这些定义将它们映射到标准对应项。
  #define off64_t off_t
  #define lseek64 lseek
  #define ftruncate64 ftruncate
#endif

using namespace std;

// 动态镜像头部的垃圾变量
uint32_t dyn_img_hdr::j32 = 0;
uint64_t dyn_img_hdr::j64 = 0;

#define PADDING 15  // 格式化输出时的填充宽度

// 解压缩函数，将压缩数据写入文件描述符
static void decompress(format_t type, int fd, const void *in, size_t size) {
    auto ptr = get_decoder(type, make_unique<fd_stream>(fd));
    ptr->write(in, size, true);
}

// 压缩函数，压缩数据并写入文件描述符，返回压缩后的大小
static off_t compress(format_t type, int fd, const void *in, size_t size) {
    auto prev = lseek(fd, 0, SEEK_CUR);      // 记录当前位置
    {
        auto strm = get_encoder(type, make_unique<fd_stream>(fd));
        strm->write(in, size, true);          // 写入压缩数据
    }
    auto now = lseek(fd, 0, SEEK_CUR);       // 记录新位置
    return now - prev;                       // 返回写入的字节数
}

// 将缓冲区数据导出到文件
static void dump(const void *buf, size_t size, const char *filename) {
    if (size == 0)
        return;
    int fd = creat(filename, 0644);          // 创建文件
    xwrite(fd, buf, size);                   // 写入数据
    close(fd);                               // 关闭文件
}

// 从文件恢复数据到文件描述符，返回恢复的数据大小
static size_t restore(int fd, const char *filename) {
    int ifd = xopen(filename, O_RDONLY);     // 打开输入文件
    size_t size = lseek(ifd, 0, SEEK_END);   // 获取文件大小
    lseek(ifd, 0, SEEK_SET);                 // 回到文件开头
    xsendfile(fd, ifd, nullptr, size);       // 复制文件内容
    close(ifd);                              // 关闭输入文件
    return size;                             // 返回文件大小
}

// 打印动态镜像头部信息
void dyn_img_hdr::print() {
    uint32_t ver = header_version();
    fprintf(stderr, "%-*s [%u]\n", PADDING, "HEADER_VER", ver);     // 头部版本
    if (!is_vendor)
        fprintf(stderr, "%-*s [%u]\n", PADDING, "KERNEL_SZ", kernel_size());  // 内核大小
    fprintf(stderr, "%-*s [%u]\n", PADDING, "RAMDISK_SZ", ramdisk_size());    // Ramdisk大小
    if (ver < 3)
        fprintf(stderr, "%-*s [%u]\n", PADDING, "SECOND_SZ", second_size());  // 第二阶段大小
    if (ver == 0)
        fprintf(stderr, "%-*s [%u]\n", PADDING, "EXTRA_SZ", extra_size());    // 额外数据大小
    if (ver == 1 || ver == 2)
        fprintf(stderr, "%-*s [%u]\n", PADDING, "RECOV_DTBO_SZ", recovery_dtbo_size());  // 恢复DTBO大小
    if (ver == 2 || is_vendor)
        fprintf(stderr, "%-*s [%u]\n", PADDING, "DTB_SZ", dtb_size());        // DTB大小

    // 解析并打印操作系统版本信息
    if (uint32_t os_ver = os_version()) {
        int a,b,c,y,m = 0;
        int version = os_ver >> 11;          // 版本号部分
        int patch_level = os_ver & 0x7ff;    // 补丁级别部分

        // 解析版本号A.B.C
        a = (version >> 14) & 0x7f;
        b = (version >> 7) & 0x7f;
        c = version & 0x7f;
        fprintf(stderr, "%-*s [%d.%d.%d]\n", PADDING, "OS_VERSION", a, b, c);

        // 解析补丁级别Y-M
        y = (patch_level >> 4) + 2000;      // 年份（从2000年开始）
        m = patch_level & 0xf;               // 月份
        fprintf(stderr, "%-*s [%d-%02d]\n", PADDING, "OS_PATCH_LEVEL", y, m);
    }

    fprintf(stderr, "%-*s [%u]\n", PADDING, "PAGESIZE", page_size());         // 页面大小
    if (char *n = name()) {
        fprintf(stderr, "%-*s [%s]\n", PADDING, "NAME", n);                   // 产品名称
    }
    // 打印命令行参数（标准+额外）
    fprintf(stderr, "%-*s [%.*s%.*s]\n", PADDING, "CMDLINE",
            BOOT_ARGS_SIZE, cmdline(), BOOT_EXTRA_ARGS_SIZE, extra_cmdline());
    if (char *checksum = id()) {
        fprintf(stderr, "%-*s [", PADDING, "CHECKSUM");                       // 校验和
        for (int i = 0; i < SHA256_DIGEST_SIZE; ++i)
            fprintf(stderr, "%02hhx", checksum[i]);
        fprintf(stderr, "]\n");
    }
}

void dyn_img_hdr::dump_hdr_file() {
    FILE *fp = xfopen(HEADER_FILE, "w");
    if (name())
        fprintf(fp, "name=%s\n", name());
    fprintf(fp, "cmdline=%.*s%.*s\n", BOOT_ARGS_SIZE, cmdline(), BOOT_EXTRA_ARGS_SIZE, extra_cmdline());
    uint32_t ver = os_version();
    if (ver) {
        int a, b, c, y, m;
        int version, patch_level;
        version = ver >> 11;
        patch_level = ver & 0x7ff;

        a = (version >> 14) & 0x7f;
        b = (version >> 7) & 0x7f;
        c = version & 0x7f;
        fprintf(fp, "os_version=%d.%d.%d\n", a, b, c);

        y = (patch_level >> 4) + 2000;
        m = patch_level & 0xf;
        fprintf(fp, "os_patch_level=%d-%02d\n", y, m);
    }
    fclose(fp);
}

void dyn_img_hdr::load_hdr_file() {
    parse_prop_file(HEADER_FILE, [=](string_view key, string_view value) -> bool {
        if (key == "name" && name()) {
            memset(name(), 0, 16);
            memcpy(name(), value.data(), value.length() > 15 ? 15 : value.length());
        } else if (key == "cmdline") {
            memset(cmdline(), 0, BOOT_ARGS_SIZE);
            memset(extra_cmdline(), 0, BOOT_EXTRA_ARGS_SIZE);
            if (value.length() > BOOT_ARGS_SIZE) {
                memcpy(cmdline(), value.data(), BOOT_ARGS_SIZE);
                auto len = std::min(value.length() - BOOT_ARGS_SIZE, (size_t) BOOT_EXTRA_ARGS_SIZE);
                memcpy(extra_cmdline(), &value[BOOT_ARGS_SIZE], len);
            } else {
                memcpy(cmdline(), value.data(), value.length());
            }
        } else if (key == "os_version") {
            int patch_level = os_version() & 0x7ff;
            int a, b, c;
            sscanf(value.data(), "%d.%d.%d", &a, &b, &c);
            os_version() = (((a << 14) | (b << 7) | c) << 11) | patch_level;
        } else if (key == "os_patch_level") {
            int os_ver = os_version() >> 11;
            int y, m;
            sscanf(value.data(), "%d-%d", &y, &m);
            y -= 2000;
            os_version() = (os_ver << 11) | (y << 4) | m;
        }
        return true;
    });
}

boot_img::boot_img(const char *image) : map(image) {
    fprintf(stderr, "Parsing image: [%s]\n", image);
    for (const uint8_t *addr = map.buf; addr < map.buf + map.sz; ++addr) {
        format_t fmt = check_fmt(addr, map.sz);
        switch (fmt) {
        case CHROMEOS:
            // chromeos require external signing
            flags[CHROMEOS_FLAG] = true;
            addr += 65535;
            break;
        case DHTB:
            flags[DHTB_FLAG] = true;
            flags[SEANDROID_FLAG] = true;
            fprintf(stderr, "DHTB_HDR\n");
            addr += sizeof(dhtb_hdr) - 1;
            break;
        case BLOB_FMT:
            flags[BLOB_FLAG] = true;
            fprintf(stderr, "TEGRA_BLOB\n");
            addr += sizeof(blob_hdr) - 1;
            break;
        case AOSP:
        case AOSP_VENDOR:
            parse_image(addr, fmt);
            return;
        default:
            break;
        }
    }
    exit(1);
}

// boot_img析构函数
boot_img::~boot_img() {
    delete hdr;  // 删除动态分配的头部对象
}

// 在缓冲区中查找DTB的偏移位置
static int find_dtb_offset(const uint8_t *buf, unsigned sz) {
    const uint8_t * const end = buf + sz;

    // 在缓冲区中搜索DTB magic
    for (auto curr = buf; curr < end; curr += sizeof(fdt_header)) {
        curr = static_cast<uint8_t*>(memmem(curr, end - curr, DTB_MAGIC, sizeof(fdt32_t)));
        if (curr == nullptr)
            return -1;

        auto fdt_hdr = reinterpret_cast<const fdt_header *>(curr);

        // 检查fdt_header.totalsize是否超出内核镜像大小
        uint32_t totalsize = fdt32_to_cpu(fdt_hdr->totalsize);
        if (totalsize > end - curr)
            continue;

        // 检查fdt_header.off_dt_struct是否超出内核镜像大小
        uint32_t off_dt_struct = fdt32_to_cpu(fdt_hdr->off_dt_struct);
        if (off_dt_struct > end - curr)
            continue;

        // 检查第一个节点的fdt_node_header.tag是否为FDT_BEGIN_NODE
        auto fdt_node_hdr = reinterpret_cast<const fdt_node_header *>(curr + off_dt_struct);
        if (fdt32_to_cpu(fdt_node_hdr->tag) != FDT_BEGIN_NODE)
            continue;

        return curr - buf;  // 返回DTB在缓冲区中的偏移
    }
    return -1;  // 未找到DTB
}

// 检查格式，特别处理LZ4_LEGACY和LZ4_LG的区别
static format_t check_fmt_lg(const uint8_t *buf, unsigned sz) {
    format_t fmt = check_fmt(buf, sz);
    if (fmt == LZ4_LEGACY) {
        // 需要检查是否为LZ4_LG格式
        uint32_t off = 4;
        uint32_t block_sz;
        while (off + sizeof(block_sz) <= sz) {
            memcpy(&block_sz, buf + off, sizeof(block_sz));
            off += sizeof(block_sz);
            if (off + block_sz > sz)
                return LZ4_LG;  // 如果块大小不匹配，则为LZ4_LG
            off += block_sz;
        }
    }
    return fmt;
}

#define CMD_MATCH(s) BUFFER_MATCH(h->cmdline, s)

// 根据地址和类型创建动态镜像头部
dyn_img_hdr *boot_img::create_hdr(const uint8_t *addr, format_t type) {
    if (type == AOSP_VENDOR) {
        fprintf(stderr, "VENDOR_BOOT_HDR\n");
        auto h = reinterpret_cast<const boot_img_hdr_vnd_v3*>(addr);
        hdr_addr = addr;
        switch (h->header_version) {
        case 4:
            return new dyn_img_vnd_v4(addr);  // 创建vendor v4头部
        default:
            return new dyn_img_vnd_v3(addr);  // 创建vendor v3头部
        }
    }

    auto h = reinterpret_cast<const boot_img_hdr_v0*>(addr);

    // PXA启动头部的特殊处理
    if (h->page_size >= 0x02000000) {
        fprintf(stderr, "PXA_BOOT_HDR\n");
        hdr_addr = addr;
        return new dyn_img_pxa(addr);
    }

    // 根据头部版本创建相应的动态头部对象
    auto make_hdr = [](const uint8_t *ptr) -> dyn_img_hdr * {
        auto h = reinterpret_cast<const boot_img_hdr_v0*>(ptr);
        switch (h->header_version) {
        case 1:
            return new dyn_img_v1(ptr);
        case 2:
            return new dyn_img_v2(ptr);
        case 3:
            return new dyn_img_v3(ptr);
        case 4:
            return new dyn_img_v4(ptr);
        default:
            return new dyn_img_v0(ptr);
        }
    };

    // 对于NOOKHD和ACCLAIM，整个启动镜像被固定偏移量移位
    // 对于AMONET，只有头部在内部被固定偏移量移位

    if (BUFFER_CONTAIN(addr, AMONET_MICROLOADER_SZ, AMONET_MICROLOADER_MAGIC) &&
        BUFFER_MATCH(addr + AMONET_MICROLOADER_SZ, BOOT_MAGIC)) {
        flags[AMONET_FLAG] = true;
        fprintf(stderr, "AMONET_MICROLOADER\n");

        // 真实头部被移位，复制到临时缓冲区
        h = reinterpret_cast<const boot_img_hdr_v0*>(addr + AMONET_MICROLOADER_SZ);
        auto real_hdr_sz = h->page_size - AMONET_MICROLOADER_SZ;
        auto buf = make_unique<uint8_t[]>(h->page_size);
        memcpy(buf.get(), h, real_hdr_sz);

        hdr_addr = addr;
        return make_hdr(buf.get());
    }

    // 检查NOOK HD系列和ACCLAIM的特殊magic
    if (CMD_MATCH(NOOKHD_RL_MAGIC) ||
        CMD_MATCH(NOOKHD_GL_MAGIC) ||
        CMD_MATCH(NOOKHD_GR_MAGIC) ||
        CMD_MATCH(NOOKHD_EB_MAGIC) ||
        CMD_MATCH(NOOKHD_ER_MAGIC)) {
        flags[NOOKHD_FLAG] = true;
        fprintf(stderr, "NOOKHD_LOADER\n");
        addr += NOOKHD_PRE_HEADER_SZ;  // 跳过前置头部
    } else if (BUFFER_MATCH(h->name, ACCLAIM_MAGIC)) {
        flags[ACCLAIM_FLAG] = true;
        fprintf(stderr, "ACCLAIM_LOADER\n");
        addr += ACCLAIM_PRE_HEADER_SZ;  // 跳过前置头部
    }

    // addr可能已被调整
    hdr_addr = addr;
    return make_hdr(addr);
}

// 获取并对齐块的宏定义
#define get_block(name)                 \
name = hdr_addr + off;                  \
off += hdr->name##_size();              \
off = align_to(off, hdr->page_size());

// 忽略块并更新忽略大小的宏定义
#define get_ignore(name)                                            \
if (hdr->name##_size()) {                                           \
    auto blk_sz = align_to(hdr->name##_size(), hdr->page_size());   \
    ignore_size += blk_sz;                                          \
    off += blk_sz;                                                  \
}

// 解析镜像文件的主要函数
void boot_img::parse_image(const uint8_t *addr, format_t type) {
    hdr = create_hdr(addr, type);  // 创建头部对象

    // 检查ID字段以确定是否使用SHA256
    if (char *id = hdr->id()) {
        for (int i = SHA_DIGEST_SIZE + 4; i < SHA256_DIGEST_SIZE; ++i) {
            if (id[i]) {
                flags[SHA256_FLAG] = true;
                break;
            }
        }
    }

    hdr->print();  // 打印头部信息

    // 按顺序获取各个块的位置
    size_t off = hdr->hdr_space();
    get_block(kernel);        // 获取内核块
    get_block(ramdisk);       // 获取ramdisk块
    get_block(second);        // 获取第二阶段块
    get_block(extra);         // 获取额外块
    get_block(recovery_dtbo); // 获取恢复DTBO块
    get_block(dtb);          // 获取DTB块

    // 处理需要忽略的块
    ignore = hdr_addr + off;
    get_ignore(signature)           // 忽略签名块
    get_ignore(vendor_ramdisk_table) // 忽略vendor ramdisk表
    get_ignore(bootconfig)          // 忽略启动配置块

    // 处理内核部分
    if (auto size = hdr->kernel_size()) {
        // 查找内核中的DTB
        if (int dtb_off = find_dtb_offset(kernel, size); dtb_off > 0) {
            kernel_dtb = kernel + dtb_off;
            hdr->kernel_dt_size = size - dtb_off;
            hdr->kernel_size() = dtb_off;
            fprintf(stderr, "%-*s [%u]\n", PADDING, "KERNEL_DTB_SZ", hdr->kernel_dt_size);
        }

        // 检查内核格式
        k_fmt = check_fmt_lg(kernel, hdr->kernel_size());
        if (k_fmt == MTK) {
            fprintf(stderr, "MTK_KERNEL_HDR\n");
            flags[MTK_KERNEL] = true;
            k_hdr = reinterpret_cast<const mtk_hdr *>(kernel);
            fprintf(stderr, "%-*s [%u]\n", PADDING, "SIZE", k_hdr->size);
            fprintf(stderr, "%-*s [%s]\n", PADDING, "NAME", k_hdr->name);
            kernel += sizeof(mtk_hdr);
            hdr->kernel_size() -= sizeof(mtk_hdr);
            k_fmt = check_fmt_lg(kernel, hdr->kernel_size());
        }
        // 处理ZIMAGE格式的内核
        if (k_fmt == ZIMAGE) {
            z_hdr = reinterpret_cast<const zimage_hdr *>(kernel);
            if (void *gzip_offset = memmem(kernel, hdr->kernel_size(), GZIP1_MAGIC "\x08\x00", 4)) {
                fprintf(stderr, "ZIMAGE_KERNEL\n");
                z_info.hdr_sz = (uint8_t *) gzip_offset - kernel;

                // 查找piggy的结束位置
                uint32_t zImage_size = z_hdr->end - z_hdr->start;
                uint32_t piggy_end = zImage_size;
                uint32_t offsets[16];
                memcpy(offsets, kernel + zImage_size - sizeof(offsets), sizeof(offsets));
                for (int i = 15; i >= 0; --i) {
                    if (offsets[i] > (zImage_size - 0xFF) && offsets[i] < zImage_size) {
                        piggy_end = offsets[i];
                        break;
                    }
                }

                if (piggy_end == zImage_size) {
                    fprintf(stderr, "! Could not find end of zImage piggy, keeping raw kernel\n");
                } else {
                    flags[ZIMAGE_KERNEL] = true;
                    z_info.tail = kernel + piggy_end;
                    z_info.tail_sz = hdr->kernel_size() - piggy_end;
                    kernel += z_info.hdr_sz;
                    hdr->kernel_size() = piggy_end - z_info.hdr_sz;
                    k_fmt = check_fmt_lg(kernel, hdr->kernel_size());
                }
            } else {
                fprintf(stderr, "! Could not find zImage gzip piggy, keeping raw kernel\n");
            }
        }
        fprintf(stderr, "%-*s [%s]\n", PADDING, "KERNEL_FMT", fmt2name[k_fmt]);
    }
    
    // 处理ramdisk部分
    if (auto size = hdr->ramdisk_size()) {
        if (hdr->is_vendor && hdr->header_version() >= 4) {
            // v4 vendor boot包含多个ramdisks
            // 暂时不处理
            r_fmt = UNKNOWN;
        } else {
            r_fmt = check_fmt_lg(ramdisk, size);
        }
        // 处理MTK ramdisk头部
        if (r_fmt == MTK) {
            fprintf(stderr, "MTK_RAMDISK_HDR\n");
            flags[MTK_RAMDISK] = true;
            r_hdr = reinterpret_cast<const mtk_hdr *>(ramdisk);
            fprintf(stderr, "%-*s [%u]\n", PADDING, "SIZE", r_hdr->size);
            fprintf(stderr, "%-*s [%s]\n", PADDING, "NAME", r_hdr->name);
            ramdisk += sizeof(mtk_hdr);
            hdr->ramdisk_size() -= sizeof(mtk_hdr);
            r_fmt = check_fmt_lg(ramdisk, hdr->ramdisk_size());
        }
        fprintf(stderr, "%-*s [%s]\n", PADDING, "RAMDISK_FMT", fmt2name[r_fmt]);
    }
    
    // 处理额外数据部分
    if (auto size = hdr->extra_size()) {
        e_fmt = check_fmt_lg(extra, size);
        fprintf(stderr, "%-*s [%s]\n", PADDING, "EXTRA_FMT", fmt2name[e_fmt]);
    }

    // 处理尾部数据
    if (addr + off < map.buf + map.sz) {
        tail = addr + off;
        tail_size = map.buf + map.sz - tail;

        // 检查特殊标志
        if (tail_size >= 16 && BUFFER_MATCH(tail, SEANDROID_MAGIC)) {
            fprintf(stderr, "SAMSUNG_SEANDROID\n");
            flags[SEANDROID_FLAG] = true;
        } else if (tail_size >= 16 && BUFFER_MATCH(tail, LG_BUMP_MAGIC)) {
            fprintf(stderr, "LG_BUMP_IMAGE\n");
            flags[LG_BUMP_FLAG] = true;
        }

        // 查找AVB footer
        const void *footer = tail + tail_size - sizeof(AvbFooter);
        if (BUFFER_MATCH(footer, AVB_FOOTER_MAGIC)) {
            avb_footer = reinterpret_cast<const AvbFooter*>(footer);
            // 双重检查meta头部是否存在
            const void *meta = hdr_addr + __builtin_bswap64(avb_footer->vbmeta_offset);
            if (BUFFER_MATCH(meta, AVB_MAGIC)) {
                fprintf(stderr, "VBMETA\n");
                flags[AVB_FLAG] = true;
                vbmeta = reinterpret_cast<const AvbVBMetaImageHeader*>(meta);
            }
        }
    }
}

// 分离镜像中的DTB
int split_image_dtb(const char *filename) {
    auto img = mmap_data(filename);

    if (int off = find_dtb_offset(img.buf, img.sz); off > 0) {
        format_t fmt = check_fmt_lg(img.buf, img.sz);
        if (COMPRESSED(fmt)) {
            // 如果是压缩格式，先解压缩再写入
            int fd = creat(KERNEL_FILE, 0644);
            decompress(fmt, fd, img.buf, off);
            close(fd);
        } else {
            // 直接写入内核文件
            dump(img.buf, off, KERNEL_FILE);
        }
        dump(img.buf + off, img.sz - off, KER_DTB_FILE);  // 写入DTB文件
        return 0;
    } else {
        fprintf(stderr, "Cannot find DTB in %s\n", filename);
        return 1;
    }
}

// 解包启动镜像
int unpack(const char *image, bool skip_decomp, bool hdr) {
    boot_img boot(image);

    if (hdr)
        boot.hdr->dump_hdr_file();

    // Dump kernel
    if (!skip_decomp && COMPRESSED(boot.k_fmt)) {
        if (boot.hdr->kernel_size() != 0) {
            int fd = creat(KERNEL_FILE, 0644);
            decompress(boot.k_fmt, fd, boot.kernel, boot.hdr->kernel_size());
            close(fd);
        }
    } else {
        dump(boot.kernel, boot.hdr->kernel_size(), KERNEL_FILE);
    }

    // Dump kernel_dtb
    dump(boot.kernel_dtb, boot.hdr->kernel_dt_size, KER_DTB_FILE);

    // Dump ramdisk
    if (!skip_decomp && COMPRESSED(boot.r_fmt)) {
        if (boot.hdr->ramdisk_size() != 0) {
            int fd = creat(RAMDISK_FILE, 0644);
            decompress(boot.r_fmt, fd, boot.ramdisk, boot.hdr->ramdisk_size());
            close(fd);
        }
    } else {
        dump(boot.ramdisk, boot.hdr->ramdisk_size(), RAMDISK_FILE);
    }

    // Dump second
    dump(boot.second, boot.hdr->second_size(), SECOND_FILE);

    // Dump extra
    if (!skip_decomp && COMPRESSED(boot.e_fmt)) {
        if (boot.hdr->extra_size() != 0) {
            int fd = creat(EXTRA_FILE, 0644);
            decompress(boot.e_fmt, fd, boot.extra, boot.hdr->extra_size());
            close(fd);
        }
    } else {
        dump(boot.extra, boot.hdr->extra_size(), EXTRA_FILE);
    }

    // Dump recovery_dtbo
    dump(boot.recovery_dtbo, boot.hdr->recovery_dtbo_size(), RECV_DTBO_FILE);

    // Dump dtb
    dump(boot.dtb, boot.hdr->dtb_size(), DTB_FILE);

    return boot.flags[CHROMEOS_FLAG] ? 2 : 0;
}

#define file_align_with(page_size) \
write_zero(fd, align_padding(lseek(fd, 0, SEEK_CUR) - off.header, page_size))

#define file_align() file_align_with(boot.hdr->page_size())

void repack(const char *src_img, const char *out_img, bool skip_comp) {
    const boot_img boot(src_img);
    fprintf(stderr, "Repack to image: [%s]\n", out_img);

    struct {
        uint32_t header;
        uint32_t kernel;
        uint32_t ramdisk;
        uint32_t second;
        uint32_t extra;
        uint32_t dtb;
        uint32_t total;
        uint32_t vbmeta;
    } off{};

    // Create a new boot header and reset sizes
    // 克隆头部并重置大小字段
    auto hdr = boot.hdr->clone();
    hdr->kernel_size() = 0;
    hdr->ramdisk_size() = 0;
    hdr->second_size() = 0;
    hdr->dtb_size() = 0;
    hdr->kernel_dt_size = 0;

    // 如果存在头部文件，加载头部文件
    if (access(HEADER_FILE, R_OK) == 0)
        hdr->load_hdr_file();

    /***************
     * 写入各个块
     ***************/

    // 创建新镜像文件
    int fd = creat(out_img, 0644);

    // 处理不同类型的前置头部
    if (boot.flags[DHTB_FLAG]) {
        // 跳过DHTB头部
        write_zero(fd, sizeof(dhtb_hdr));
    } else if (boot.flags[BLOB_FLAG]) {
        xwrite(fd, boot.map.buf, sizeof(blob_hdr));
    } else if (boot.flags[NOOKHD_FLAG]) {
        xwrite(fd, boot.map.buf, NOOKHD_PRE_HEADER_SZ);
    } else if (boot.flags[ACCLAIM_FLAG]) {
        xwrite(fd, boot.map.buf, ACCLAIM_PRE_HEADER_SZ);
    }

    // 复制原始头部
    off.header = lseek(fd, 0, SEEK_CUR);
    xwrite(fd, boot.hdr_addr, hdr->hdr_space());

    // 写入内核部分
    off.kernel = lseek(fd, 0, SEEK_CUR);
    if (boot.flags[MTK_KERNEL]) {
        // 复制MTK头部
        xwrite(fd, boot.k_hdr, sizeof(mtk_hdr));
    }
    if (boot.flags[ZIMAGE_KERNEL]) {
        // 复制zImage头部
        xwrite(fd, boot.z_hdr, boot.z_info.hdr_sz);
    }
    if (access(KERNEL_FILE, R_OK) == 0) {
        auto m = mmap_data(KERNEL_FILE);
        if (!skip_comp && !COMPRESSED_ANY(check_fmt(m.buf, m.sz)) && COMPRESSED(boot.k_fmt)) {
            // 对于zImage压缩总是使用zopfli
            auto fmt = (boot.flags[ZIMAGE_KERNEL] && boot.k_fmt == GZIP) ? ZOPFLI : boot.k_fmt;
            hdr->kernel_size() = compress(fmt, fd, m.buf, m.sz);
        } else {
            hdr->kernel_size() = xwrite(fd, m.buf, m.sz);
        }

        // 特殊处理zImage内核
        if (boot.flags[ZIMAGE_KERNEL]) {
            if (hdr->kernel_size() > boot.hdr->kernel_size()) {
                fprintf(stderr, "! Recompressed kernel is too large, using original kernel\n");
                ftruncate64(fd, lseek64(fd, - (off64_t) hdr->kernel_size(), SEEK_CUR));
                xwrite(fd, boot.kernel, boot.hdr->kernel_size());
            } else if (!skip_comp) {
                // 填充零以确保zImage文件大小不变
                // 同时确保最后4字节是未压缩的vmlinux大小
                uint32_t sz = m.sz;
                write_zero(fd, boot.hdr->kernel_size() - hdr->kernel_size() - sizeof(sz));
                xwrite(fd, &sz, sizeof(sz));
            }

            // zImage大小应保持不变
            hdr->kernel_size() = boot.hdr->kernel_size();
        }
    } else if (boot.hdr->kernel_size() != 0) {
        xwrite(fd, boot.kernel, boot.hdr->kernel_size());
        hdr->kernel_size() = boot.hdr->kernel_size();
    }
    if (boot.flags[ZIMAGE_KERNEL]) {
        // 复制zImage尾部并相应调整大小
        hdr->kernel_size() += boot.z_info.hdr_sz;
        hdr->kernel_size() += xwrite(fd, boot.z_info.tail, boot.z_info.tail_sz);
    }

    // 内核DTB
    if (access(KER_DTB_FILE, R_OK) == 0)
        hdr->kernel_size() += restore(fd, KER_DTB_FILE);
    file_align();

    // ramdisk部分
    off.ramdisk = lseek(fd, 0, SEEK_CUR);
    if (boot.flags[MTK_RAMDISK]) {
        // 复制MTK头部
        xwrite(fd, boot.r_hdr, sizeof(mtk_hdr));
    }
    if (access(RAMDISK_FILE, R_OK) == 0) {
        auto m = mmap_data(RAMDISK_FILE);
        auto r_fmt = boot.r_fmt;
        if (!skip_comp && !hdr->is_vendor && hdr->header_version() == 4 && r_fmt != LZ4_LEGACY) {
            // v4启动镜像ramdisk将与其他vendor ramdisks合并，
            // 它们必须使用完全相同的压缩方法。v4 GKIs要求
            // 使用lz4 (legacy)，所以在这里硬编码格式。
            fprintf(stderr, "RAMDISK_FMT: [%s] -> [%s]\n", fmt2name[r_fmt], fmt2name[LZ4_LEGACY]);
            r_fmt = LZ4_LEGACY;
        }
        if (!skip_comp && !COMPRESSED_ANY(check_fmt(m.buf, m.sz)) && COMPRESSED(r_fmt)) {
            hdr->ramdisk_size() = compress(r_fmt, fd, m.buf, m.sz);
        } else {
            hdr->ramdisk_size() = xwrite(fd, m.buf, m.sz);
        }
        file_align();
    }

    // 第二阶段部分
    off.second = lseek(fd, 0, SEEK_CUR);
    if (access(SECOND_FILE, R_OK) == 0) {
        hdr->second_size() = restore(fd, SECOND_FILE);
        file_align();
    }

    // 额外数据部分
    off.extra = lseek(fd, 0, SEEK_CUR);
    if (access(EXTRA_FILE, R_OK) == 0) {
        auto m = mmap_data(EXTRA_FILE);
        if (!skip_comp && !COMPRESSED_ANY(check_fmt(m.buf, m.sz)) && COMPRESSED(boot.e_fmt)) {
            hdr->extra_size() = compress(boot.e_fmt, fd, m.buf, m.sz);
        } else {
            hdr->extra_size() = xwrite(fd, m.buf, m.sz);
        }
        file_align();
    }

    // 恢复DTBO部分
    if (access(RECV_DTBO_FILE, R_OK) == 0) {
        hdr->recovery_dtbo_offset() = lseek(fd, 0, SEEK_CUR);
        hdr->recovery_dtbo_size() = restore(fd, RECV_DTBO_FILE);
        file_align();
    }

    // DTB部分
    off.dtb = lseek(fd, 0, SEEK_CUR);
    if (access(DTB_FILE, R_OK) == 0) {
        hdr->dtb_size() = restore(fd, DTB_FILE);
        file_align();
    }

    // 直接复制被忽略的块
    if (boot.ignore_size) {
        // ignore_size应该已经对齐
        xwrite(fd, boot.ignore, boot.ignore_size);
    }

    // 厂商专有数据
    if (boot.flags[SEANDROID_FLAG]) {
        xwrite(fd, SEANDROID_MAGIC, 16);
        if (boot.flags[DHTB_FLAG]) {
            xwrite(fd, "\xFF\xFF\xFF\xFF", 4);
        }
    } else if (boot.flags[LG_BUMP_FLAG]) {
        xwrite(fd, LG_BUMP_MAGIC, 16);
    }

    off.total = lseek(fd, 0, SEEK_CUR);
    file_align();

    // vbmeta部分
    if (boot.flags[AVB_FLAG]) {
        // 根据avbtool.py，如果输入不是Android稀疏镜像
        // （启动镜像不是），默认块大小是4096
        file_align_with(4096);
        off.vbmeta = lseek(fd, 0, SEEK_CUR);
        uint64_t vbmeta_size = __builtin_bswap64(boot.avb_footer->vbmeta_size);
        xwrite(fd, boot.vbmeta, vbmeta_size);
    }

    // 如果不是chromeos，将镜像填充到原始大小（因为它需要后处理）
    if (!boot.flags[CHROMEOS_FLAG]) {
        off_t current = lseek(fd, 0, SEEK_CUR);
        if (current < boot.map.sz) {
            write_zero(fd, boot.map.sz - current);
        }
    }

    close(fd);

    /******************
     * 补丁镜像
     ******************/

    // 以读写方式映射输出镜像
    auto out = mmap_data(out_img, true);

    // MTK头部处理
    if (boot.flags[MTK_KERNEL]) {
        auto m_hdr = reinterpret_cast<mtk_hdr *>(out.buf + off.kernel);
        m_hdr->size = hdr->kernel_size();
        hdr->kernel_size() += sizeof(mtk_hdr);
    }
    if (boot.flags[MTK_RAMDISK]) {
        auto m_hdr = reinterpret_cast<mtk_hdr *>(out.buf + off.ramdisk);
        m_hdr->size = hdr->ramdisk_size();
        hdr->ramdisk_size() += sizeof(mtk_hdr);
    }

    // 确保头部大小匹配
    hdr->header_size() = hdr->hdr_size();

    // 更新校验和
    if (char *id = hdr->id()) {
        HASH_CTX ctx;
        boot.flags[SHA256_FLAG] ? SHA256_init(&ctx) : SHA_init(&ctx);
        uint32_t size = hdr->kernel_size();
        HASH_update(&ctx, out.buf + off.kernel, size);
        HASH_update(&ctx, &size, sizeof(size));
        size = hdr->ramdisk_size();
        HASH_update(&ctx, out.buf + off.ramdisk, size);
        HASH_update(&ctx, &size, sizeof(size));
        size = hdr->second_size();
        HASH_update(&ctx, out.buf + off.second, size);
        HASH_update(&ctx, &size, sizeof(size));
        size = hdr->extra_size();
        if (size) {
            HASH_update(&ctx, out.buf + off.extra, size);
            HASH_update(&ctx, &size, sizeof(size));
        }
        uint32_t ver = hdr->header_version();
        if (ver == 1 || ver == 2) {
            size = hdr->recovery_dtbo_size();
            HASH_update(&ctx, out.buf + hdr->recovery_dtbo_offset(), size);
            HASH_update(&ctx, &size, sizeof(size));
        }
        if (ver == 2) {
            size = hdr->dtb_size();
            HASH_update(&ctx, out.buf + off.dtb, size);
            HASH_update(&ctx, &size, sizeof(size));
        }
        memset(id, 0, BOOT_ID_SIZE);
        memcpy(id, HASH_final(&ctx), boot.flags[SHA256_FLAG] ? SHA256_DIGEST_SIZE : SHA_DIGEST_SIZE);
    }

    // 打印新头部信息
    hdr->print();

    // 复制主头部
    if (boot.flags[AMONET_FLAG]) {
        auto real_hdr_sz = std::min(hdr->hdr_space() - AMONET_MICROLOADER_SZ, hdr->hdr_size());
        memcpy(out.buf + off.header + AMONET_MICROLOADER_SZ, hdr->raw_hdr(), real_hdr_sz);
    } else {
        memcpy(out.buf + off.header, hdr->raw_hdr(), hdr->hdr_size());
    }

    // 处理AVB结构
    if (boot.flags[AVB_FLAG]) {
        // 复制并补丁AVB结构
        auto footer = reinterpret_cast<AvbFooter*>(out.buf + out.sz - sizeof(AvbFooter));
        auto vbmeta = reinterpret_cast<AvbVBMetaImageHeader*>(out.buf + off.vbmeta);
        memcpy(footer, boot.avb_footer, sizeof(AvbFooter));
        footer->original_image_size = __builtin_bswap64(off.total);
        footer->vbmeta_offset = __builtin_bswap64(off.vbmeta);
        if (check_env("PATCHVBMETAFLAG")) {
            vbmeta->flags = __builtin_bswap32(3);
        }
    }

    // 处理特殊头部格式
    if (boot.flags[DHTB_FLAG]) {
        // DHTB头部
        auto d_hdr = reinterpret_cast<dhtb_hdr *>(out.buf);
        memcpy(d_hdr, DHTB_MAGIC, 8);
        d_hdr->size = off.total - sizeof(dhtb_hdr);
        SHA256_hash(out.buf + sizeof(dhtb_hdr), d_hdr->size, d_hdr->checksum);
    } else if (boot.flags[BLOB_FLAG]) {
        // Blob头部
        auto b_hdr = reinterpret_cast<blob_hdr *>(out.buf);
        b_hdr->size = off.total - sizeof(blob_hdr);
    }

    // 返回成功
}
