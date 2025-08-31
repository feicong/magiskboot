// CPIO归档文件处理实现
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <algorithm>

#include <base.hpp>

#include "cpio.hpp"

using namespace std;

// CPIO newc头部结构
struct cpio_newc_header {
    char magic[6];      // 魔数
    char ino[8];        // 索引节点号
    char mode[8];       // 文件模式
    char uid[8];        // 用户ID
    char gid[8];        // 组ID
    char nlink[8];      // 硬链接数
    char mtime[8];      // 修改时间
    char filesize[8];   // 文件大小
    char devmajor[8];   // 设备主号
    char devminor[8];   // 设备次号
    char rdevmajor[8];  // 特殊设备主号
    char rdevminor[8];  // 特殊设备次号
    char namesize[8];   // 文件名大小
    char check[8];      // 校验和
} __attribute__((packed));

// 8位十六进制字符串转换为uint32
static uint32_t x8u(const char *hex) {
    uint32_t val, inpos = 8, outpos;
    char pattern[6];

    while (*hex == '0') {
        hex++;
        if (!--inpos) return 0;
    }
    // 因为scanf对%*X的处理方式与printf不同
    sprintf(pattern, "%%%dx%%n", inpos);
    sscanf(hex, pattern, &val, &outpos);
    if (inpos != outpos)
        LOGE("bad cpio header\n");

    return val;
}

// CPIO入口构造函数
cpio_entry::cpio_entry(uint32_t mode) : mode(mode), uid(0), gid(0), filesize(0), data(nullptr) {}

cpio_entry::cpio_entry(uint32_t mode, uint32_t uid, uint32_t gid) : mode(mode), uid(uid), gid(gid), filesize(0), data(nullptr) {}

cpio_entry::cpio_entry(const cpio_newc_header *h) :
mode(x8u(h->mode)), uid(x8u(h->uid)), gid(x8u(h->gid)), filesize(x8u(h->filesize)), data(nullptr)
{}

// 递归目录遍历器
static void recursive_dir_iterator(cpio::entry_map &entries, const char* root, const char *sub = nullptr) {
    auto path = sub ? sub : root;
    auto cur = opendir(path);

    if (errno || !cur)
        return;

    for (dirent *entry; (entry = xreaddir(cur));) {
        char *filename = (char *)malloc(strlen(path) + 2 +
#ifndef SVB_MINGW
        strlen(entry->d_name));
#else
        entry->d_namlen);
#endif
        struct stat st;

        if (sprintf(filename, "%s/%s", path, entry->d_name) < 0 ||
            xlstat(filename, &st)) {
            errno = EINVAL;
            break;
        }

        auto e = new cpio_entry(st.st_mode, st.st_uid, st.st_gid);
        auto name = filename + strlen(root) + 1;
        auto type = st.st_mode & S_IFMT;

        if (type == S_IFREG) {                      // 常规文件
            auto m = mmap_data(filename);
            e->filesize = m.sz;
            e->data = xmalloc(m.sz);
            memcpy(e->data, m.buf, m.sz);
        } else if (type == S_IFLNK) {               // 符号链接
            char* ln_target = (char *)malloc(st.st_size + 1);
            int read_cnt = xreadlink(filename, ln_target, st.st_size);

            if (read_cnt == -1 || read_cnt > st.st_size) {
                errno = EINVAL;
                return;
            }
            e->filesize = st.st_size;
            e->data = ln_target;
        } else {                                    // 假设为目录
            recursive_dir_iterator(entries, root, filename);
        }

        entries.emplace(name, e);
        free(filename);
    }

    closedir(cur);
}

// 转储CPIO到文件
void cpio::dump(const char *file) {
    fprintf(stderr, "Dump cpio: [%s]\n", file);
    dump(xfopen(file, "we"));
}

// 删除条目（迭代器版本）
void cpio::rm(entry_map::iterator it) {
    if (it == entries.end())
        return;
    fprintf(stderr, "Remove [%s]\n", it->first.data());
    entries.erase(it);
}

// 删除条目（名称版本）
void cpio::rm(const char *name, bool r) {
    size_t len = strlen(name);
    for (auto it = entries.begin(); it != entries.end();) {
        if (it->first.compare(0, len, name) == 0 &&
            ((r && it->first[len] == '/') || it->first[len] == '\0')) {
            auto tmp = it;
            ++it;
            rm(tmp);
            if (!r) return;     // 如果不递归，删除一个后返回
        } else {
            ++it;
        }
    }
}

// 提取单个条目
void cpio::extract_entry(const entry_map::value_type &e, const char *file) {
    fprintf(stderr, "Extract [%s] to [%s]\n", e.first.data(), file);
    unlink(file);
    rmdir(file);
    // 确保父目录存在
    char *parent = dirname(strdup(file));
    xmkdirs(parent, 0755);
    if (S_ISDIR(e.second->mode)) {
        xmkdir(file, e.second->mode & 0777);
    } else if (S_ISREG(e.second->mode)) {        // 常规文件
        int fd = xopen(file, O_CREAT | O_WRONLY | O_TRUNC, e.second->mode & 0777);
        xwrite(fd, e.second->data, e.second->filesize);
#ifndef SVB_WIN32
        fchown(fd, e.second->uid, e.second->gid);
#endif
        close(fd);
    } else if (S_ISLNK(e.second->mode) && e.second->filesize < 4096) {  // 符号链接
        char target[4096];
        memcpy(target, e.second->data, e.second->filesize);
        target[e.second->filesize] = '\0';
        symlink(target, file);
    }
#ifdef SVB_WIN32
    FILE *config = fopen("cpio", "a");
    fprintf(config, "%s %o %u %u\n", e.first.data(), e.second->mode & 0777, e.second->uid, e.second->gid);
    fclose(config);
#endif
}

// 提取所有条目到ramdisk目录
void cpio::extract() {
    unlink("cpio");
    rmdir("ramdisk");
#ifdef SVB_MINGW
    ::mkdir("ramdisk");
#else
    ::mkdir("ramdisk", 0744);
#endif
    for (auto &e : entries)
        extract_entry(e, ("ramdisk/" + e.first).data());
}

// 从目录加载CPIO
void cpio::load_cpio(const char* dir, const char* config, bool sync) {
    entry_map dentries;

    recursive_dir_iterator(dentries, dir);

    if (errno) {
        PLOGE("%s [%s]", sync ? "Sync" : "Pack", dir);
        return;
    }

    // 逐行读取配置文件
    file_readline(config, [&](string_view line) -> bool {
        if (line.empty() || line[0] == '#')
            return true;

        auto tokens = split(string(line), " ");

        if (tokens.size() < 4) {
            LOGE("Ill-formed line in [%s]\n", config);
        }

        auto it = dentries.find(tokens[0].data());
        if (it != dentries.end()) {
            it->second->mode &= S_IFMT;
            it->second->mode |= static_cast<unsigned int>(strtol(tokens[1].data(), nullptr, 8)) & 0777;
            it->second->uid = strtol(tokens[2].data(), nullptr, 10);
            it->second->gid = strtol(tokens[3].data(), nullptr, 10);
        }

        return true;
    });

    if (!sync) {
        entries = std::move(dentries);
        return;
    }

    auto rhs = entries.begin();
    auto lhs = dentries.begin();

    while (rhs != entries.end() || lhs != dentries.end()) {
        int res;
        if (lhs != dentries.end() && rhs != entries.end()) {
            res = rhs->first.compare(lhs->first);
        } else if (rhs == entries.end()) {
            res = 1;
        } else {
            res = -1;
        }

        bool is_new = res >= 0;

        // 同步比较两个条目映射
        if (res < 0) {              // 文件已删除
            rm(rhs++);
        } else if (res == 0) {      // 文件相同，可能有变化
            is_new = rhs->second->filesize != lhs->second->filesize ||
                     rhs->second->mode != lhs->second->mode ||
                     rhs->second->uid != lhs->second->uid ||
                     rhs->second->gid != lhs->second->gid ||
                     memcmp(lhs->second->data, rhs->second->data, lhs->second->filesize) != 0;
        }                           // 文件已添加

        if (is_new) {
            fprintf(stderr, "%s entry [%s] (%04o)\n", res > 0 ? "Add new" : "Updated", lhs->first.data(), lhs->second->mode & 0777);
            insert(lhs->first, lhs->second.release());
        }

        if (res > 0) {
            ++lhs;
        } else if (res == 0)  {
            ++lhs; ++rhs;
        }
    }
}

// 提取指定条目到文件
bool cpio::extract(const char *name, const char *file) {
    auto it = entries.find(name);
    if (it != entries.end()) {
        extract_entry(*it, file);
        return true;
    }
    fprintf(stderr, "Cannot find the file entry [%s]\n", name);
    return false;
}

// 检查条目是否存在
bool cpio::exists(const char *name) {
    return entries.count(name) != 0;
}

#define do_out(buf, len) pos += fwrite(buf, 1, len, out);
#define out_align() do_out(zeros, align_padding(pos, 4))
// 将CPIO转储到文件流
void cpio::dump(FILE *out) {
    size_t pos = 0;
    unsigned inode = 300000;
    char header[111];
    char zeros[4] = {0};
    for (auto &e : entries) {
        sprintf(header, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
                inode++,    // e->ino
                e.second->mode,
                e.second->uid,
                e.second->gid,
                1,          // e->nlink
                0,          // e->mtime
                e.second->filesize,
                0,          // e->devmajor
                0,          // e->devminor
                0,          // e->rdevmajor
                0,          // e->rdevminor
                (uint32_t) e.first.size() + 1,
                0           // e->check
        );
        do_out(header, 110);
        do_out(e.first.data(), e.first.size() + 1);
        out_align();
        if (e.second->filesize) {
            do_out(e.second->data, e.second->filesize);
            out_align();
        }
    }
    // 写入结尾标记
    sprintf(header, "070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
            inode++, 0755, 0, 0, 1, 0, 0, 0, 0, 0, 0, 11, 0);
    do_out(header, 110);
    do_out("TRAILER!!!\0", 11);
    out_align();
    fclose(out);
}

// 从文件加载CPIO
void cpio::load_cpio(const char *file) {
    fprintf(stderr, "Loading cpio: [%s]\n", file);
    auto m = mmap_data(file);
    load_cpio(reinterpret_cast<char *>(m.buf), m.sz);
}

// 插入新条目
void cpio::insert(string_view name, cpio_entry *e) {
    auto it = entries.find(name);
    if (it != entries.end()) {
        it->second.reset(e);
    } else {
        entries.emplace(name, e);
    }
}

// 添加文件条目
void cpio::add(mode_t mode, const char *name, const char *file) {
    auto m = mmap_data(file);
    auto e = new cpio_entry(S_IFREG | mode);
    e->filesize = m.sz;
    e->data = xmalloc(m.sz);
    memcpy(e->data, m.buf, m.sz);
    insert(name, e);
    fprintf(stderr, "Add entry [%s] (%04o)\n", name, mode);
}

// 创建目录条目
void cpio::mkdir(mode_t mode, const char *name) {
    insert(name, new cpio_entry(S_IFDIR | mode));
    fprintf(stderr, "Create directory [%s] (%04o)\n", name, mode);
}

// 创建符号链接条目
void cpio::ln(const char *target, const char *name) {
    auto e = new cpio_entry(S_IFLNK);
    e->filesize = strlen(target);
    e->data = strdup(target);
    insert(name, e);
    fprintf(stderr, "Create symlink [%s] -> [%s]\n", name, target);
}

// 移动条目（迭代器版本）
void cpio::mv(entry_map::iterator it, const char *name) {
    fprintf(stderr, "Move [%s] -> [%s]\n", it->first.data(), name);
    auto e = it->second.release();
    entries.erase(it);
    insert(name, e);
}

// 移动条目（名称版本）
bool cpio::mv(const char *from, const char *to) {
    auto it = entries.find(from);
    if (it != entries.end()) {
        mv(it, to);
        return true;
    }
    fprintf(stderr, "Cannot find entry %s\n", from);
    return false;
}

#define pos_align(p) p = align_to(p, 4)

// 从缓冲区加载CPIO
void cpio::load_cpio(const char *buf, size_t sz) {
    size_t pos = 0;
    while (pos < sz) {
        auto hdr = reinterpret_cast<const cpio_newc_header *>(buf + pos);
        if (memcmp(hdr->magic, "070701", 6) != 0)
            LOGE("bad cpio header\n");
        pos += sizeof(cpio_newc_header);
        string_view name(buf + pos);
        pos += x8u(hdr->namesize);
        pos_align(pos);
        if (name == "." || name == "..")
            continue;
        if (name == "TRAILER!!!") {
            // Android支持多个CPIO连接
            // 搜索下一个cpio头部
            auto next = static_cast<const char *>(memmem(buf + pos, sz - pos, "070701", 6));
            if (next == nullptr)
                break;
            pos = next - buf;
            continue;
        }
        auto entry = new cpio_entry(hdr);
        entry->data = xmalloc(entry->filesize);
        memcpy(entry->data, buf + pos, entry->filesize);
        pos += entry->filesize;
        insert(name, entry);
        pos_align(pos);
    }
}
