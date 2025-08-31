// CPIO归档文件处理头文件
#pragma once

#include <stdint.h>
#include <string>
#include <memory>
#include <map>
#include <string_view>

struct cpio_newc_header;

// CPIO条目结构
struct cpio_entry {
    uint32_t mode;      // 文件模式
    uint32_t uid;       // 用户ID
    uint32_t gid;       // 组ID
    uint32_t filesize;  // 文件大小
    void *data;         // 文件数据

    explicit cpio_entry(uint32_t mode = 0);
    explicit cpio_entry(uint32_t mode, uint32_t uid, uint32_t gid);
    explicit cpio_entry(const cpio_newc_header *h);
    ~cpio_entry() { free(data); }
};

// CPIO归档处理类
class cpio {
public:
    // 字符串比较器，支持透明比较
    struct StringCmp {
        using is_transparent = void;
        bool operator()(std::string_view a, std::string_view b) const {
            return a < b;
        }
    };
    using entry_map = std::map<std::string, std::unique_ptr<cpio_entry>, StringCmp>;

    void load_cpio(const char *file);                                   // 从文件加载CPIO
    void load_cpio(const char* dir, const char* config, bool sync);     // 从目录和配置加载CPIO
    void dump(const char *file);                                        // 导出到文件
    void rm(const char *name, bool r = false);                         // 删除条目
    void extract();                                                     // 提取所有文件
    bool extract(const char *name, const char *file);                  // 提取特定文件
    bool exists(const char *name);                                     // 检查文件是否存在
    void add(mode_t mode, const char *name, const char *file);         // 添加文件
    void mkdir(mode_t mode, const char *name);                         // 创建目录
    void ln(const char *target, const char *name);                     // 创建链接
    bool mv(const char *from, const char *to);                         // 移动/重命名文件

protected:
    entry_map entries;  // 条目映射

    static void extract_entry(const entry_map::value_type &e, const char *file);  // 提取单个条目
    void rm(entry_map::iterator it);                                              // 删除迭代器指向的条目
    void mv(entry_map::iterator it, const char *name);                           // 移动迭代器指向的条目

private:
    void dump(FILE *out);                                                        // 导出到文件流
    void insert(std::string_view name, cpio_entry *e);                          // 插入条目
    void load_cpio(const char *buf, size_t sz);                                 // 从缓冲区加载CPIO
};
