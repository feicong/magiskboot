// 压缩/解压缩实现文件，支持多种压缩格式
#include <memory>
#include <functional>

#include <zlib.h>
#include <bzlib.h>
#include <lzma.h>
#include <lz4.h>
#include <lz4frame.h>
#include <lz4hc.h>
#include <zopfli/util.h>
#include <zopfli/deflate.h>

#include <base.hpp>

#include "magiskboot.hpp"
#include "compress.hpp"

using namespace std;

#define bwrite this->base->write
#define crc32_z crc32

// 常量定义
constexpr size_t CHUNK = 0x40000;           // 64KB块大小
constexpr size_t LZ4_UNCOMPRESSED = 0x800000;  // 8MB未压缩大小
constexpr size_t LZ4_COMPRESSED = LZ4_COMPRESSBOUND(LZ4_UNCOMPRESSED);

// 输出流类
class out_stream : public filter_stream {
    using filter_stream::filter_stream;
    using stream::read;
};

// gzip流处理类
class gz_strm : public out_stream {
public:
    bool write(const void *buf, size_t len) override {
        return len == 0 || do_write(buf, len, Z_NO_FLUSH);
    }

    // 析构函数，完成压缩/解压缩
    ~gz_strm() override {
        do_write(nullptr, 0, Z_FINISH);
        switch(mode) {
        case DECODE:
            inflateEnd(&strm);     // 结束解压缩
            break;
        case ENCODE:
            deflateEnd(&strm);     // 结束压缩
            break;
        default:
            break;
        }
    }

protected:
    // 流模式枚举
    enum mode_t {
        DECODE,  // 解码模式
        ENCODE,  // 编码模式
        WAIT,    // 等待模式
        COPY     // 复制模式
    } mode;

    // 构造函数，初始化流
    gz_strm(mode_t mode, stream_ptr &&base) :
        out_stream(std::move(base)), mode(mode), strm{}, outbuf{0} {
        switch(mode) {
        case DECODE:
            inflateInit2(&strm, 15 | 16);  // 初始化gzip解压缩
            break;
        case ENCODE:
            deflateInit2(&strm, 9, Z_DEFLATED, 15 | 16, 8, Z_DEFAULT_STRATEGY);  // 初始化gzip压缩
            break;
        default:
            break;
        }
    }

private:
    z_stream strm;           // zlib流结构
    uint8_t outbuf[CHUNK];   // 输出缓冲区

    // 执行写入操作
    bool do_write(const void *buf, size_t len, int flush) {
        if (mode == WAIT) {
            if (len == 0) return true;
            Bytef b[1] = {0x1f};
            if (*(Bytef *)buf == 0x8b) {
                mode = DECODE;
                inflateReset(&strm);
                strm.next_in = b;
                strm.avail_in = 1;
                inflate(&strm, flush);
            } else {
                mode = COPY;
                return true;
            }
        }
        strm.next_in = (Bytef *) buf;
        strm.avail_in = len;
        do {
            int code;
            strm.next_out = outbuf;
            strm.avail_out = sizeof(outbuf);
            switch(mode) {
                case DECODE:
                    code = inflate(&strm, flush);    // 执行解压缩
                    break;
                case ENCODE:
                    code = deflate(&strm, flush);    // 执行压缩
                    break;
                case COPY:
                    return true;                     // 直接复制模式
                default:
                    // 不应该到达这里
                    return false;
            }
            if (code == Z_STREAM_ERROR) {
                LOGW("gzip %s failed (%d)\n", mode ? "encode" : "decode", code);
                return false;
            }
            if (!bwrite(outbuf, sizeof(outbuf) - strm.avail_out))
                return false;
            if (mode == DECODE && code == Z_STREAM_END) {
                if (strm.avail_in > 1) {
                    if (strm.next_in[0] == 0x1f && strm.next_in[1] == 0x8b) {
                        // 流中还有数据，需要重置流并继续解码
                        inflateReset(&strm);
                        strm.avail_out = 0;
                        continue;
                    }
                } else if (strm.avail_in == 1) {
                    if (strm.next_in[0] == 0x1f) {
                        // 如果只剩一个字节，需要等待下一个字节
                        // 来确定是否为gzip头部
                        mode = WAIT;
                        return true;
                    }
                } else {
                    // 下一次inflate不会消耗任何数据，但会回退
                    // 到前面两个条件
                    return true;
                }
                // 流中还有数据，需要复制它
                mode = COPY;
                return true;
            }
        } while (strm.avail_out == 0);
        return true;
    }
};

// gzip解码器类
class gz_decoder : public gz_strm {
public:
    explicit gz_decoder(stream_ptr &&base) : gz_strm(DECODE, std::move(base)) {};
};

// gzip编码器类
class gz_encoder : public gz_strm {
public:
    explicit gz_encoder(stream_ptr &&base) : gz_strm(ENCODE, std::move(base)) {};
};

// Zopfli编码器类（高压缩比的gzip兼容压缩器）
class zopfli_encoder : public chunk_out_stream {
public:
    explicit zopfli_encoder(stream_ptr &&base) :
        chunk_out_stream(std::move(base), ZOPFLI_MASTER_BLOCK_SIZE),
        zo{}, out(nullptr), outsize(0), crc(crc32_z(0L, Z_NULL, 0)), in_total(0), bp(0) {
        ZopfliInitOptions(&zo);

        // 这个配置已经比gzip -9更好
        zo.numiterations = 1;
        zo.blocksplitting = 0;

        // 写入gzip头部
        ZOPFLI_APPEND_DATA(31, &out, &outsize);  /* ID1 */
        ZOPFLI_APPEND_DATA(139, &out, &outsize); /* ID2 */
        ZOPFLI_APPEND_DATA(8, &out, &outsize);   /* CM */
        ZOPFLI_APPEND_DATA(0, &out, &outsize);   /* FLG */
        /* MTIME */
        ZOPFLI_APPEND_DATA(0, &out, &outsize);
        ZOPFLI_APPEND_DATA(0, &out, &outsize);
        ZOPFLI_APPEND_DATA(0, &out, &outsize);
        ZOPFLI_APPEND_DATA(0, &out, &outsize);

        ZOPFLI_APPEND_DATA(2, &out, &outsize);  /* XFL, 2表示最佳压缩 */
        ZOPFLI_APPEND_DATA(3, &out, &outsize);  /* OS遵循Unix约定 */
    }

    // 析构函数，完成压缩并写入CRC和文件大小
    ~zopfli_encoder() override {
        finalize();

        /* CRC校验和 */
        ZOPFLI_APPEND_DATA(crc % 256, &out, &outsize);
        ZOPFLI_APPEND_DATA((crc >> 8) % 256, &out, &outsize);
        ZOPFLI_APPEND_DATA((crc >> 16) % 256, &out, &outsize);
        ZOPFLI_APPEND_DATA((crc >> 24) % 256, &out, &outsize);

        /* ISIZE 原始数据大小 */
        ZOPFLI_APPEND_DATA(in_total % 256, &out, &outsize);
        ZOPFLI_APPEND_DATA((in_total >> 8) % 256, &out, &outsize);
        ZOPFLI_APPEND_DATA((in_total >> 16) % 256, &out, &outsize);
        ZOPFLI_APPEND_DATA((in_total >> 24) % 256, &out, &outsize);

        bwrite(out, outsize);  // 写入最终数据
        free(out);             // 释放内存
    }

protected:
    // 写入数据块的实现
    bool write_chunk(const void *buf, size_t len, bool final) override {
        if (len == 0)
            return true;

        auto in = static_cast<const unsigned char *>(buf);

        in_total += len;                    // 累计输入大小
        crc = crc32_z(crc, in, len);       // 更新CRC校验和

        // 使用Zopfli压缩数据
        ZopfliDeflatePart(&zo, 2, final, in, 0, len, &bp, &out, &outsize);

        // ZOPFLI_APPEND_DATA非常简单，所以我们总是保留最后一个字节
        // 以确保使用realloc而不是malloc
        if (!bwrite(out, outsize - 1))
            return false;
        out[0] = out[outsize - 1];
        outsize = 1;

        return true;
    }

private:
    ZopfliOptions zo;      // Zopfli选项
    unsigned char *out;    // 输出缓冲区
    size_t outsize;        // 输出大小
    unsigned long crc;     // CRC校验和
    uint32_t in_total;     // 输入总大小
    unsigned char bp;      // 位位置
};

// bzip2流处理类
class bz_strm : public out_stream {
public:
    bool write(const void *buf, size_t len) override {
        return len == 0 || do_write(buf, len, BZ_RUN);
    }

    // 析构函数，完成压缩/解压缩
    ~bz_strm() override {
        switch(mode) {
            case DECODE:
                BZ2_bzDecompressEnd(&strm);   // 结束解压缩
                break;
            case ENCODE:
                do_write(nullptr, 0, BZ_FINISH);  // 完成压缩
                BZ2_bzCompressEnd(&strm);     // 结束压缩
                break;
        }
    }

protected:
    // bzip2模式枚举
    enum mode_t {
        DECODE,  // 解码模式
        ENCODE   // 编码模式
    } mode;

    // 构造函数，初始化bzip2流
    bz_strm(mode_t mode, stream_ptr &&base) :
        out_stream(std::move(base)), mode(mode), strm{}, outbuf{0} {
        switch(mode) {
        case DECODE:
            BZ2_bzDecompressInit(&strm, 0, 0);  // 初始化bzip2解压缩
            break;
        case ENCODE:
            BZ2_bzCompressInit(&strm, 9, 0, 0);  // 初始化bzip2压缩（级别9）
            break;
        }
    }

private:
    bz_stream strm;        // bzip2流结构
    char outbuf[CHUNK];    // 输出缓冲区

    // 执行写入操作
    bool do_write(const void *buf, size_t len, int flush) {
        strm.next_in = (char *) buf;
        strm.avail_in = len;
        do {
            int code;
            strm.avail_out = sizeof(outbuf);
            strm.next_out = outbuf;
            switch(mode) {
            case DECODE:
                code = BZ2_bzDecompress(&strm);    // 执行解压缩
                break;
            case ENCODE:
                code = BZ2_bzCompress(&strm, flush);  // 执行压缩
                break;
            }
            if (code < 0) {
                LOGW("bzip2 %s failed (%d)\n", mode ? "encode" : "decode", code);
                return false;
            }
            if (!bwrite(outbuf, sizeof(outbuf) - strm.avail_out))
                return false;
        } while (strm.avail_out == 0);
        return true;
    }
};

// bzip2解码器类
class bz_decoder : public bz_strm {
public:
    explicit bz_decoder(stream_ptr &&base) : bz_strm(DECODE, std::move(base)) {};
};

// bzip2编码器类
class bz_encoder : public bz_strm {
public:
    explicit bz_encoder(stream_ptr &&base) : bz_strm(ENCODE, std::move(base)) {};
};

// LZMA/XZ流处理类
class lzma_strm : public out_stream {
public:
    bool write(const void *buf, size_t len) override {
        return len == 0 || do_write(buf, len, LZMA_RUN);
    }

    // 析构函数，完成压缩/解压缩
    ~lzma_strm() override {
        do_write(nullptr, 0, LZMA_FINISH);  // 完成操作
        lzma_end(&strm);                    // 结束LZMA流
    }

protected:
    // LZMA模式枚举
    enum mode_t {
        DECODE,      // 解码模式
        ENCODE_XZ,   // XZ编码模式
        ENCODE_LZMA  // LZMA编码模式
    } mode;

    // 构造函数，初始化LZMA流
    lzma_strm(mode_t mode, stream_ptr &&base) :
        out_stream(std::move(base)), mode(mode), strm(LZMA_STREAM_INIT), outbuf{0} {
        lzma_options_lzma opt;

        // 初始化预设
        lzma_lzma_preset(&opt, 9);  // 使用最高压缩级别
        lzma_filter filters[] = {
            { .id = LZMA_FILTER_LZMA2, .options = &opt },
            { .id = LZMA_VLI_UNKNOWN, .options = nullptr },
        };

        lzma_ret code;
        switch(mode) {
        case DECODE:
            code = lzma_auto_decoder(&strm, UINT64_MAX, 0);  // 自动检测格式并解码
            break;
        case ENCODE_XZ:
            code = lzma_stream_encoder(&strm, filters, LZMA_CHECK_CRC32);  // XZ格式编码
            break;
        case ENCODE_LZMA:
            code = lzma_alone_encoder(&strm, &opt);  // LZMA格式编码
            break;
        }
        if (code != LZMA_OK) {
            LOGE("LZMA initialization failed (%d)\n", code);
        }
    }

private:
    lzma_stream strm;       // LZMA流结构
    uint8_t outbuf[CHUNK];  // 输出缓冲区

    // 执行写入操作
    bool do_write(const void *buf, size_t len, lzma_action flush) {
        strm.next_in = (uint8_t *) buf;
        strm.avail_in = len;
        do {
            strm.avail_out = sizeof(outbuf);
            strm.next_out = outbuf;
            int code = lzma_code(&strm, flush);  // 执行LZMA操作
            if (code != LZMA_OK && code != LZMA_STREAM_END) {
                LOGW("LZMA %s failed (%d)\n", mode ? "encode" : "decode", code);
                return false;
            }
            if (!bwrite(outbuf, sizeof(outbuf) - strm.avail_out))
                return false;
        } while (strm.avail_out == 0);
        return true;
    }
};

// LZMA解码器类
class lzma_decoder : public lzma_strm {
public:
    explicit lzma_decoder(stream_ptr &&base) : lzma_strm(DECODE, std::move(base)) {}
};

// XZ编码器类
class xz_encoder : public lzma_strm {
public:
    explicit xz_encoder(stream_ptr &&base) : lzma_strm(ENCODE_XZ, std::move(base)) {}
};

// LZMA编码器类
class lzma_encoder : public lzma_strm {
public:
    explicit lzma_encoder(stream_ptr &&base) : lzma_strm(ENCODE_LZMA, std::move(base)) {}
};

// LZ4F解码器类
class LZ4F_decoder : public out_stream {
public:
    explicit LZ4F_decoder(stream_ptr &&base) :
        out_stream(std::move(base)), ctx(nullptr), outbuf(nullptr), outCapacity(0) {
        LZ4F_createDecompressionContext(&ctx, LZ4F_VERSION);  // 创建LZ4F解压缩上下文
    }

    // 析构函数，清理资源
    ~LZ4F_decoder() override {
        LZ4F_freeDecompressionContext(ctx);  // 释放解压缩上下文
        delete[] outbuf;                     // 释放输出缓冲区
    }

    bool write(const void *buf, size_t len) override {
        auto in = reinterpret_cast<const uint8_t *>(buf);
        if (!outbuf) {
            // 首次调用，需要获取帧信息并分配缓冲区
            size_t read = len;
            LZ4F_frameInfo_t info;
            LZ4F_getFrameInfo(ctx, &info, in, &read);
            switch (info.blockSizeID) {
            case LZ4F_default:
            case LZ4F_max64KB:  outCapacity = 1 << 16; break;   // 64KB
            case LZ4F_max256KB: outCapacity = 1 << 18; break;   // 256KB
            case LZ4F_max1MB:   outCapacity = 1 << 20; break;   // 1MB
            case LZ4F_max4MB:   outCapacity = 1 << 22; break;   // 4MB
            }
            outbuf = new uint8_t[outCapacity];  // 分配输出缓冲区
            in += read;
            len -= read;
        }
        size_t read, write;
        LZ4F_errorCode_t code;
        do {
            read = len;
            write = outCapacity;
            // 执行LZ4F解压缩
            code = LZ4F_decompress(ctx, outbuf, &write, in, &read, nullptr);
            if (LZ4F_isError(code)) {
                LOGW("LZ4F decode error: %s\n", LZ4F_getErrorName(code));
                return false;
            }
            len -= read;
            in += read;
            if (!bwrite(outbuf, write))
                return false;
        } while (len != 0 || write != 0);
        return true;
    }

private:
    LZ4F_decompressionContext_t ctx;  // LZ4F解压缩上下文
    uint8_t *outbuf;                  // 输出缓冲区
    size_t outCapacity;               // 输出缓冲区容量
};

// LZ4F编码器类
class LZ4F_encoder : public out_stream {
public:
    explicit LZ4F_encoder(stream_ptr &&base) :
        out_stream(std::move(base)), ctx(nullptr), out_buf(nullptr), outCapacity(0) {
        LZ4F_createCompressionContext(&ctx, LZ4F_VERSION);  // 创建LZ4F压缩上下文
    }

    bool write(const void *buf, size_t len) override {
        if (!out_buf) {
            // 首次调用，初始化压缩参数并分配缓冲区
            LZ4F_preferences_t prefs {
                .frameInfo = {
                    .blockSizeID = LZ4F_max4MB,                    // 最大4MB块
                    .blockMode = LZ4F_blockIndependent,            // 独立块模式
                    .contentChecksumFlag = LZ4F_contentChecksumEnabled,  // 启用内容校验和
                    .blockChecksumFlag = LZ4F_noBlockChecksum,     // 不使用块校验和
                },
                .compressionLevel = 9,  // 最高压缩级别
                .autoFlush = 1,         // 自动刷新
            };
            outCapacity = LZ4F_compressBound(BLOCK_SZ, &prefs);  // 计算输出缓冲区大小
            out_buf = new uint8_t[outCapacity];                  // 分配输出缓冲区
            size_t write = LZ4F_compressBegin(ctx, out_buf, outCapacity, &prefs);  // 开始压缩
            if (!bwrite(out_buf, write))
                return false;
        }
        if (len == 0)
            return true;

        auto in = reinterpret_cast<const uint8_t *>(buf);
        size_t read, write;
        do {
            read = len > BLOCK_SZ ? BLOCK_SZ : len;  // 确定读取大小
            // 压缩数据块
            write = LZ4F_compressUpdate(ctx, out_buf, outCapacity, in, read, nullptr);
            if (LZ4F_isError(write)) {
                LOGW("LZ4F encode error: %s\n", LZ4F_getErrorName(write));
                return false;
            }
            len -= read;
            in += read;
            if (!bwrite(out_buf, write))
                return false;
        } while (len != 0);
        return true;
    }

    // 析构函数，完成压缩并清理资源
    ~LZ4F_encoder() override {
        size_t len = LZ4F_compressEnd(ctx, out_buf, outCapacity, nullptr);  // 结束压缩
        if (LZ4F_isError(len)) {
            LOGE("LZ4F end of frame error: %s\n", LZ4F_getErrorName(len));
        } else if (!bwrite(out_buf, len)) {
            LOGE("LZ4F end of frame error: I/O error\n");
        }
        LZ4F_freeCompressionContext(ctx);  // 释放压缩上下文
        delete[] out_buf;                  // 释放输出缓冲区
    }

private:
    LZ4F_compressionContext_t ctx;  // LZ4F压缩上下文
    uint8_t *out_buf;               // 输出缓冲区
    size_t outCapacity;             // 输出缓冲区容量

    static constexpr size_t BLOCK_SZ = 1 << 22;  // 4MB块大小
};

// LZ4遗留格式解码器类
class LZ4_decoder : public chunk_out_stream {
public:
    explicit LZ4_decoder(stream_ptr &&base) :
        chunk_out_stream(std::move(base), LZ4_COMPRESSED, sizeof(block_sz)),
        out_buf(new char[LZ4_UNCOMPRESSED]), block_sz(0) {}

    // 析构函数，完成解码并清理资源
    ~LZ4_decoder() override {
        finalize();
        delete[] out_buf;
    }

protected:
    // 写入数据块的实现
    bool write_chunk(const void *buf, size_t len, bool final) override {
        // 长度不匹配是错误
        if (len != chunk_sz)
            return false;

        auto in = reinterpret_cast<const char *>(buf);

        if (block_sz == 0) {
            // 读取块大小
            memcpy(&block_sz, in, sizeof(block_sz));
            if (block_sz == 0x184C2102) {
                // 这实际上是lz4 magic，读取下4个字节
                block_sz = 0;
                chunk_sz = sizeof(block_sz);
                return true;
            }
            // 读取下一个数据块
            chunk_sz = block_sz;
            return true;
        } else {
            // 执行LZ4解压缩
            int r = LZ4_decompress_safe(in, out_buf, block_sz, LZ4_UNCOMPRESSED);
            chunk_sz = sizeof(block_sz);
            block_sz = 0;
            if (r < 0) {
                LOGW("LZ4HC decompression failure (%d)\n", r);
                return false;
            }
            return bwrite(out_buf, r);
        }
    }

private:
    char *out_buf;      // 输出缓冲区
    uint32_t block_sz;  // 块大小
};

// LZ4编码器类
class LZ4_encoder : public chunk_out_stream {
public:
    explicit LZ4_encoder(stream_ptr &&base, bool lg) :
        chunk_out_stream(std::move(base), LZ4_UNCOMPRESSED),
        out_buf(new char[LZ4_COMPRESSED]), lg(lg), in_total(0) {
        bwrite("\x02\x21\x4c\x18", 4);  // 写入LZ4魔数
    }

    // 析构函数，完成编码并清理资源
    ~LZ4_encoder() override {
        finalize();
        if (lg)
            bwrite(&in_total, sizeof(in_total));  // LG格式需要写入总大小
        delete[] out_buf;
    }

protected:
    // 写入数据块的实现
    bool write_chunk(const void *buf, size_t len, bool final) override {
        auto in = static_cast<const char *>(buf);
        // 使用LZ4HC高压缩比压缩数据
        uint32_t block_sz = LZ4_compress_HC(in, out_buf, len, LZ4_COMPRESSED, LZ4HC_CLEVEL_MAX);
        if (block_sz == 0) {
            LOGW("LZ4HC compression failure\n");
            return false;
        }
        if (bwrite(&block_sz, sizeof(block_sz)) && bwrite(out_buf, block_sz)) {
            in_total += len;
            return true;
        }
        return false;
    }

private:
    char *out_buf;      // 输出缓冲区
    bool lg;            // 是否为LG格式
    uint32_t in_total;  // 输入总大小
};

// 获取编码器的工厂函数
filter_strm_ptr get_encoder(format_t type, stream_ptr &&base) {
    switch (type) {
        case XZ:
            return make_unique<xz_encoder>(std::move(base));
        case LZMA:
            return make_unique<lzma_encoder>(std::move(base));
        case BZIP2:
            return make_unique<bz_encoder>(std::move(base));
        case LZ4:
            return make_unique<LZ4F_encoder>(std::move(base));
        case LZ4_LEGACY:
            return make_unique<LZ4_encoder>(std::move(base), false);
        case LZ4_LG:
            return make_unique<LZ4_encoder>(std::move(base), true);
        case ZOPFLI:
            return make_unique<zopfli_encoder>(std::move(base));
        case GZIP:
        default:
            return make_unique<gz_encoder>(std::move(base));
    }
}

// 获取解码器的工厂函数
filter_strm_ptr get_decoder(format_t type, stream_ptr &&base) {
    switch (type) {
        case XZ:
        case LZMA:
            return make_unique<lzma_decoder>(std::move(base));
        case BZIP2:
            return make_unique<bz_decoder>(std::move(base));
        case LZ4:
            return make_unique<LZ4F_decoder>(std::move(base));
        case LZ4_LEGACY:
        case LZ4_LG:
            return make_unique<LZ4_decoder>(std::move(base));
        case ZOPFLI:
        case GZIP:
        default:
            return make_unique<gz_decoder>(std::move(base));
    }
}

// 解压缩函数
void decompress(char *infile, const char *outfile) {
    bool in_std = infile == "-"sv;  // 是否从标准输入读取
    bool rm_in = false;             // 是否删除输入文件

    FILE *in_fp = in_std ? stdin : xfopen(infile, "re");
    stream_ptr strm;

    char buf[4096];
    size_t len;
    while ((len = fread(buf, 1, sizeof(buf), in_fp))) {
        if (!strm) {
            // 检测压缩格式
            format_t type = check_fmt(buf, len);

            fprintf(stderr, "Detected format: [%s]\n", fmt2name[type]);

            if (!COMPRESSED(type))
                LOGE("Input file is not a supported compressed type!\n");

            /* 如果用户未提供输出文件，输入文件必须是
            * <path>.[ext]或'-'格式。输出文件将是<path>或'-'。
            * 如果输入格式不正确，则中止 */

            char *ext = nullptr;
            if (outfile == nullptr) {
                outfile = infile;
                if (!in_std) {
                    ext = strrchr(infile, '.');
                    if (ext == nullptr || strcmp(ext, fmt2ext[type]) != 0)
                        LOGE("Input file is not a supported type!\n");

                    // 去掉扩展名并删除输入文件
                    *ext = '\0';
                    rm_in = true;
                    fprintf(stderr, "Decompressing to [%s]\n", outfile);
                }
            }

            FILE *out_fp = outfile == "-"sv ? stdout : xfopen(outfile, "we");
            strm = get_decoder(type, make_unique<fp_stream>(out_fp));
            if (ext) *ext = '.';
        }
        if (!strm->write(buf, len))
            LOGE("Decompression error!\n");
    }

    strm.reset(nullptr);  // 重置流指针
    fclose(in_fp);

    if (rm_in)
        unlink(infile);   // 删除输入文件
}

// 压缩函数
void compress(const char *method, const char *infile, const char *outfile) {
    format_t fmt = name2fmt[method];  // 根据方法名获取格式
    if (fmt == UNKNOWN)
        LOGE("Unknown compression method: [%s]\n", method);

    bool in_std = infile == "-"sv;  // 是否从标准输入读取
    bool rm_in = false;             // 是否删除输入文件

    FILE *in_fp = in_std ? stdin : xfopen(infile, "re");
    FILE *out_fp;

    if (outfile == nullptr) {
        if (in_std) {
            out_fp = stdout;  // 输出到标准输出
        } else {
            /* 如果用户未提供输出文件且输入文件不是标准输入，
             * 输出到<infile>.[ext] */
            string tmp(infile);
            tmp += fmt2ext[fmt];
            out_fp = xfopen(tmp.data(), "we");
            fprintf(stderr, "Compressing to [%s]\n", tmp.data());
            rm_in = true;
        }
    } else {
        out_fp = outfile == "-"sv ? stdout : xfopen(outfile, "we");
    }

    auto strm = get_encoder(fmt, make_unique<fp_stream>(out_fp));

    char buf[4096];
    size_t len;
    while ((len = fread(buf, 1, sizeof(buf), in_fp))) {
        if (!strm->write(buf, len))
            LOGE("Compression error!\n");
    }

    strm.reset(nullptr);  // 重置流指针
    fclose(in_fp);

    if (rm_in)
        unlink(infile);   // 删除输入文件
}
