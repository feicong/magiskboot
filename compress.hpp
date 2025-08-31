// 压缩/解压缩头文件，定义压缩相关的接口
#pragma once

#include <stream.hpp>

#include "format.hpp"

// 获取编码器流
filter_strm_ptr get_encoder(format_t type, stream_ptr &&base);

// 获取解码器流
filter_strm_ptr get_decoder(format_t type, stream_ptr &&base);

// 压缩函数
void compress(const char *method, const char *infile, const char *outfile);

// 解压缩函数
void decompress(char *infile, const char *outfile);
