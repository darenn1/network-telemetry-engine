#include "parsers/tcp_parser.h"

namespace parsers {


static inline uint16_t readU16Be(const uint8_t* p) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

static inline uint32_t readU32Be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24)
         | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) <<  8)
         |  static_cast<uint32_t>(p[3]);
}


std::optional<TcpHeader> parseTcpHeader(
    const uint8_t* data,
    std::size_t    len)
{
    if (!data || len < 20) {
        return std::nullopt;
    }

    const uint16_t src_port = readU16Be(data + 0);
    const uint16_t dst_port = readU16Be(data + 2);

    const uint32_t seq_num = readU32Be(data + 4);

    const uint8_t data_offset = (data[12] >> 4) & 0x0F;
    const std::size_t header_bytes = data_offset * 4u;

    if (data_offset < 5 || header_bytes > len) {
        return std::nullopt;
    }

    const uint8_t flags = data[13] & 0x3F;

    const uint16_t window_size = readU16Be(data + 14);

    const uint8_t*  payload     = data + header_bytes;
    const std::size_t payload_len = len - header_bytes;

    return TcpHeader{
        .src_port    = src_port,
        .dst_port    = dst_port,
        .seq_num     = seq_num,
        .data_offset = data_offset,
        .flags       = flags,
        .window_size = window_size,
        .payload     = payload,
        .payload_len = payload_len,
    };
}

} 