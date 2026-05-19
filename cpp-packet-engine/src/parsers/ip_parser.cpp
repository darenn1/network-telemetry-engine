#include "parsers/ip_parser.h"
#include "utils/checksum.h"

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


std::optional<IpHeader> parseIpHeader(
    const uint8_t* data,
    std::size_t    len,
    Direction      direction)
{
    if (len < 20) {
        return std::nullopt;
    }

    const uint8_t version = (data[0] >> 4) & 0x0F;
    if (version != 4) {
        return std::nullopt;
    }

    const uint8_t ihl = data[0] & 0x0F;  
    const std::size_t header_bytes = ihl * 4u;

    if (ihl < 5 || header_bytes > len) {
        return std::nullopt;
    }

    const uint16_t total_length = readU16Be(data + 2);

    if (static_cast<std::size_t>(total_length) > len) {
        return std::nullopt;
    }

    const uint8_t ttl = data[8];

    const uint8_t protocol = data[9];

    const uint32_t src_ip = readU32Be(data + 12);
    const uint32_t dst_ip = readU32Be(data + 16);

    const bool checksum_ok = utils::verifyIpChecksum(data, header_bytes);

    const uint8_t*  payload     = data + header_bytes;
    const std::size_t payload_len =
        static_cast<std::size_t>(total_length) - header_bytes;

    return IpHeader{
        .ihl          = ihl,
        .ttl          = ttl,
        .protocol     = protocol,
        .src_ip       = src_ip,
        .dst_ip       = dst_ip,
        .total_length = total_length,
        .checksum_ok  = checksum_ok,
        .direction    = direction,
        .payload      = payload,
        .payload_len  = payload_len,
    };
}

} 