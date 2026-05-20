#include "parsers/udp_parser.h"

namespace parsers {


static inline uint16_t readU16Be(const uint8_t* p) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(p[0]) << 8) | p[1]);
}


std::optional<UdpHeader> parseUdpHeader(
    const uint8_t* data,
    std::size_t    len)
{
    if (!data || len < 8) {
        return std::nullopt;
    }

    const uint16_t src_port = readU16Be(data + 0);
    const uint16_t dst_port = readU16Be(data + 2);

    const uint16_t length = readU16Be(data + 4);

    if (length < 8 || static_cast<std::size_t>(length) > len) {
        return std::nullopt;
    }

    const bool is_dns = (src_port == UDP_PORT_DNS || dst_port == UDP_PORT_DNS);

    const uint8_t*  payload     = data + 8;
    const std::size_t payload_len =
        static_cast<std::size_t>(length) - 8u;

    return UdpHeader{
        .src_port    = src_port,
        .dst_port    = dst_port,
        .length      = length,
        .is_dns      = is_dns,
        .payload     = payload,
        .payload_len = payload_len,
    };
}

} 