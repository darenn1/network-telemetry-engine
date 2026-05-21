#include "parsers/icmp_parser.h"

namespace parsers {

std::optional<IcmpHeader> parseIcmpHeader(
    const uint8_t* data,
    std::size_t    len,
    uint16_t       ip_total_length)
{
    if (!data || len < 8) {
        return std::nullopt;
    }

    const uint8_t type = data[0];
    const uint8_t code = data[1];

    const uint16_t packet_size  = ip_total_length;
    const bool     is_oversized = (packet_size > ICMP_NORMAL_MTU);

    return IcmpHeader{
        .type         = type,
        .code         = code,
        .packet_size  = packet_size,
        .is_oversized = is_oversized,
        .payload      = data + 8,
        .payload_len  = len - 8,
    };
}

} 