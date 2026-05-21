#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

namespace parsers {

namespace IcmpType {
    static constexpr uint8_t ECHO_REPLY = 0;
    static constexpr uint8_t DEST_UNREACHABLE = 3;
    static constexpr uint8_t ECHO_REQUEST = 8;
    static constexpr uint8_t TTL_EXCEEDED = 11;
}

static constexpr uint16_t ICMP_NORMAL_MTU = 1500;

struct IcmpHeader {
    uint8_t type;
    uint8_t code;
    uint16_t packet_size;
    bool is_oversized;
    const uint8_t* payload;
    std::size_t payload_len;
};

std::optional<IcmpHeader> parseIcmpHeader(
    const uint8_t* data,
    std::size_t len,
    uint16_t ip_total_length);

} // namespace parsers