#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <array>
#include "parsers/types.h"

namespace parsers {

namespace ArpOper {
    static constexpr uint16_t REQUEST = 1;
    static constexpr uint16_t REPLY = 2;
}

static constexpr uint16_t ARP_HTYPE_ETHERNET = 1;
static constexpr uint16_t ARP_PTYPE_IPV4 = 0x0800;

struct ArpPacket {
    uint16_t oper;
    MACAddress sender_mac;
    uint32_t sender_ip;
    MACAddress target_mac;
    uint32_t target_ip;
    bool is_reply;
};

std::optional<ArpPacket> parseArpPacket(
    const uint8_t* data,
    std::size_t len);

} // namespace parsers