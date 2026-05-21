#include "parsers/arp_parser.h"

namespace parsers {

static inline uint16_t readU16Be(const uint8_t* p) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

static inline uint32_t readU32Be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24)
         | (static_cast<uint32_t>(p[1]) << 16)
         | (static_cast<uint32_t>(p[2]) << 8)
         | static_cast<uint32_t>(p[3]);
}

std::optional<ArpPacket> parseArpPacket(
    const uint8_t* data,
    std::size_t len)
{
    if (!data || len < 28) {
        return std::nullopt;
    }

    const uint16_t htype = readU16Be(data + 0);
    if (htype != ARP_HTYPE_ETHERNET) {
        return std::nullopt;
    }

    const uint16_t ptype = readU16Be(data + 2);
    if (ptype != ARP_PTYPE_IPV4) {
        return std::nullopt;
    }

    if (data[4] != 6 || data[5] != 4) {
        return std::nullopt;
    }

    const uint16_t oper = readU16Be(data + 6);

    MACAddress sender_mac{};
    for (int i = 0; i < 6; ++i) sender_mac[i] = data[8 + i];

    const uint32_t sender_ip = readU32Be(data + 14);

    MACAddress target_mac{};
    for (int i = 0; i < 6; ++i) target_mac[i] = data[18 + i];

    const uint32_t target_ip = readU32Be(data + 24);

    return ArpPacket{
        .oper = oper,
        .sender_mac = sender_mac,
        .sender_ip = sender_ip,
        .target_mac = target_mac,
        .target_ip = target_ip,
        .is_reply = (oper == ArpOper::REPLY),
    };
}

} // namespace parsers