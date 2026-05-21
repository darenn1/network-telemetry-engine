#pragma once

#include "pipeline/filter_stage.h"
#include "parsers/ip_parser.h"
#include "parsers/tcp_parser.h"
#include "parsers/udp_parser.h"
#include "parsers/icmp_parser.h"
#include "parsers/arp_parser.h"

#include <optional>
#include <variant>
#include <cstdint>
#include <unordered_set>

namespace pipeline {

using LocalIpSet = std::unordered_set<uint32_t>;


struct IpTcpFrame {
    parsers::EthernetFrame eth;
    parsers::IpHeader      ip;
    parsers::TcpHeader     tcp;
    uint64_t               capture_ts_ms;
};

struct IpUdpFrame {
    parsers::EthernetFrame eth;
    parsers::IpHeader      ip;
    parsers::UdpHeader     udp;
    uint64_t               capture_ts_ms;
};

struct IpIcmpFrame {
    parsers::EthernetFrame eth;
    parsers::IpHeader      ip;
    parsers::IcmpHeader    icmp;
    uint64_t               capture_ts_ms;
};

struct ArpFrame {
    parsers::EthernetFrame eth;
    parsers::ArpPacket     arp;
    uint64_t               capture_ts_ms;
};

struct IpOtherFrame {
    parsers::EthernetFrame eth;
    parsers::IpHeader      ip;
    uint64_t               capture_ts_ms;
};

using DissectedFrame = std::variant<
    IpTcpFrame,
    IpUdpFrame,
    IpIcmpFrame,
    ArpFrame,
    IpOtherFrame
>;

std::optional<DissectedFrame> dissector_stage(
    const FilteredFrame& filtered,
    const LocalIpSet&    local_ips);

} // namespace pipeline