#include "pipeline/dissector_stage.h"
#include "utils/logger.h"

namespace pipeline {


static parsers::Direction resolveDirection(
    uint32_t          src_ip,
    uint32_t          dst_ip,
    const LocalIpSet& local_ips)
{
    if (local_ips.count(dst_ip)) return parsers::Direction::Inbound;
    if (local_ips.count(src_ip)) return parsers::Direction::Outbound;
    return parsers::Direction::Unknown;
}


std::optional<DissectedFrame> dissector_stage(
    const FilteredFrame& filtered,
    const LocalIpSet&    local_ips)
{
    const auto& eth = filtered.eth;

    if (eth.ethertype == parsers::ETHERTYPE_ARP) {
        auto arp = parsers::parseArpPacket(eth.payload, eth.payload_size);
        if (!arp.has_value()) {
            utils::log_warn("dissector_stage: ARP parse failed — dropped");
            return std::nullopt;
        }
        return ArpFrame{
            .eth           = eth,
            .arp           = *arp,
            .capture_ts_ms = filtered.capture_ts_ms,
        };
    }

    if (eth.payload_size < 20) {
        utils::log_warn("dissector_stage: IPv4 payload too short — dropped");
        return std::nullopt;
    }

    const uint32_t peek_src = (static_cast<uint32_t>(eth.payload[12]) << 24)
                            | (static_cast<uint32_t>(eth.payload[13]) << 16)
                            | (static_cast<uint32_t>(eth.payload[14]) <<  8)
                            |  static_cast<uint32_t>(eth.payload[15]);
    const uint32_t peek_dst = (static_cast<uint32_t>(eth.payload[16]) << 24)
                            | (static_cast<uint32_t>(eth.payload[17]) << 16)
                            | (static_cast<uint32_t>(eth.payload[18]) <<  8)
                            |  static_cast<uint32_t>(eth.payload[19]);

    const parsers::Direction dir = resolveDirection(peek_src, peek_dst, local_ips);

    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size, dir);
    if (!ip.has_value()) {
        utils::log_warn("dissector_stage: IP parse failed — dropped");
        return std::nullopt;
    }

    switch (ip->protocol) {

    case 6: { // TCP
        auto tcp = parsers::parseTcpHeader(ip->payload, ip->payload_len);
        if (!tcp.has_value()) {
            utils::log_warn("dissector_stage: TCP parse failed — dropped");
            return std::nullopt;
        }
        return IpTcpFrame{
            .eth           = eth,
            .ip            = *ip,
            .tcp           = *tcp,
            .capture_ts_ms = filtered.capture_ts_ms,
        };
    }

    case 17: { // UDP
        auto udp = parsers::parseUdpHeader(ip->payload, ip->payload_len);
        if (!udp.has_value()) {
            utils::log_warn("dissector_stage: UDP parse failed — dropped");
            return std::nullopt;
        }
        return IpUdpFrame{
            .eth           = eth,
            .ip            = *ip,
            .udp           = *udp,
            .capture_ts_ms = filtered.capture_ts_ms,
        };
    }

    case 1: { // ICMP
        auto icmp = parsers::parseIcmpHeader(
            ip->payload, ip->payload_len, ip->total_length);
        if (!icmp.has_value()) {
            utils::log_warn("dissector_stage: ICMP parse failed — dropped");
            return std::nullopt;
        }
        return IpIcmpFrame{
            .eth           = eth,
            .ip            = *ip,
            .icmp          = *icmp,
            .capture_ts_ms = filtered.capture_ts_ms,
        };
    }

    default:
        return IpOtherFrame{
            .eth           = eth,
            .ip            = *ip,
            .capture_ts_ms = filtered.capture_ts_ms,
        };
    }
}

} // namespace pipeline