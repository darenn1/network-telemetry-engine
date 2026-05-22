#include "pipeline/stats_stage.h"

#include <arpa/inet.h>   // inet_ntop
#include <cstdio>        // snprintf

namespace pipeline {

// ---------------------------------------------------------------------------
// Flow key helpers
// ---------------------------------------------------------------------------

static std::string ipToString(uint32_t ip_host) {
    // ip is in host byte order — convert to network byte order for inet_ntop
    uint32_t ip_net = htonl(ip_host);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_net, buf, sizeof(buf));
    return std::string(buf);
}

static std::string makeFlowKey(
    uint32_t src_ip, uint16_t src_port,
    uint32_t dst_ip, uint16_t dst_port)
{
    return ipToString(src_ip) + ":" + std::to_string(src_port)
         + "->"
         + ipToString(dst_ip) + ":" + std::to_string(dst_port);
}

static std::string makeArpFlowKey(uint32_t sender_ip) {
    return "ARP:" + ipToString(sender_ip);
}

// ---------------------------------------------------------------------------
// stats_stage — one visitor per DissectedFrame variant
// ---------------------------------------------------------------------------

std::optional<EnrichedFrame> stats_stage(const DissectedFrame& dissected) {

    return std::visit([](const auto& frame) -> std::optional<EnrichedFrame> {
        using T = std::decay_t<decltype(frame)>;
        EnrichedFrame e;

        // ── IpTcpFrame ────────────────────────────────────────────────────
        if constexpr (std::is_same_v<T, IpTcpFrame>) {
            e.timestamp       = frame.capture_ts_ms;
            e.src_ip          = frame.ip.src_ip;
            e.dst_ip          = frame.ip.dst_ip;
            e.protocol        = frame.ip.protocol;        // 6
            e.packet_size     = frame.ip.total_length;
            e.direction       = frame.ip.direction;
            e.ttl             = frame.ip.ttl;
            e.src_mac         = frame.eth.src_mac;
            e.dst_mac         = frame.eth.dst_mac;
            e.checksum_valid  = frame.ip.checksum_ok;
            e.src_port        = frame.tcp.src_port;
            e.dst_port        = frame.tcp.dst_port;
            e.flags           = frame.tcp.flags;
            e.seq_num         = frame.tcp.seq_num;
            e.flow_key        = makeFlowKey(
                frame.ip.src_ip,  frame.tcp.src_port,
                frame.ip.dst_ip,  frame.tcp.dst_port);
            return e;
        }

        // ── IpUdpFrame ────────────────────────────────────────────────────
        else if constexpr (std::is_same_v<T, IpUdpFrame>) {
            e.timestamp       = frame.capture_ts_ms;
            e.src_ip          = frame.ip.src_ip;
            e.dst_ip          = frame.ip.dst_ip;
            e.protocol        = frame.ip.protocol;        // 17
            e.packet_size     = frame.ip.total_length;
            e.direction       = frame.ip.direction;
            e.ttl             = frame.ip.ttl;
            e.src_mac         = frame.eth.src_mac;
            e.dst_mac         = frame.eth.dst_mac;
            e.checksum_valid  = frame.ip.checksum_ok;
            e.src_port        = frame.udp.src_port;
            e.dst_port        = frame.udp.dst_port;
            e.flow_key        = makeFlowKey(
                frame.ip.src_ip,  frame.udp.src_port,
                frame.ip.dst_ip,  frame.udp.dst_port);
            return e;
        }

        // ── IpIcmpFrame ───────────────────────────────────────────────────
        else if constexpr (std::is_same_v<T, IpIcmpFrame>) {
            e.timestamp       = frame.capture_ts_ms;
            e.src_ip          = frame.ip.src_ip;
            e.dst_ip          = frame.ip.dst_ip;
            e.protocol        = frame.ip.protocol;        // 1
            e.packet_size     = frame.icmp.packet_size;   // ip.total_length
            e.direction       = frame.ip.direction;
            e.ttl             = frame.ip.ttl;
            e.src_mac         = frame.eth.src_mac;
            e.dst_mac         = frame.eth.dst_mac;
            e.checksum_valid  = frame.ip.checksum_ok;
            e.icmp_type       = frame.icmp.type;
            e.icmp_code       = frame.icmp.code;
            // src_port, dst_port, flags, seq_num stay 0
            e.flow_key        = makeFlowKey(
                frame.ip.src_ip, 0,
                frame.ip.dst_ip, 0);
            return e;
        }

        // ── ArpFrame ──────────────────────────────────────────────────────
        else if constexpr (std::is_same_v<T, ArpFrame>) {
            e.timestamp        = frame.capture_ts_ms;
            e.src_ip           = frame.arp.sender_ip;
            e.dst_ip           = frame.arp.target_ip;
            e.src_mac          = frame.eth.src_mac;
            e.dst_mac          = frame.eth.dst_mac;
            // protocol=0, packet_size=0, direction=Unknown for ARP
            e.arp_sender_ip    = frame.arp.sender_ip;
            e.arp_sender_mac   = frame.arp.sender_mac;
            e.arp_target_ip    = frame.arp.target_ip;
            e.arp_opcode       = frame.arp.oper;        // 1=request, 2=reply
            e.flow_key         = makeArpFlowKey(frame.arp.sender_ip);
            return e;
        }

        // ── IpOtherFrame ──────────────────────────────────────────────────
        else if constexpr (std::is_same_v<T, IpOtherFrame>) {
            e.timestamp       = frame.capture_ts_ms;
            e.src_ip          = frame.ip.src_ip;
            e.dst_ip          = frame.ip.dst_ip;
            e.protocol        = frame.ip.protocol;
            e.packet_size     = frame.ip.total_length;
            e.direction       = frame.ip.direction;
            e.ttl             = frame.ip.ttl;
            e.src_mac         = frame.eth.src_mac;
            e.dst_mac         = frame.eth.dst_mac;
            e.checksum_valid  = frame.ip.checksum_ok;
            // No transport fields available
            e.flow_key        = makeFlowKey(
                frame.ip.src_ip, 0,
                frame.ip.dst_ip, 0);
            return e;
        }

        return std::nullopt;

    }, dissected);
}

} // namespace pipeline