#include <gtest/gtest.h>

// Full pipeline chain
#include "parsers/ethernet_parser.h"
#include "parsers/ip_parser.h"
#include "parsers/tcp_parser.h"
#include "parsers/udp_parser.h"
#include "parsers/icmp_parser.h"
#include "parsers/arp_parser.h"
#include "pipeline/dissector_stage.h"
#include "pipeline/stats_stage.h"
#include "pipeline/flow_tracker.h"

// ─────────────────────────────────────────────────────────────────────────────
// Raw Ethernet frame fixtures (reused from test_parsers_integration.cpp)
// ─────────────────────────────────────────────────────────────────────────────

// TCP SYN: 192.168.1.10:12345 → 10.0.0.5:80, SYN, seq=1, TTL=64
static constexpr uint8_t kTcpSynFrame[54] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x01, 0x00, 0x00,
    0x40, 0x06, 0xAF, 0x18,
    0xC0, 0xA8, 0x01, 0x0A,
    0x0A, 0x00, 0x00, 0x05,
    0x30, 0x39, 0x00, 0x50,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x02,
    0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00,
};

// TCP SYN+ACK: 10.0.0.5:80 → 192.168.1.10:12345, seq=100
static constexpr uint8_t kTcpSynAckFrame[54] = {
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x02, 0x00, 0x00,
    0x40, 0x06, 0xAE, 0x15,
    0x0A, 0x00, 0x00, 0x05,
    0xC0, 0xA8, 0x01, 0x0A,
    0x00, 0x50, 0x30, 0x39,
    0x00, 0x00, 0x00, 0x64,
    0x00, 0x00, 0x00, 0x02,
    0x50, 0x12,              // flags = SYN|ACK
    0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00,
};

// UDP DNS query: 10.0.0.5:54321 → 8.8.8.8:53
static constexpr uint8_t kUdpDnsFrame[54] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x02, 0x00, 0x00,
    0x40, 0x11, 0x60, 0xAF,
    0x0A, 0x00, 0x00, 0x05,
    0x08, 0x08, 0x08, 0x08,
    0xD4, 0x31, 0x00, 0x35,
    0x00, 0x14, 0x00, 0x00,
    0x12, 0x34, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

// ICMP echo request: 192.168.1.1 → 192.168.1.2, total_length=32
static constexpr uint8_t kIcmpFrame[46] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x20,
    0x00, 0x03, 0x00, 0x00,
    0x40, 0x01, 0xF7, 0x86,
    0xC0, 0xA8, 0x01, 0x01,
    0xC0, 0xA8, 0x01, 0x02,
    0x08, 0x00, 0xF7, 0xFD,
    0x00, 0x01, 0x00, 0x01,
    0xDE, 0xAD, 0xBE, 0xEF,
};

// ARP request: 192.168.1.10/11:22:33:44:55:66 → 192.168.1.1
static constexpr uint8_t kArpFrame[42] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x06,
    0x00, 0x01, 0x08, 0x00,
    0x06, 0x04, 0x00, 0x01,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0xC0, 0xA8, 0x01, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
};

// ─────────────────────────────────────────────────────────────────────────────
// Helper — run a raw frame through ethernet_parser + dissector_stage +
// stats_stage in one call. Mirrors what filter_stage does minus the
// packet_buffer read and timestamp strip.
// ─────────────────────────────────────────────────────────────────────────────

static std::optional<pipeline::EnrichedFrame> runPipeline(
    const uint8_t*          raw,
    std::size_t             len,
    const pipeline::LocalIpSet& local_ips = {},
    uint64_t                ts_ms = 1000)
{
    auto eth = parsers::ethernet_parser::parse(raw, len);
    if (!eth.valid) return std::nullopt;

    pipeline::FilteredFrame filtered{.eth = eth, .capture_ts_ms = ts_ms};

    auto dissected = pipeline::dissector_stage(filtered, local_ips);
    if (!dissected.has_value()) return std::nullopt;

    return pipeline::stats_stage(*dissected);
}

// ─────────────────────────────────────────────────────────────────────────────
// EnrichedFrame field verification — Day 20 milestone requirement:
// "Verify JSON payload includes: src_ip, dst_ip, src_port, dst_port,
//  protocol, flags bitmask, packet_size, direction, flow_key, seq_num,
//  first_seen, last_seen, total_bytes"
// ─────────────────────────────────────────────────────────────────────────────

TEST(FullPipeline, TcpSynEnrichedFrameHasAllRequiredFields) {
    auto e = runPipeline(kTcpSynFrame, sizeof(kTcpSynFrame));
    ASSERT_TRUE(e.has_value());

    // Network layer
    EXPECT_EQ(e->src_ip,      0xC0A8010Au);   // 192.168.1.10
    EXPECT_EQ(e->dst_ip,      0x0A000005u);   // 10.0.0.5
    EXPECT_EQ(e->protocol,    6u);            // TCP
    EXPECT_EQ(e->packet_size, 40u);           // ip.total_length
    EXPECT_EQ(e->ttl,         64u);

    // MAC layer
    EXPECT_EQ(e->src_mac[0], 0x11u);
    EXPECT_EQ(e->dst_mac[0], 0xAAu);

    // Transport layer
    EXPECT_EQ(e->src_port, 12345u);
    EXPECT_EQ(e->dst_port, 80u);

    // TCP-specific
    EXPECT_EQ(e->flags & parsers::TcpFlags::SYN, parsers::TcpFlags::SYN);
    EXPECT_EQ(e->flags & parsers::TcpFlags::ACK, 0u);
    EXPECT_EQ(e->seq_num, 1u);

    // Non-applicable protocol fields
    EXPECT_EQ(e->icmp_type, 0u);
    EXPECT_EQ(e->icmp_code, 0u);

    EXPECT_EQ(e->arp_sender_ip, 0u);
    EXPECT_EQ(e->arp_target_ip, 0u);
    EXPECT_EQ(e->arp_opcode, 0u);

    // Pipeline metadata
    EXPECT_TRUE(e->checksum_valid);
    EXPECT_FALSE(e->is_retransmit);


    // Flow key format
    EXPECT_EQ(e->flow_key, "192.168.1.10:12345->10.0.0.5:80");

    // Timestamp promoted from FilteredFrame
    EXPECT_EQ(e->timestamp, 1000u);
}

TEST(FullPipeline, UdpDnsEnrichedFrameHasAllRequiredFields) {
    auto e = runPipeline(kUdpDnsFrame, sizeof(kUdpDnsFrame));
    ASSERT_TRUE(e.has_value());

    EXPECT_EQ(e->protocol,  17u);           // UDP
    EXPECT_EQ(e->src_port,  54321u);
    EXPECT_EQ(e->dst_port,  53u);
    EXPECT_EQ(e->flags,     0u);            // no TCP flags
    EXPECT_EQ(e->seq_num,   0u);            // no seq_num
    // Non-applicable protocol fields
    EXPECT_EQ(e->icmp_type, 0u);
    EXPECT_EQ(e->icmp_code, 0u);

    EXPECT_EQ(e->arp_sender_ip, 0u);
    EXPECT_EQ(e->arp_target_ip, 0u);
    EXPECT_EQ(e->arp_opcode, 0u);

    EXPECT_TRUE(e->checksum_valid);
    EXPECT_FALSE(e->is_retransmit);
    EXPECT_EQ(e->flow_key,  "10.0.0.5:54321->8.8.8.8:53");
}

TEST(FullPipeline, IcmpEnrichedFrameHasAllRequiredFields) {
    auto e = runPipeline(kIcmpFrame, sizeof(kIcmpFrame));
    ASSERT_TRUE(e.has_value());

    EXPECT_EQ(e->protocol,    1u);          // ICMP
    EXPECT_EQ(e->packet_size, 32u);         // ip.total_length — Rule 3
    EXPECT_EQ(e->src_port,    0u);
    EXPECT_EQ(e->dst_port,    0u);
    EXPECT_EQ(e->flags,       0u);
    EXPECT_EQ(e->seq_num,     0u);
    // ICMP-specific fields
    EXPECT_EQ(e->icmp_type, 8u);   // Echo Request
    EXPECT_EQ(e->icmp_code, 0u);

    EXPECT_EQ(e->arp_sender_ip, 0u);
    EXPECT_EQ(e->arp_target_ip, 0u);
    EXPECT_EQ(e->arp_opcode, 0u);

    EXPECT_TRUE(e->checksum_valid);
    EXPECT_FALSE(e->is_retransmit);
}

TEST(FullPipeline, ArpEnrichedFrameHasAllRequiredFields) {
    auto e = runPipeline(kArpFrame, sizeof(kArpFrame));
    ASSERT_TRUE(e.has_value());

    EXPECT_EQ(e->arp_sender_ip, 0xC0A8010Au);  // 192.168.1.10
    EXPECT_EQ(e->arp_target_ip, 0xC0A80101u);  // 192.168.1.1
    EXPECT_EQ(e->arp_opcode, 1u);              // ARP request (oper=1)
    EXPECT_EQ(e->arp_sender_mac[0], 0x11u);
    EXPECT_EQ(e->arp_sender_mac[5], 0x66u);
    EXPECT_EQ(e->flow_key, "ARP:192.168.1.10");
}

// ─────────────────────────────────────────────────────────────────────────────
// FlowTracker — accumulates state across packets in same flow
// ─────────────────────────────────────────────────────────────────────────────

TEST(FullPipeline, FlowTrackerAccumulatesBytesAcrossPackets) {
    pipeline::FlowTable table;

    bool retransmit = false;

    auto e1 = runPipeline(kTcpSynFrame, sizeof(kTcpSynFrame), {}, 1000);
    ASSERT_TRUE(e1.has_value());

    auto f1 = pipeline::flow_tracker(*e1, table, retransmit);

    EXPECT_FALSE(retransmit);

    EXPECT_EQ(f1.first_seen_ms, 1000u);
    EXPECT_EQ(f1.last_seen_ms,  1000u);

    EXPECT_EQ(f1.total_bytes,    40u);
    EXPECT_EQ(f1.inbound_bytes,   0u);
    EXPECT_EQ(f1.outbound_bytes,  0u);

    EXPECT_EQ(f1.syn_count,      1u);
    EXPECT_EQ(f1.syn_ack_count,  0u);
    EXPECT_EQ(f1.rst_count,      0u);

    EXPECT_EQ(f1.retransmit_count, 0u);

    // Second packet on same flow
    auto e2 = runPipeline(kTcpSynFrame, sizeof(kTcpSynFrame), {}, 2000);
    ASSERT_TRUE(e2.has_value());

    auto f2 = pipeline::flow_tracker(*e2, table, retransmit);

    EXPECT_TRUE(retransmit);

    EXPECT_EQ(f2.first_seen_ms, 1000u);
    EXPECT_EQ(f2.last_seen_ms,  2000u);

    EXPECT_EQ(f2.total_bytes, 80u);

    EXPECT_EQ(f2.syn_count,     2u);
    EXPECT_EQ(f2.syn_ack_count, 0u);

    EXPECT_EQ(f2.retransmit_count, 1u);
}

TEST(FullPipeline, FlowTrackerTracksSynAndSynAckSeparately) {
    pipeline::FlowTable table;

    bool retransmit = false;

    auto syn = runPipeline(kTcpSynFrame,
                           sizeof(kTcpSynFrame),
                           {},
                           1000);

    ASSERT_TRUE(syn.has_value());

    pipeline::flow_tracker(*syn, table, retransmit);

    auto synack = runPipeline(kTcpSynAckFrame,
                              sizeof(kTcpSynAckFrame),
                              {},
                              1001);

    ASSERT_TRUE(synack.has_value());

    // Reverse direction => different flow key
    auto f = pipeline::flow_tracker(*synack, table, retransmit);

    EXPECT_EQ(f.syn_ack_count, 1u);
    EXPECT_EQ(f.syn_count,     0u);
    EXPECT_EQ(f.rst_count,     0u);
}

TEST(FullPipeline, FlowTrackerRetransmitSetGrowsOnNewSeqNums) {
    pipeline::FlowTable table;

    bool retransmit = false;

    // First packet: seq=1
    auto e1 = runPipeline(kTcpSynFrame, sizeof(kTcpSynFrame), {}, 1000);
    ASSERT_TRUE(e1.has_value());

    auto f1 = pipeline::flow_tracker(*e1, table, retransmit);

    EXPECT_FALSE(retransmit);

    EXPECT_EQ(f1.retransmit_set.size(), 1u);
    EXPECT_EQ(f1.retransmit_count,      0u);

    // Same sequence number again => retransmission
    auto e2 = runPipeline(kTcpSynFrame, sizeof(kTcpSynFrame), {}, 1001);
    ASSERT_TRUE(e2.has_value());

    auto f2 = pipeline::flow_tracker(*e2, table, retransmit);

    EXPECT_TRUE(retransmit);

    EXPECT_EQ(f2.retransmit_set.size(), 1u);
    EXPECT_EQ(f2.retransmit_count,      1u);
}

TEST(FullPipeline, FlowTrackerTracksDistinctFlowsSeparately) {
    pipeline::FlowTable table;

    bool retransmit = false;

    auto tcp = runPipeline(kTcpSynFrame, sizeof(kTcpSynFrame), {}, 1000);
    ASSERT_TRUE(tcp.has_value());

    pipeline::flow_tracker(*tcp, table, retransmit);

    auto udp = runPipeline(kUdpDnsFrame, sizeof(kUdpDnsFrame), {}, 1000);
    ASSERT_TRUE(udp.has_value());

    pipeline::flow_tracker(*udp, table, retransmit);

    auto tcp_rec = table.get("192.168.1.10:12345->10.0.0.5:80");

    auto udp_rec = table.get("10.0.0.5:54321->8.8.8.8:53");

    EXPECT_EQ(tcp_rec.total_bytes, 40u);
    EXPECT_EQ(udp_rec.total_bytes, 40u);

    EXPECT_EQ(tcp_rec.syn_count, 1u);
    EXPECT_EQ(udp_rec.syn_count, 0u);

    EXPECT_EQ(tcp_rec.syn_ack_count, 0u);
    EXPECT_EQ(udp_rec.syn_ack_count, 0u);
}

// ─────────────────────────────────────────────────────────────────────────────
// Direction — injected by dissector based on local_ips
// ─────────────────────────────────────────────────────────────────────────────

TEST(FullPipeline, DirectionInboundWhenDstIpIsLocal) {
    pipeline::LocalIpSet local_ips = {0x0A000005u};

    auto e = runPipeline(kTcpSynFrame,
                         sizeof(kTcpSynFrame),
                         local_ips);

    ASSERT_TRUE(e.has_value());

    EXPECT_EQ(e->direction, parsers::Direction::Inbound);
}

TEST(FullPipeline, DirectionOutboundWhenSrcIpIsLocal) {
    pipeline::LocalIpSet local_ips = {0xC0A8010Au};

    auto e = runPipeline(kTcpSynFrame,
                         sizeof(kTcpSynFrame),
                         local_ips);

    ASSERT_TRUE(e.has_value());

    EXPECT_EQ(e->direction, parsers::Direction::Outbound);
}

TEST(FullPipeline, DirectionUnknownWhenNeitherIpIsLocal) {
    pipeline::LocalIpSet local_ips = {};

    auto e = runPipeline(kTcpSynFrame,
                         sizeof(kTcpSynFrame),
                         local_ips);

    ASSERT_TRUE(e.has_value());

    EXPECT_EQ(e->direction, parsers::Direction::Unknown);
}

TEST(FullPipeline, InboundBytesAccumulateCorrectly) {
    pipeline::LocalIpSet local_ips = {0x0A000005u};

    pipeline::FlowTable table;

    bool retransmit = false;

    auto e = runPipeline(kTcpSynFrame,
                         sizeof(kTcpSynFrame),
                         local_ips,
                         1000);

    ASSERT_TRUE(e.has_value());

    EXPECT_EQ(e->direction, parsers::Direction::Inbound);

    auto f = pipeline::flow_tracker(*e, table, retransmit);

    EXPECT_EQ(f.inbound_bytes,  40u);
    EXPECT_EQ(f.outbound_bytes, 0u);
}