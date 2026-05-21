#include <gtest/gtest.h>

#include "parsers/ethernet_parser.h"
#include "parsers/ip_parser.h"
#include "parsers/tcp_parser.h"
#include "parsers/udp_parser.h"
#include "parsers/icmp_parser.h"
#include "parsers/arp_parser.h"

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

static constexpr uint8_t kIcmpEchoFrame[46] = {
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

static constexpr uint8_t kArpRequestFrame[42] = {
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

static constexpr uint8_t kTruncatedIpFrame[20] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x28,
    0x00, 0x01,
};

static constexpr uint8_t kIpv6EtherFrame[60] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x86, 0xDD,
    0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3A, 0x40,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static parsers::EthernetFrame parseEth(const uint8_t* frame, std::size_t len) {
    return parsers::ethernet_parser::parse(frame, len);
}

TEST(ParserIntegration, TcpSynFrameEthernetLayer) {
    auto eth = parseEth(kTcpSynFrame, sizeof(kTcpSynFrame));
    ASSERT_TRUE(eth.valid);
    EXPECT_EQ(eth.ethertype, 0x0800u);
    EXPECT_EQ(eth.dst_mac[0], 0xAAu);
    EXPECT_EQ(eth.src_mac[0], 0x11u);
    EXPECT_EQ(eth.payload_size, 40u);
}

TEST(ParserIntegration, TcpSynFrameIpLayer) {
    auto eth = parseEth(kTcpSynFrame, sizeof(kTcpSynFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size, parsers::Direction::Inbound);
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->protocol, 6u);
    EXPECT_EQ(ip->src_ip, 0xC0A8010Au);
    EXPECT_EQ(ip->dst_ip, 0x0A000005u);
    EXPECT_EQ(ip->total_length, 40u);
    EXPECT_TRUE(ip->checksum_ok);
    EXPECT_EQ(ip->direction, parsers::Direction::Inbound);
}

TEST(ParserIntegration, TcpSynFrameTcpLayer) {
    auto eth = parseEth(kTcpSynFrame, sizeof(kTcpSynFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip.has_value());
    auto tcp = parsers::parseTcpHeader(ip->payload, ip->payload_len);
    ASSERT_TRUE(tcp.has_value());
    EXPECT_EQ(tcp->src_port, 12345u);
    EXPECT_EQ(tcp->dst_port, 80u);
    EXPECT_EQ(tcp->seq_num, 1u);
    EXPECT_EQ(tcp->flags & parsers::TcpFlags::SYN, parsers::TcpFlags::SYN);
    EXPECT_EQ(tcp->flags & parsers::TcpFlags::ACK, 0u);
    EXPECT_EQ(tcp->payload_len, 0u);
}

TEST(ParserIntegration, TcpSynFramePayloadChainIsConsistent) {
    auto eth = parseEth(kTcpSynFrame, sizeof(kTcpSynFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->payload, kTcpSynFrame + 34);
    EXPECT_EQ(ip->payload_len, 20u);
    auto tcp = parsers::parseTcpHeader(ip->payload, ip->payload_len);
    ASSERT_TRUE(tcp.has_value());
    EXPECT_EQ(tcp->payload, kTcpSynFrame + 54);
}

TEST(ParserIntegration, UdpDnsFrameEthernetLayer) {
    auto eth = parseEth(kUdpDnsFrame, sizeof(kUdpDnsFrame));
    ASSERT_TRUE(eth.valid);
    EXPECT_EQ(eth.ethertype, 0x0800u);
}

TEST(ParserIntegration, UdpDnsFrameIpLayer) {
    auto eth = parseEth(kUdpDnsFrame, sizeof(kUdpDnsFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->protocol, 17u);
    EXPECT_EQ(ip->src_ip, 0x0A000005u);
    EXPECT_EQ(ip->dst_ip, 0x08080808u);
    EXPECT_TRUE(ip->checksum_ok);
}

TEST(ParserIntegration, UdpDnsFrameUdpLayer) {
    auto eth = parseEth(kUdpDnsFrame, sizeof(kUdpDnsFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip.has_value());
    auto udp = parsers::parseUdpHeader(ip->payload, ip->payload_len);
    ASSERT_TRUE(udp.has_value());
    EXPECT_EQ(udp->src_port, 54321u);
    EXPECT_EQ(udp->dst_port, 53u);
    EXPECT_TRUE(udp->is_dns);
    EXPECT_EQ(udp->payload_len, 12u);
    EXPECT_EQ(udp->payload[0], 0x12u);
}

TEST(ParserIntegration, UdpDnsFramePayloadChainIsConsistent) {
    auto eth = parseEth(kUdpDnsFrame, sizeof(kUdpDnsFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->payload, kUdpDnsFrame + 34);
    auto udp = parsers::parseUdpHeader(ip->payload, ip->payload_len);
    ASSERT_TRUE(udp.has_value());
    EXPECT_EQ(udp->payload, kUdpDnsFrame + 42);
}

TEST(ParserIntegration, IcmpFrameIpLayer) {
    auto eth = parseEth(kIcmpEchoFrame, sizeof(kIcmpEchoFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->protocol, 1u);
    EXPECT_TRUE(ip->checksum_ok);
    EXPECT_EQ(ip->total_length, 32u);
}

TEST(ParserIntegration, IcmpFrameIcmpLayer) {
    auto eth = parseEth(kIcmpEchoFrame, sizeof(kIcmpEchoFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip.has_value());
    auto icmp = parsers::parseIcmpHeader(ip->payload, ip->payload_len, ip->total_length);
    ASSERT_TRUE(icmp.has_value());
    EXPECT_EQ(icmp->type, parsers::IcmpType::ECHO_REQUEST);
    EXPECT_EQ(icmp->code, 0u);
    EXPECT_EQ(icmp->packet_size, 32u);
    EXPECT_FALSE(icmp->is_oversized);
    EXPECT_EQ(icmp->payload_len, 4u);
    EXPECT_EQ(icmp->payload[0], 0xDEu);
}

TEST(ParserIntegration, IcmpFramePayloadChainIsConsistent) {
    auto eth = parseEth(kIcmpEchoFrame, sizeof(kIcmpEchoFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->payload, kIcmpEchoFrame + 34);
    auto icmp = parsers::parseIcmpHeader(ip->payload, ip->payload_len, ip->total_length);
    ASSERT_TRUE(icmp.has_value());
    EXPECT_EQ(icmp->payload, kIcmpEchoFrame + 42);
    EXPECT_EQ(icmp->payload[0], 0xDEu);
    EXPECT_EQ(icmp->payload[3], 0xEFu);
}

TEST(ParserIntegration, ArpFrameEthernetLayer) {
    auto eth = parseEth(kArpRequestFrame, sizeof(kArpRequestFrame));
    ASSERT_TRUE(eth.valid);
    EXPECT_EQ(eth.ethertype, 0x0806u);
    EXPECT_EQ(eth.payload_size, 28u);
}

TEST(ParserIntegration, ArpFrameArpLayer) {
    auto eth = parseEth(kArpRequestFrame, sizeof(kArpRequestFrame));
    ASSERT_TRUE(eth.valid);
    auto arp = parsers::parseArpPacket(eth.payload, eth.payload_size);
    ASSERT_TRUE(arp.has_value());
    EXPECT_EQ(arp->oper, parsers::ArpOper::REQUEST);
    EXPECT_FALSE(arp->is_reply);
    EXPECT_EQ(arp->sender_ip, 0xC0A8010Au);
    EXPECT_EQ(arp->target_ip, 0xC0A80101u);
    EXPECT_EQ(arp->sender_mac[0], 0x11u);
    EXPECT_EQ(arp->sender_mac[5], 0x66u);
}

TEST(ParserIntegration, ArpFramePayloadChainIsConsistent) {
    auto eth = parseEth(kArpRequestFrame, sizeof(kArpRequestFrame));
    ASSERT_TRUE(eth.valid);
    EXPECT_EQ(eth.payload, kArpRequestFrame + 14);
    auto arp = parsers::parseArpPacket(eth.payload, eth.payload_size);
    ASSERT_TRUE(arp.has_value());
}

TEST(ParserIntegration, TruncatedIpFrameRejectedByIpParser) {
    auto eth = parseEth(kTruncatedIpFrame, sizeof(kTruncatedIpFrame));
    ASSERT_TRUE(eth.valid);
    EXPECT_EQ(eth.ethertype, 0x0800u);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    EXPECT_FALSE(ip.has_value());
}

TEST(ParserIntegration, IPv6EtherTypeNotRoutedToIpParser) {
    auto eth = parseEth(kIpv6EtherFrame, sizeof(kIpv6EtherFrame));
    ASSERT_TRUE(eth.valid);
    EXPECT_EQ(eth.ethertype, 0x86DDu);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    EXPECT_FALSE(ip.has_value());
}

TEST(ParserIntegration, NullFrameRejectedByEthernetParser) {
    auto eth = parsers::ethernet_parser::parse(nullptr, 0);
    EXPECT_FALSE(eth.valid);
}

TEST(ParserIntegration, IpTotalLengthPassedThroughToIcmpParser) {
    auto eth = parseEth(kIcmpEchoFrame, sizeof(kIcmpEchoFrame));
    ASSERT_TRUE(eth.valid);
    auto ip = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip.has_value());
    EXPECT_EQ(ip->total_length, 32u);
    auto icmp = parsers::parseIcmpHeader(ip->payload, ip->payload_len, ip->total_length);
    ASSERT_TRUE(icmp.has_value());
    EXPECT_EQ(icmp->packet_size, ip->total_length);
    EXPECT_FALSE(icmp->is_oversized);
}

TEST(ParserIntegration, DirectionInjectedByDissectorNotParser) {
    auto eth = parseEth(kTcpSynFrame, sizeof(kTcpSynFrame));
    ASSERT_TRUE(eth.valid);
    auto ip_unknown = parsers::parseIpHeader(eth.payload, eth.payload_size);
    ASSERT_TRUE(ip_unknown.has_value());
    EXPECT_EQ(ip_unknown->direction, parsers::Direction::Unknown);
    auto ip_inbound = parsers::parseIpHeader(eth.payload, eth.payload_size, parsers::Direction::Inbound);
    ASSERT_TRUE(ip_inbound.has_value());
    EXPECT_EQ(ip_inbound->direction, parsers::Direction::Inbound);
}
