#include <gtest/gtest.h>
#include "parsers/ip_parser.h"

using parsers::parseIpHeader;
using parsers::Direction;

static constexpr uint8_t kTcpInbound[40] = {
    // IP header (20 bytes)
    0x45, 0x00, 0x00, 0x28,   
    0x00, 0x01, 0x40, 0x00,   
    0x80, 0x06, 0x2F, 0x18,   
    0xC0, 0xA8, 0x01, 0x0A,  
    0x0A, 0x00, 0x00, 0x05,   
    0x00, 0x50, 0x1F, 0x90,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x02, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00,
};


static constexpr uint8_t kUdpOutbound[36] = {
    0x45, 0x00, 0x00, 0x24,
    0x00, 0x02, 0x00, 0x00,
    0x40, 0x11, 0xAF, 0x10,   
    0x0A, 0x00, 0x00, 0x05,  
    0xC0, 0xA8, 0x01, 0x0A,  
    0x00, 0x35, 0x04, 0x00,
    0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};


static constexpr uint8_t kIcmpHeader[28] = {
    0x45, 0x00, 0x00, 0x1C,
    0x00, 0x03, 0x00, 0x00,
    0xFF, 0x01, 0x1B, 0x33,   
    0xC0, 0xA8, 0x00, 0x01,   
    0xE0, 0x00, 0x00, 0x01,   
    0x08, 0x00, 0xF7, 0xFD,
    0x00, 0x01, 0x00, 0x01,
};


static constexpr uint8_t kBadChecksum[20] = {
    0x45, 0x00, 0x00, 0x14,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0xDE, 0xAD,   
    0xC0, 0xA8, 0x01, 0x01,
    0x0A, 0x00, 0x00, 0x01,
};

static constexpr uint8_t kTooShort[19] = {
    0x45, 0x00, 0x00, 0x13,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
    0x0A, 0x00, 0x00,   // truncated
};

static constexpr uint8_t kIpv6Version[20] = {
    0x65, 0x00, 0x00, 0x14,   
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
    0x0A, 0x00, 0x00, 0x01,
};

static constexpr uint8_t kSmallIhl[20] = {
    0x43, 0x00, 0x00, 0x14,   
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
    0x0A, 0x00, 0x00, 0x01,
};

static constexpr uint8_t kTotalLengthTooLarge[20] = {
    0x45, 0x00, 0xFF, 0xFF,   
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
    0x0A, 0x00, 0x00, 0x01,
};

// ---------------------------------------------------------------------------
// Field extraction tests
// ---------------------------------------------------------------------------

TEST(IpParserTest, ParsesTcpInboundCorrectly) {
    auto result = parseIpHeader(kTcpInbound, sizeof(kTcpInbound), Direction::Inbound);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->ihl,          5u);
    EXPECT_EQ(result->ttl,          128u);
    EXPECT_EQ(result->protocol,     6u);    
    EXPECT_EQ(result->total_length, 40u);
    EXPECT_EQ(result->src_ip,       0xC0A8010Au); 
    EXPECT_EQ(result->dst_ip,       0x0A000005u); 
    EXPECT_TRUE(result->checksum_ok);
    EXPECT_EQ(result->direction,    Direction::Inbound);
}

TEST(IpParserTest, ParsesUdpOutboundCorrectly) {
    auto result = parseIpHeader(kUdpOutbound, sizeof(kUdpOutbound), Direction::Outbound);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->protocol,     17u);   
    EXPECT_EQ(result->ttl,          64u);
    EXPECT_EQ(result->total_length, 36u);
    EXPECT_EQ(result->src_ip,       0x0A000005u); 
    EXPECT_EQ(result->dst_ip,       0xC0A8010Au); 
    EXPECT_TRUE(result->checksum_ok);
    EXPECT_EQ(result->direction,    Direction::Outbound);
}

TEST(IpParserTest, ParsesIcmpProtocolField) {
    auto result = parseIpHeader(kIcmpHeader, sizeof(kIcmpHeader), Direction::Unknown);
    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->protocol,  1u);     
    EXPECT_EQ(result->ttl,       255u);
    EXPECT_TRUE(result->checksum_ok);
}

// ---------------------------------------------------------------------------
// Packet size (total_length) tests
// ---------------------------------------------------------------------------

TEST(IpParserTest, TotalLengthExtractedCorrectly) {
    auto result = parseIpHeader(kTcpInbound, sizeof(kTcpInbound), Direction::Inbound);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->total_length, 40u);
}

TEST(IpParserTest, PayloadPointerAndLengthCorrect) {
    auto result = parseIpHeader(kTcpInbound, sizeof(kTcpInbound), Direction::Inbound);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_len, 20u);
    EXPECT_EQ(result->payload,     kTcpInbound + 20);
}

// ---------------------------------------------------------------------------
// Direction tests — required for Rule 15
// ---------------------------------------------------------------------------

TEST(IpParserTest, DirectionInboundPreserved) {
    auto result = parseIpHeader(kTcpInbound, sizeof(kTcpInbound), Direction::Inbound);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->direction, Direction::Inbound);
}

TEST(IpParserTest, DirectionOutboundPreserved) {
    auto result = parseIpHeader(kUdpOutbound, sizeof(kUdpOutbound), Direction::Outbound);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->direction, Direction::Outbound);
}

TEST(IpParserTest, DirectionUnknownWhenNotSupplied) {
    auto result = parseIpHeader(kTcpInbound, sizeof(kTcpInbound));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->direction, Direction::Unknown);
}

// ---------------------------------------------------------------------------
// Checksum tests
// ---------------------------------------------------------------------------

TEST(IpParserTest, ValidChecksumSetsChecksumOkTrue) {
    auto result = parseIpHeader(kTcpInbound, sizeof(kTcpInbound), Direction::Inbound);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->checksum_ok);
}

TEST(IpParserTest, CorruptChecksumSetsChecksumOkFalse) {
    auto result = parseIpHeader(kBadChecksum, sizeof(kBadChecksum), Direction::Unknown);
    ASSERT_TRUE(result.has_value());   
    EXPECT_FALSE(result->checksum_ok);
}

// ---------------------------------------------------------------------------
// Rejection / malformed tests
// ---------------------------------------------------------------------------

TEST(IpParserTest, RejectsBufferSmallerThanMinimumHeader) {
    auto result = parseIpHeader(kTooShort, sizeof(kTooShort));
    EXPECT_FALSE(result.has_value());
}

TEST(IpParserTest, RejectsIpv6VersionField) {
    auto result = parseIpHeader(kIpv6Version, sizeof(kIpv6Version));
    EXPECT_FALSE(result.has_value());
}

TEST(IpParserTest, RejectsIhlBelowMinimum) {
    auto result = parseIpHeader(kSmallIhl, sizeof(kSmallIhl));
    EXPECT_FALSE(result.has_value());
}

TEST(IpParserTest, RejectsTotalLengthExceedingBuffer) {
    auto result = parseIpHeader(kTotalLengthTooLarge, sizeof(kTotalLengthTooLarge));
    EXPECT_FALSE(result.has_value());
}

TEST(IpParserTest, RejectsEmptyBuffer) {
    auto result = parseIpHeader(nullptr, 0);
    EXPECT_FALSE(result.has_value());
}

TEST(IpParserTest, RejectsSingleByteBuffer) {
    uint8_t buf[1] = {0x45};
    auto result = parseIpHeader(buf, 1);
    EXPECT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// TTL edge cases
// ---------------------------------------------------------------------------

TEST(IpParserTest, TtlOf255ParsedCorrectly) {
    auto result = parseIpHeader(kIcmpHeader, sizeof(kIcmpHeader));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ttl, 255u);
}

TEST(IpParserTest, TtlOf128ParsedCorrectly) {
    auto result = parseIpHeader(kTcpInbound, sizeof(kTcpInbound), Direction::Inbound);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ttl, 128u);
}

TEST(IpParserTest, TtlOf64ParsedCorrectly) {
    auto result = parseIpHeader(kUdpOutbound, sizeof(kUdpOutbound), Direction::Outbound);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ttl, 64u);
}