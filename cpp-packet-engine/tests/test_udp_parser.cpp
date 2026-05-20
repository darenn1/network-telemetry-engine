#include <gtest/gtest.h>
#include "parsers/udp_parser.h"

using parsers::parseUdpHeader;
using parsers::UDP_PORT_DNS;

static constexpr uint8_t kDnsQuery[20] = {
    0xD4, 0x31,
    0x00, 0x35,
    0x00, 0x14,
    0x00, 0x00,
    0x12, 0x34, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};

static constexpr uint8_t kDnsReply[20] = {
    0x00, 0x35,
    0xD4, 0x31,
    0x00, 0x14,
    0x00, 0x00,
    0x12, 0x34, 0x81, 0x80,
    0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
};

static constexpr uint8_t kPlainUdp[16] = {
    0x30, 0x39,
    0x27, 0x0F,
    0x00, 0x10,
    0x00, 0x00,
    0xAA, 0xBB, 0xCC, 0xDD,
    0xEE, 0xFF, 0x11, 0x22,
};

static constexpr uint8_t kHeaderOnly[8] = {
    0x04, 0xD2,
    0x1F, 0x90,
    0x00, 0x08,
    0x00, 0x00,
};

static constexpr uint8_t kLengthTooSmall[8] = {
    0x04, 0xD2,
    0x1F, 0x90,
    0x00, 0x04,
    0x00, 0x00,
};

static constexpr uint8_t kLengthExceedsBuffer[8] = {
    0x04, 0xD2,
    0x1F, 0x90,
    0xFF, 0xFF,
    0x00, 0x00,
};

TEST(UdpParserTest, ParsesSrcPortCorrectly) {
    auto result = parseUdpHeader(kDnsQuery, sizeof(kDnsQuery));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->src_port, 54321u);
}

TEST(UdpParserTest, ParsesDstPortCorrectly) {
    auto result = parseUdpHeader(kDnsQuery, sizeof(kDnsQuery));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->dst_port, 53u);
}

TEST(UdpParserTest, ParsesNonDnsPorts) {
    auto result = parseUdpHeader(kPlainUdp, sizeof(kPlainUdp));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->src_port, 12345u);
    EXPECT_EQ(result->dst_port, 9999u);
}

TEST(UdpParserTest, DnsQueryDetectedByDstPort) {
    auto result = parseUdpHeader(kDnsQuery, sizeof(kDnsQuery));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->is_dns);
}

TEST(UdpParserTest, DnsReplyDetectedBySrcPort) {
    auto result = parseUdpHeader(kDnsReply, sizeof(kDnsReply));
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->is_dns);
}

TEST(UdpParserTest, NonDnsTrafficNotFlagged) {
    auto result = parseUdpHeader(kPlainUdp, sizeof(kPlainUdp));
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->is_dns);
}

TEST(UdpParserTest, DnsPortConstantIsCorrect) {
    EXPECT_EQ(UDP_PORT_DNS, 53u);
}

TEST(UdpParserTest, LengthFieldParsedCorrectly) {
    auto result = parseUdpHeader(kDnsQuery, sizeof(kDnsQuery));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->length, 20u);
}

TEST(UdpParserTest, HeaderOnlyLengthIsEight) {
    auto result = parseUdpHeader(kHeaderOnly, sizeof(kHeaderOnly));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->length, 8u);
}

TEST(UdpParserTest, PayloadPointerCorrectForDnsQuery) {
    auto result = parseUdpHeader(kDnsQuery, sizeof(kDnsQuery));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_len, 12u);
    EXPECT_EQ(result->payload, kDnsQuery + 8);
    EXPECT_EQ(result->payload[0], 0x12u);
}

TEST(UdpParserTest, PayloadPointerCorrectForPlainUdp) {
    auto result = parseUdpHeader(kPlainUdp, sizeof(kPlainUdp));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_len, 8u);
    EXPECT_EQ(result->payload, kPlainUdp + 8);
    EXPECT_EQ(result->payload[0], 0xAAu);
}

TEST(UdpParserTest, ZeroPayloadLenWhenHeaderOnly) {
    auto result = parseUdpHeader(kHeaderOnly, sizeof(kHeaderOnly));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_len, 0u);
    EXPECT_EQ(result->payload, kHeaderOnly + 8);
}

TEST(UdpParserTest, RejectsNullPointer) {
    auto result = parseUdpHeader(nullptr, 8);
    EXPECT_FALSE(result.has_value());
}

TEST(UdpParserTest, RejectsBufferSmallerThan8Bytes) {
    auto result = parseUdpHeader(kHeaderOnly, 7);
    EXPECT_FALSE(result.has_value());
}

TEST(UdpParserTest, RejectsLengthFieldBelowMinimum) {
    auto result = parseUdpHeader(kLengthTooSmall, sizeof(kLengthTooSmall));
    EXPECT_FALSE(result.has_value());
}

TEST(UdpParserTest, RejectsLengthFieldExceedingBuffer) {
    auto result = parseUdpHeader(kLengthExceedsBuffer, sizeof(kLengthExceedsBuffer));
    EXPECT_FALSE(result.has_value());
}

TEST(UdpParserTest, RejectsEmptyBuffer) {
    uint8_t buf[1] = {0x00};
    auto result = parseUdpHeader(buf, 0);
    EXPECT_FALSE(result.has_value());
}