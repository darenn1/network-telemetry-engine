#include <gtest/gtest.h>
#include "parsers/icmp_parser.h"

using parsers::parseIcmpHeader;
using parsers::ICMP_NORMAL_MTU;
namespace IcmpType = parsers::IcmpType;

static constexpr uint8_t kEchoRequest[12] = {
    0x08, 0x00, 0xF7, 0xFD, 0x00, 0x01, 0x00, 0x01,
    0xDE, 0xAD, 0xBE, 0xEF,
};

static constexpr uint8_t kEchoReply[8] = {
    0x00, 0x00, 0xFF, 0xFD, 0x00, 0x01, 0x00, 0x01,
};

static constexpr uint8_t kDestUnreachable[8] = {
    0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static constexpr uint8_t kTtlExceeded[8] = {
    0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

TEST(IcmpParserTest, ParsesEchoRequestType) {
    auto result = parseIcmpHeader(kEchoRequest, sizeof(kEchoRequest), 32);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, IcmpType::ECHO_REQUEST);
    EXPECT_EQ(result->code, 0u);
}

TEST(IcmpParserTest, ParsesEchoReplyType) {
    auto result = parseIcmpHeader(kEchoReply, sizeof(kEchoReply), 28);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, IcmpType::ECHO_REPLY);
}

TEST(IcmpParserTest, ParsesDestUnreachableTypeAndCode) {
    auto result = parseIcmpHeader(kDestUnreachable, sizeof(kDestUnreachable), 28);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, IcmpType::DEST_UNREACHABLE);
    EXPECT_EQ(result->code, 1u);
}

TEST(IcmpParserTest, ParsesTtlExceededType) {
    auto result = parseIcmpHeader(kTtlExceeded, sizeof(kTtlExceeded), 28);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->type, IcmpType::TTL_EXCEEDED);
}

TEST(IcmpParserTest, PacketSizeIsIpTotalLength) {
    auto result = parseIcmpHeader(kEchoRequest, sizeof(kEchoRequest), 500);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->packet_size, 500u);
}

TEST(IcmpParserTest, NormalSizedPacketNotFlagged) {
    auto result = parseIcmpHeader(kEchoRequest, sizeof(kEchoRequest), 1500);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->is_oversized);
}

TEST(IcmpParserTest, PacketAtExactMtuNotFlagged) {
    auto result = parseIcmpHeader(kEchoRequest, sizeof(kEchoRequest), 1500);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->packet_size, ICMP_NORMAL_MTU);
    EXPECT_FALSE(result->is_oversized);
}

TEST(IcmpParserTest, PacketOneByteOverMtuIsFlagged) {
    auto result = parseIcmpHeader(kEchoRequest, sizeof(kEchoRequest), 1501);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->is_oversized);
}

TEST(IcmpParserTest, PingOfDeathSizedPacketFlagged) {
    auto result = parseIcmpHeader(kEchoRequest, sizeof(kEchoRequest), 65535);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->is_oversized);
}

TEST(IcmpParserTest, SmallPacketNotFlagged) {
    auto result = parseIcmpHeader(kEchoRequest, sizeof(kEchoRequest), 28);
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->is_oversized);
}

TEST(IcmpParserTest, MtuConstantIsCorrect) {
    EXPECT_EQ(ICMP_NORMAL_MTU, 1500u);
}

TEST(IcmpParserTest, PayloadPointerCorrectForEchoRequest) {
    auto result = parseIcmpHeader(kEchoRequest, sizeof(kEchoRequest), 32);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_len, 4u);
    EXPECT_EQ(result->payload, kEchoRequest + 8);
    EXPECT_EQ(result->payload[0], 0xDEu);
    EXPECT_EQ(result->payload[3], 0xEFu);
}

TEST(IcmpParserTest, ZeroPayloadLenWhenHeaderFillsBuffer) {
    auto result = parseIcmpHeader(kEchoReply, sizeof(kEchoReply), 28);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_len, 0u);
    EXPECT_EQ(result->payload, kEchoReply + 8);
}

TEST(IcmpParserTest, RejectsNullPointer) {
    auto result = parseIcmpHeader(nullptr, 8, 28);
    EXPECT_FALSE(result.has_value());
}

TEST(IcmpParserTest, RejectsBufferSmallerThan8Bytes) {
    auto result = parseIcmpHeader(kEchoReply, 7, 28);
    EXPECT_FALSE(result.has_value());
}

TEST(IcmpParserTest, RejectsEmptyBuffer) {
    uint8_t buf[1] = {0x08};
    auto result = parseIcmpHeader(buf, 0, 28);
    EXPECT_FALSE(result.has_value());
}