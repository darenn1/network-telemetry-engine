#include <gtest/gtest.h>
#include "parsers/tcp_parser.h"

using parsers::parseTcpHeader;
namespace TcpFlags = parsers::TcpFlags;

static constexpr uint8_t kSynPacket[20] = {
    0x30, 0x39,
    0x00, 0x50,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00,
    0x50,
    0x02,
    0xFF, 0xFF,
    0x00, 0x00,
    0x00, 0x00,
};

static constexpr uint8_t kSynAckPacket[20] = {
    0x00, 0x50,
    0x30, 0x39,
    0xDE, 0xAD, 0xBE, 0xEF,
    0x00, 0x00, 0x00, 0x02,
    0x50,
    0x12,
    0xFF, 0xFF,
    0x00, 0x00,
    0x00, 0x00,
};

static constexpr uint8_t kRstPacket[20] = {
    0x00, 0x50,
    0x30, 0x39,
    0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x00,
    0x50,
    0x04,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
};

static constexpr uint8_t kSynFinPacket[20] = {
    0x04, 0xD2,
    0x00, 0x50,
    0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00,
    0x50,
    0x03,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
};

static constexpr uint8_t kNullScanPacket[20] = {
    0x04, 0xD2,
    0x00, 0x50,
    0x00, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x00,
    0x50,
    0x00,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
};

static constexpr uint8_t kXmasPacket[20] = {
    0x04, 0xD2,
    0x00, 0x50,
    0x00, 0x00, 0x00, 0x06,
    0x00, 0x00, 0x00, 0x00,
    0x50,
    0x29,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
};

static constexpr uint8_t kOptionsPacket[36] = {
    0x04, 0xD2,
    0x1F, 0x90,
    0x00, 0x00, 0x00, 0x07,
    0x00, 0x00, 0x00, 0x00,
    0x80,
    0x18,
    0x00, 0x72,
    0x00, 0x00,
    0x00, 0x00,
    0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x01,
    0xDE, 0xAD, 0xBE, 0xEF,
};

static constexpr uint8_t kSmallOffset[20] = {
    0x00, 0x50,
    0x04, 0xD2,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x40,
    0x02,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
};

static constexpr uint8_t kOffsetExceedsBuffer[20] = {
    0x00, 0x50,
    0x04, 0xD2,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0xF0,
    0x02,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
};

TEST(TcpParserTest, ParsesSrcPortCorrectly) {
    auto result = parseTcpHeader(kSynPacket, sizeof(kSynPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->src_port, 12345u);
}

TEST(TcpParserTest, ParsesDstPortCorrectly) {
    auto result = parseTcpHeader(kSynPacket, sizeof(kSynPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->dst_port, 80u);
}

TEST(TcpParserTest, ParsesPortsReversedInReply) {
    auto result = parseTcpHeader(kSynAckPacket, sizeof(kSynAckPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->src_port, 80u);
    EXPECT_EQ(result->dst_port, 12345u);
}

TEST(TcpParserTest, ParsesSequenceNumberCorrectly) {
    auto result = parseTcpHeader(kSynPacket, sizeof(kSynPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->seq_num, 1u);
}

TEST(TcpParserTest, ParsesLargeSequenceNumber) {
    auto result = parseTcpHeader(kSynAckPacket, sizeof(kSynAckPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->seq_num, 0xDEADBEEFu);
}

TEST(TcpParserTest, SynFlagParsedCorrectly) {
    auto result = parseTcpHeader(kSynPacket, sizeof(kSynPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->flags & TcpFlags::SYN, TcpFlags::SYN);
    EXPECT_EQ(result->flags & TcpFlags::ACK, 0u);
}

TEST(TcpParserTest, SynAckFlagsParsedCorrectly) {
    auto result = parseTcpHeader(kSynAckPacket, sizeof(kSynAckPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->flags & TcpFlags::SYN_ACK, TcpFlags::SYN_ACK);
}

TEST(TcpParserTest, RstFlagParsedCorrectly) {
    auto result = parseTcpHeader(kRstPacket, sizeof(kRstPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->flags & TcpFlags::RST, TcpFlags::RST);
    EXPECT_EQ(result->flags & TcpFlags::SYN, 0u);
}

TEST(TcpParserTest, MalformedSynFinDetected) {
    auto result = parseTcpHeader(kSynFinPacket, sizeof(kSynFinPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->flags & TcpFlags::SYN_FIN, TcpFlags::SYN_FIN);
}

TEST(TcpParserTest, NullScanDetected) {
    auto result = parseTcpHeader(kNullScanPacket, sizeof(kNullScanPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->flags, TcpFlags::NULL_SCAN);
}

TEST(TcpParserTest, XmasScanDetected) {
    auto result = parseTcpHeader(kXmasPacket, sizeof(kXmasPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->flags & TcpFlags::XMAS, TcpFlags::XMAS);
}

TEST(TcpParserTest, ReservedBitsNotIncludedInFlags) {
    auto result = parseTcpHeader(kSynPacket, sizeof(kSynPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->flags & 0xC0, 0u);
}

TEST(TcpParserTest, DataOffsetFiveParsedCorrectly) {
    auto result = parseTcpHeader(kSynPacket, sizeof(kSynPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->data_offset, 5u);
}

TEST(TcpParserTest, DataOffsetEightParsedCorrectly) {
    auto result = parseTcpHeader(kOptionsPacket, sizeof(kOptionsPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->data_offset, 8u);
}

TEST(TcpParserTest, NoPayloadWhenHeaderFillsBuffer) {
    auto result = parseTcpHeader(kSynPacket, sizeof(kSynPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_len, 0u);
    EXPECT_EQ(result->payload, kSynPacket + 20);
}

TEST(TcpParserTest, PayloadPointerCorrectWithOptions) {
    auto result = parseTcpHeader(kOptionsPacket, sizeof(kOptionsPacket));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->payload_len, 4u);
    EXPECT_EQ(result->payload, kOptionsPacket + 32);
    EXPECT_EQ(result->payload[0], 0xDEu);
    EXPECT_EQ(result->payload[3], 0xEFu);
}

TEST(TcpParserTest, RejectsNullPointer) {
    auto result = parseTcpHeader(nullptr, 20);
    EXPECT_FALSE(result.has_value());
}

TEST(TcpParserTest, RejectsBufferSmallerThan20Bytes) {
    auto result = parseTcpHeader(kSynPacket, 19);
    EXPECT_FALSE(result.has_value());
}

TEST(TcpParserTest, RejectsDataOffsetBelowMinimum) {
    auto result = parseTcpHeader(kSmallOffset, sizeof(kSmallOffset));
    EXPECT_FALSE(result.has_value());
}

TEST(TcpParserTest, RejectsDataOffsetExceedingBuffer) {
    auto result = parseTcpHeader(kOffsetExceedsBuffer, sizeof(kOffsetExceedsBuffer));
    EXPECT_FALSE(result.has_value());
}

TEST(TcpParserTest, RejectsEmptyBuffer) {
    uint8_t buf[1] = {0x50};
    auto result = parseTcpHeader(buf, 0);
    EXPECT_FALSE(result.has_value());
}


