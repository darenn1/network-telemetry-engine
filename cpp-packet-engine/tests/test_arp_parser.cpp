#include <gtest/gtest.h>
#include "parsers/arp_parser.h"

using parsers::parseArpPacket;
namespace ArpOper = parsers::ArpOper;

static constexpr uint8_t kArpRequest[28] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0xC0, 0xA8, 0x01, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
};

static constexpr uint8_t kArpReply[28] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0xC0, 0xA8, 0x01, 0x01,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0xC0, 0xA8, 0x01, 0x0A,
};

static constexpr uint8_t kSpoofedReply[28] = {
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02,
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
    0xC0, 0xA8, 0x01, 0x01,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0xC0, 0xA8, 0x01, 0x0A,
};

static constexpr uint8_t kNonEthernet[28] = {
    0x00, 0x06, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0xC0, 0xA8, 0x01, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
};

static constexpr uint8_t kNonIPv4[28] = {
    0x00, 0x01, 0x86, 0xDD, 0x06, 0x04, 0x00, 0x01,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0xC0, 0xA8, 0x01, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
};

static constexpr uint8_t kWrongHlen[28] = {
    0x00, 0x01, 0x08, 0x00, 0x08, 0x04, 0x00, 0x01,
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    0xC0, 0xA8, 0x01, 0x0A,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xC0, 0xA8, 0x01, 0x01,
};

TEST(ArpParserTest, ParsesRequestOperation) {
    auto result = parseArpPacket(kArpRequest, sizeof(kArpRequest));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->oper, ArpOper::REQUEST);
    EXPECT_FALSE(result->is_reply);
}

TEST(ArpParserTest, ParsesReplyOperation) {
    auto result = parseArpPacket(kArpReply, sizeof(kArpReply));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->oper, ArpOper::REPLY);
    EXPECT_TRUE(result->is_reply);
}

TEST(ArpParserTest, ArpOperConstantsCorrect) {
    EXPECT_EQ(ArpOper::REQUEST, 1u);
    EXPECT_EQ(ArpOper::REPLY, 2u);
}

TEST(ArpParserTest, ParsesSenderMacFromRequest) {
    auto result = parseArpPacket(kArpRequest, sizeof(kArpRequest));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->sender_mac[0], 0xAAu);
    EXPECT_EQ(result->sender_mac[1], 0xBBu);
    EXPECT_EQ(result->sender_mac[2], 0xCCu);
    EXPECT_EQ(result->sender_mac[3], 0xDDu);
    EXPECT_EQ(result->sender_mac[4], 0xEEu);
    EXPECT_EQ(result->sender_mac[5], 0xFFu);
}

TEST(ArpParserTest, ParsesSenderMacFromReply) {
    auto result = parseArpPacket(kArpReply, sizeof(kArpReply));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->sender_mac[0], 0x11u);
    EXPECT_EQ(result->sender_mac[5], 0x66u);
}

TEST(ArpParserTest, SpoofedReplyHasDifferentSenderMac) {
    auto legit = parseArpPacket(kArpReply, sizeof(kArpReply));
    auto spoof = parseArpPacket(kSpoofedReply, sizeof(kSpoofedReply));
    ASSERT_TRUE(legit.has_value());
    ASSERT_TRUE(spoof.has_value());
    EXPECT_EQ(legit->sender_ip, spoof->sender_ip);
    EXPECT_NE(legit->sender_mac, spoof->sender_mac);
}

TEST(ArpParserTest, ParsesSenderIpFromRequest) {
    auto result = parseArpPacket(kArpRequest, sizeof(kArpRequest));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->sender_ip, 0xC0A8010Au);
}

TEST(ArpParserTest, ParsesSenderIpFromReply) {
    auto result = parseArpPacket(kArpReply, sizeof(kArpReply));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->sender_ip, 0xC0A80101u);
}

TEST(ArpParserTest, ParsesTargetIpFromRequest) {
    auto result = parseArpPacket(kArpRequest, sizeof(kArpRequest));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->target_ip, 0xC0A80101u);
}

TEST(ArpParserTest, ParsesTargetIpFromReply) {
    auto result = parseArpPacket(kArpReply, sizeof(kArpReply));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->target_ip, 0xC0A8010Au);
}

TEST(ArpParserTest, TargetMacAllZeroesInRequest) {
    auto result = parseArpPacket(kArpRequest, sizeof(kArpRequest));
    ASSERT_TRUE(result.has_value());
    for (int i = 0; i < 6; ++i) {
        EXPECT_EQ(result->target_mac[i], 0x00u);
    }
}

TEST(ArpParserTest, ParsesTargetMacFromReply) {
    auto result = parseArpPacket(kArpReply, sizeof(kArpReply));
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->target_mac[0], 0xAAu);
    EXPECT_EQ(result->target_mac[5], 0xFFu);
}

TEST(ArpParserTest, RejectsNullPointer) {
    auto result = parseArpPacket(nullptr, 28);
    EXPECT_FALSE(result.has_value());
}

TEST(ArpParserTest, RejectsBufferSmallerThan28Bytes) {
    auto result = parseArpPacket(kArpRequest, 27);
    EXPECT_FALSE(result.has_value());
}

TEST(ArpParserTest, RejectsNonEthernetHtype) {
    auto result = parseArpPacket(kNonEthernet, sizeof(kNonEthernet));
    EXPECT_FALSE(result.has_value());
}

TEST(ArpParserTest, RejectsNonIPv4Ptype) {
    auto result = parseArpPacket(kNonIPv4, sizeof(kNonIPv4));
    EXPECT_FALSE(result.has_value());
}

TEST(ArpParserTest, RejectsWrongHlen) {
    auto result = parseArpPacket(kWrongHlen, sizeof(kWrongHlen));
    EXPECT_FALSE(result.has_value());
}

TEST(ArpParserTest, RejectsEmptyBuffer) {
    uint8_t buf[1] = {0x00};
    auto result = parseArpPacket(buf, 0);
    EXPECT_FALSE(result.has_value());
}