#include <gtest/gtest.h>
#include "utils/checksum.h"

static constexpr uint8_t kGoodHeader[20] = {
    0x45, 0x00, 0x00, 0x34,  
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0xAF, 0x1A,
    0xC0, 0xA8, 0x01, 0x01, 
    0x0A, 0x00, 0x00, 0x01,  
};

static constexpr uint8_t kZeroedChecksumHeader[20] = {
    0x45, 0x00, 0x00, 0x34,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0x00, 0x00, 
    0xC0, 0xA8, 0x01, 0x01,
    0x0A, 0x00, 0x00, 0x01,
};

static constexpr uint8_t kBadHeader[20] = {
    0x45, 0x00, 0x00, 0x34,
    0x00, 0x00, 0x00, 0x00,
    0x40, 0x06, 0xDE, 0xAD,  
    0xC0, 0xA8, 0x01, 0x01,
    0x0A, 0x00, 0x00, 0x01,
};

// ---------------------------------------------------------------------------
// internetChecksum tests
// ---------------------------------------------------------------------------

TEST(ChecksumTest, AllZeroesIsZero) {
    uint8_t buf[4] = {0, 0, 0, 0};
    uint16_t cs = utils::internetChecksum(buf, 4);
    EXPECT_EQ(cs, 0xFFFFu);
}

TEST(ChecksumTest, KnownGoodHeaderChecksumFieldIsCorrect) {
    uint16_t cs = utils::internetChecksum(kGoodHeader, 20);
    EXPECT_EQ(cs, 0x0000u);
}

TEST(ChecksumTest, ComputedChecksumMatchesKnownValue) {
    uint16_t cs = utils::internetChecksum(kZeroedChecksumHeader, 20);
    EXPECT_EQ(cs, 0xAF1Au);
}

TEST(ChecksumTest, BadChecksumIsNonZero) {
    uint16_t cs = utils::internetChecksum(kBadHeader, 20);
    EXPECT_NE(cs, 0x0000u);
}

TEST(ChecksumTest, OddLengthBuffer) {
    uint8_t buf[3] = {0x00, 0x01, 0x02};
    uint16_t cs = utils::internetChecksum(buf, 3);
    EXPECT_EQ(cs, 0xFDFEu);
}

TEST(ChecksumTest, SingleByteBuffer) {
    uint8_t buf[1] = {0xFF};
    uint16_t cs = utils::internetChecksum(buf, 1);
    EXPECT_EQ(cs, 0x00FFu);
}

TEST(ChecksumTest, TwoByteKnownValue) {
    uint8_t buf[2] = {0x45, 0x00};
    uint16_t cs = utils::internetChecksum(buf, 2);
    EXPECT_EQ(cs, 0xBAFFu);
}

TEST(ChecksumTest, CarryFoldingWorksCorrectly) {
    uint8_t buf[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    uint16_t cs = utils::internetChecksum(buf, 4);
    EXPECT_EQ(cs, 0x0000u);
}

// ---------------------------------------------------------------------------
// verifyIpChecksum tests
// ---------------------------------------------------------------------------

TEST(VerifyChecksumTest, GoodHeaderReturnsTrue) {
    EXPECT_TRUE(utils::verifyIpChecksum(kGoodHeader, 20));
}

TEST(VerifyChecksumTest, BadChecksumReturnsFalse) {
    EXPECT_FALSE(utils::verifyIpChecksum(kBadHeader, 20));
}

TEST(VerifyChecksumTest, ZeroedChecksumReturnsFalse) {
    // A header with the checksum field zeroed is invalid.
    EXPECT_FALSE(utils::verifyIpChecksum(kZeroedChecksumHeader, 20));
}