#include <gtest/gtest.h>
#include "parsers/ethernet_parser.h"

using namespace parsers;


static const uint8_t IPV4_FRAME[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08, 0x00,
    0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46,
    0x40, 0x00, 0x40, 0x06, 0xb8, 0xfa,
    0xc0, 0xa8, 0x01, 0x65, 0x08, 0x08,
    0x08, 0x08
};
static constexpr size_t IPV4_FRAME_SIZE = sizeof(IPV4_FRAME);

static const uint8_t ARP_FRAME[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0xad, 0xbe, 0xef, 0x00, 0x01,
    0x08, 0x06,
    0x00, 0x01, 0x08, 0x00, 0x06, 0x04,
    0x00, 0x01, 0xde, 0xad, 0xbe, 0xef,
    0x00, 0x01, 0xc0, 0xa8, 0x01, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xc0, 0xa8, 0x01, 0x65
};
static constexpr size_t ARP_FRAME_SIZE = sizeof(ARP_FRAME);

static const uint8_t MIN_FRAME[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02,  
    0x08, 0x00,                           
    0x45                                  
};
static constexpr size_t MIN_FRAME_SIZE = sizeof(MIN_FRAME);

static const uint8_t TOO_SHORT_FRAME[] = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    0x08   
};
static constexpr size_t TOO_SHORT_SIZE = sizeof(TOO_SHORT_FRAME);


TEST(EthernetParserTest, IPv4EtherTypeCorrect) {
    auto frame = ethernet_parser::parse(IPV4_FRAME, IPV4_FRAME_SIZE);
    EXPECT_TRUE(frame.valid);
    EXPECT_EQ(frame.ethertype, ETHERTYPE_IPV4);
}

TEST(EthernetParserTest, IPv4SrcMACCorrect) {
    auto frame = ethernet_parser::parse(IPV4_FRAME, IPV4_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);

    EXPECT_EQ(frame.src_mac[0], 0x11);
    EXPECT_EQ(frame.src_mac[1], 0x22);
    EXPECT_EQ(frame.src_mac[2], 0x33);
    EXPECT_EQ(frame.src_mac[3], 0x44);
    EXPECT_EQ(frame.src_mac[4], 0x55);
    EXPECT_EQ(frame.src_mac[5], 0x66);
}

TEST(EthernetParserTest, IPv4DstMACCorrect) {
    auto frame = ethernet_parser::parse(IPV4_FRAME, IPV4_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);

    EXPECT_EQ(frame.dst_mac[0], 0xaa);
    EXPECT_EQ(frame.dst_mac[1], 0xbb);
    EXPECT_EQ(frame.dst_mac[2], 0xcc);
    EXPECT_EQ(frame.dst_mac[3], 0xdd);
    EXPECT_EQ(frame.dst_mac[4], 0xee);
    EXPECT_EQ(frame.dst_mac[5], 0xff);
}

TEST(EthernetParserTest, IPv4MACStringFormat) {
    auto frame = ethernet_parser::parse(IPV4_FRAME, IPV4_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);
    EXPECT_EQ(frame.srcMacString(), "11:22:33:44:55:66");
    EXPECT_EQ(frame.dstMacString(), "aa:bb:cc:dd:ee:ff");
}

TEST(EthernetParserTest, IPv4PayloadPointerCorrect) {
    auto frame = ethernet_parser::parse(IPV4_FRAME, IPV4_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);

    ASSERT_NE(frame.payload, nullptr);
    EXPECT_EQ(frame.payload, IPV4_FRAME + ETHERNET_HEADER_SIZE);

    EXPECT_EQ(frame.payload[0], 0x45);
}

TEST(EthernetParserTest, IPv4PayloadSizeCorrect) {
    auto frame = ethernet_parser::parse(IPV4_FRAME, IPV4_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);
    EXPECT_EQ(frame.payload_size, IPV4_FRAME_SIZE - ETHERNET_HEADER_SIZE);
}


TEST(EthernetParserTest, ARPEtherTypeCorrect) {
    auto frame = ethernet_parser::parse(ARP_FRAME, ARP_FRAME_SIZE);
    EXPECT_TRUE(frame.valid);
    EXPECT_EQ(frame.ethertype, ETHERTYPE_ARP);
}

TEST(EthernetParserTest, ARPDstMACIsBroadcast) {
    auto frame = ethernet_parser::parse(ARP_FRAME, ARP_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);

    for (int i = 0; i < 6; i++) {
        EXPECT_EQ(frame.dst_mac[i], 0xff)
            << "Broadcast MAC byte " << i << " is not 0xff";
    }
    EXPECT_EQ(frame.dstMacString(), "ff:ff:ff:ff:ff:ff");
}

TEST(EthernetParserTest, ARPSrcMACCorrect) {
    auto frame = ethernet_parser::parse(ARP_FRAME, ARP_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);

    EXPECT_EQ(frame.src_mac[0], 0xde);
    EXPECT_EQ(frame.src_mac[1], 0xad);
    EXPECT_EQ(frame.src_mac[2], 0xbe);
    EXPECT_EQ(frame.src_mac[3], 0xef);
    EXPECT_EQ(frame.src_mac[4], 0x00);
    EXPECT_EQ(frame.src_mac[5], 0x01);
}

TEST(EthernetParserTest, ARPPayloadPointerCorrect) {
    auto frame = ethernet_parser::parse(ARP_FRAME, ARP_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);

    ASSERT_NE(frame.payload, nullptr);
    EXPECT_EQ(frame.payload, ARP_FRAME + ETHERNET_HEADER_SIZE);

    EXPECT_EQ(frame.payload[0], 0x00);
    EXPECT_EQ(frame.payload[1], 0x01);
}

TEST(EthernetParserTest, ARPPayloadSizeCorrect) {
    auto frame = ethernet_parser::parse(ARP_FRAME, ARP_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);
    EXPECT_EQ(frame.payload_size, ARP_FRAME_SIZE - ETHERNET_HEADER_SIZE);
}


TEST(EthernetParserTest, IPv4EtherTypeIsNotARP) {
    auto frame = ethernet_parser::parse(IPV4_FRAME, IPV4_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);
    EXPECT_NE(frame.ethertype, ETHERTYPE_ARP)
        << "IPv4 frame must not be classified as ARP";
}

TEST(EthernetParserTest, ARPEtherTypeIsNotIPv4) {
    auto frame = ethernet_parser::parse(ARP_FRAME, ARP_FRAME_SIZE);
    ASSERT_TRUE(frame.valid);
    EXPECT_NE(frame.ethertype, ETHERTYPE_IPV4)
        << "ARP frame must not be classified as IPv4";
}


TEST(EthernetParserTest, MinimumValidFrameParsesCorrectly) {
    auto frame = ethernet_parser::parse(MIN_FRAME, MIN_FRAME_SIZE);
    EXPECT_TRUE(frame.valid);
    EXPECT_EQ(frame.ethertype, ETHERTYPE_IPV4);
    EXPECT_EQ(frame.payload_size, 1u);
    EXPECT_EQ(frame.payload[0], 0x45);
}


TEST(EthernetParserTest, TooShortFrameIsInvalid) {
    auto frame = ethernet_parser::parse(TOO_SHORT_FRAME, TOO_SHORT_SIZE);
    EXPECT_FALSE(frame.valid)
        << "Frame shorter than ETHERNET_MIN_SIZE must be invalid";
    EXPECT_EQ(frame.payload, nullptr);
    EXPECT_EQ(frame.ethertype, 0);
}

TEST(EthernetParserTest, ExactlyHeaderSizeIsInvalid) {
    auto frame = ethernet_parser::parse(IPV4_FRAME, ETHERNET_HEADER_SIZE);
    EXPECT_FALSE(frame.valid)
        << "Frame with no payload must be invalid";
}

TEST(EthernetParserTest, NullPointerIsInvalid) {
    auto frame = ethernet_parser::parse(nullptr, 100);
    EXPECT_FALSE(frame.valid)
        << "Null data pointer must produce invalid frame";
    EXPECT_EQ(frame.payload, nullptr);
}

TEST(EthernetParserTest, ZeroSizeIsInvalid) {
    auto frame = ethernet_parser::parse(IPV4_FRAME, 0);
    EXPECT_FALSE(frame.valid)
        << "Zero size must produce invalid frame";
}


TEST(EthernetParserTest, EtherTypeBigEndianCorrect) {
    uint8_t frame[15] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  
        0x08, 0x00,                            
        0x45                                   
    };
    auto result = ethernet_parser::parse(frame, sizeof(frame));
    ASSERT_TRUE(result.valid);
    EXPECT_EQ(result.ethertype, 0x0800u)
        << "EtherType must be parsed big-endian: 0x08=high, 0x00=low";
    EXPECT_NE(result.ethertype, 0x0008u)
        << "Little-endian parsing would give wrong EtherType";
}