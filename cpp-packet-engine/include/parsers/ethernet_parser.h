#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace parsers {

static constexpr size_t ETHERNET_HEADER_SIZE = 14;
static constexpr size_t ETHERNET_MIN_SIZE    = 15;

static constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
static constexpr uint16_t ETHERTYPE_ARP  = 0x0806;
static constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;

using MACAddress = std::array<uint8_t, 6>;


struct EthernetFrame {
    MACAddress dst_mac{};   
    MACAddress src_mac{};       
    uint16_t   ethertype{0};    

    const uint8_t* payload{nullptr};
    size_t         payload_size{0};

    bool valid{false};

    static std::string macToString(const MACAddress& mac);
    std::string srcMacString() const { return macToString(src_mac); }
    std::string dstMacString() const { return macToString(dst_mac); }
};


namespace ethernet_parser {

EthernetFrame parse(const uint8_t* data, size_t size);

} 

}