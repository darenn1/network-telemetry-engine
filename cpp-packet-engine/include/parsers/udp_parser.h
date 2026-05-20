#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

namespace parsers {

static constexpr uint16_t UDP_PORT_DNS = 53;

struct UdpHeader {
    uint16_t src_port;  
    uint16_t dst_port; 
    uint16_t length;    
    bool     is_dns;    

    const uint8_t* payload;
    std::size_t    payload_len;
};

std::optional<UdpHeader> parseUdpHeader(
    const uint8_t* data,
    std::size_t    len);

} 