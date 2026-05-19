#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>
#include <array>

namespace parsers {

enum class Direction : uint8_t {
    Inbound,
    Outbound,
    Unknown
};

struct IpHeader {
    uint8_t  ihl;           
    uint8_t  ttl;          
    uint8_t  protocol;     
    uint32_t src_ip;      
    uint32_t dst_ip;       
    uint16_t total_length;  
    bool     checksum_ok;   
    Direction direction;    

    const uint8_t* payload;
    std::size_t    payload_len;
};

std::optional<IpHeader> parseIpHeader(
    const uint8_t* data,
    std::size_t    len,
    Direction      direction = Direction::Unknown);

} 