#pragma once

#include <cstdint>
#include <cstddef>
#include <optional>

namespace parsers {

namespace TcpFlags {
    static constexpr uint8_t FIN = 0x01;
    static constexpr uint8_t SYN = 0x02;
    static constexpr uint8_t RST = 0x04;
    static constexpr uint8_t PSH = 0x08;
    static constexpr uint8_t ACK = 0x10;
    static constexpr uint8_t URG = 0x20;

    static constexpr uint8_t SYN_FIN = SYN | FIN;  
    static constexpr uint8_t SYN_ACK = SYN | ACK;  
    static constexpr uint8_t XMAS    = FIN | PSH | URG; 
    static constexpr uint8_t NULL_SCAN = 0x00;     
} 

struct TcpHeader {
    uint16_t src_port;    
    uint16_t dst_port;  
    uint32_t seq_num;     
    uint8_t  data_offset;
    uint8_t  flags;    
    uint16_t window_size;

    const uint8_t* payload;
    std::size_t    payload_len;
};

std::optional<TcpHeader> parseTcpHeader(
    const uint8_t* data,
    std::size_t    len);

} 