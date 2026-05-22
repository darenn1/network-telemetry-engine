#pragma once
#include "pipeline/dissector_stage.h"
#include "parsers/arp_parser.h"   
#include "parsers/tcp_parser.h"     // TcpFlags (if needed)
#include "parsers/ip_parser.h"      // for TTL, checksum_valid, etc.
#include <cstdint>
#include <optional>
#include <string>

namespace pipeline {


struct EnrichedFrame {
    uint64_t timestamp = 0;   

    uint32_t src_ip       = 0;   
    uint32_t dst_ip       = 0;    
    uint8_t  protocol     = 0;    
    uint16_t packet_size  = 0;    
    parsers::Direction direction = parsers::Direction::Unknown; 

    uint16_t src_port = 0;       
    uint16_t dst_port = 0;      

    uint8_t  flags   = 0;        
    uint32_t seq_num = 0;     
         

    uint32_t arp_sender_ip = 0;
    parsers::MACAddress arp_sender_mac = {};
    uint32_t arp_target_ip = 0;      // ← NEW
    uint16_t arp_opcode = 0;         // ← NEW (1=request, 2=reply)

    uint8_t icmp_type = 0;           // ← NEW
    uint8_t icmp_code = 0;

    uint8_t  ttl = 0;                // ← NEW
    parsers::MACAddress src_mac = {};   // ← NEW
    parsers::MACAddress dst_mac = {};   // ← NEW
    bool     checksum_valid = true;  // ← NEW (default true)

    bool     is_retransmit = false;  // ← NEW (set by flow_tracker)

    std::string flow_key;
};

std::optional<EnrichedFrame> stats_stage(const DissectedFrame& dissected);

} // namespace pipeline