#pragma once

#include "pipeline/stats_stage.h"

#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>

namespace pipeline {


struct FlowRecord {
    std::string flow_key;

    uint64_t first_seen_ms = 0; 
    uint64_t last_seen_ms  = 0;  

    uint64_t total_bytes   = 0; 
    uint64_t inbound_bytes = 0; 
    uint64_t outbound_bytes= 0; 

    uint32_t syn_count     = 0;  
    uint32_t syn_ack_count = 0;  
    uint32_t rst_count     = 0; 

    uint32_t retransmit_count = 0;

    std::set<uint32_t> retransmit_set;
};

class FlowTable {
public:
    void update(const EnrichedFrame& frame, bool& out_is_retransmit);

    FlowRecord get(const std::string& flow_key) const;

private:
    mutable std::mutex                            mutex_;
    std::unordered_map<std::string, FlowRecord>   table_;
};

FlowRecord flow_tracker(const EnrichedFrame& frame, FlowTable& table,
                        bool& out_is_retransmit);

} // namespace pipeline