#pragma once

#include "capture/packet_buffer.h"
#include "parsers/ethernet_parser.h"
#include <optional>

namespace pipeline {

struct FilteredFrame {
    parsers::EthernetFrame eth;
    uint64_t               capture_ts_ms; 
};

std::optional<FilteredFrame> filter_stage(
    utils::PacketBuffer& packet_buf,
    uint8_t*             frame_buf,     // caller-owned, reused buffer
    size_t               buf_capacity
);

} // namespace pipeline