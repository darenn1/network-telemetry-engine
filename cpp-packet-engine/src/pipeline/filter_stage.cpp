#include "pipeline/filter_stage.h"
#include "capture/packet_buffer.h"
#include "utils/logger.h"

namespace pipeline {

std::optional<FilteredFrame> filter_stage(
    utils::PacketBuffer& packet_buf,
    uint8_t*             frame_buf,
    size_t               buf_capacity)
{
    size_t   frame_size = 0;
    uint64_t capture_ts_ms = 0;

    if (!packet_buf.read(frame_buf, frame_size, capture_ts_ms)) {
        return std::nullopt; 
    }

    if (frame_size < parsers::ETHERNET_MIN_SIZE) {
        utils::log_warn("filter_stage: frame too short (" +
                        std::to_string(frame_size) + " bytes) — dropped");
        return std::nullopt;
    }

    if (frame_size > buf_capacity) {
        utils::log_warn("filter_stage: frame exceeds buffer capacity — dropped");
        return std::nullopt;
    }

    auto eth = parsers::ethernet_parser::parse(frame_buf, frame_size);

    if (!eth.valid) {
        utils::log_warn("filter_stage: invalid Ethernet frame — dropped");
        return std::nullopt;
    }

    if (eth.payload_size == 0) {
        utils::log_warn("filter_stage: empty payload — dropped");
        return std::nullopt;
    }

    if (eth.ethertype != parsers::ETHERTYPE_IPV4 &&
        eth.ethertype != parsers::ETHERTYPE_ARP) {
        return std::nullopt;   
    }

    return FilteredFrame{
        .eth           = eth,
        .capture_ts_ms = capture_ts_ms
    };
  }
}