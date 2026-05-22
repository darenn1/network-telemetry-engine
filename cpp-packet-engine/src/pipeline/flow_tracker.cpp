#include "pipeline/flow_tracker.h"

#include "parsers/tcp_parser.h" 

namespace pipeline {

void FlowTable::update(const EnrichedFrame& frame, bool& out_is_retransmit) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& rec = table_[frame.flow_key];
    out_is_retransmit = false;

    if (rec.flow_key.empty()) {
        rec.flow_key = frame.flow_key;
        rec.first_seen_ms = frame.timestamp;
    }
    rec.last_seen_ms = frame.timestamp;

    rec.total_bytes += frame.packet_size;
    if (frame.direction == parsers::Direction::Inbound) {
        rec.inbound_bytes += frame.packet_size;
    } else if (frame.direction == parsers::Direction::Outbound) {
        rec.outbound_bytes += frame.packet_size;
    }

    if (frame.protocol == 6) { 
        if (frame.flags & parsers::TcpFlags::SYN) {
            if (frame.flags & parsers::TcpFlags::ACK) {
                ++rec.syn_ack_count;
            } else {
                ++rec.syn_count;
            }
        }
        if (frame.flags & parsers::TcpFlags::RST) {
            ++rec.rst_count;
        }
        if (frame.seq_num != 0) {
            auto result = rec.retransmit_set.insert(frame.seq_num);
            if (!result.second) {
                ++rec.retransmit_count;
                out_is_retransmit = true;

            }

        }

    }

}

FlowRecord FlowTable::get(const std::string& flow_key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = table_.find(flow_key);
    if (it == table_.end()) return FlowRecord{};
    return it->second;
}

FlowRecord flow_tracker(const EnrichedFrame& frame, FlowTable& table,
                        bool& out_is_retransmit) {
    table.update(frame, out_is_retransmit);
    return table.get(frame.flow_key);

}

} // namespace pipeline