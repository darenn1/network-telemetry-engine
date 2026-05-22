#include "pipeline/flow_tracker.h"

#include "parsers/tcp_parser.h" // TcpFlags

namespace pipeline {

// ---------------------------------------------------------------------------

// FlowTable

// ---------------------------------------------------------------------------

void FlowTable::update(const EnrichedFrame& frame, bool& out_is_retransmit) {

    std::lock_guard<std::mutex> lock(mutex_);

    auto& rec = table_[frame.flow_key];

    out_is_retransmit = false; // default

    // ── First packet in this flow ─────────────────────────────────────────

    if (rec.flow_key.empty()) {

        rec.flow_key = frame.flow_key;

        rec.first_seen_ms = frame.timestamp;

    }

    rec.last_seen_ms = frame.timestamp;

    // ── Byte counts ───────────────────────────────────────────────────────

    rec.total_bytes += frame.packet_size;

    if (frame.direction == parsers::Direction::Inbound) {

        rec.inbound_bytes += frame.packet_size;

    } else if (frame.direction == parsers::Direction::Outbound) {

        rec.outbound_bytes += frame.packet_size;

    }

    // ── TCP flag counts ───────────────────────────────────────────────────

    if (frame.protocol == 6) { // TCP

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

        // ── Retransmission tracking (Fix 1 + Fix 2) ───────────────────────

        if (frame.seq_num != 0) {

            auto result = rec.retransmit_set.insert(frame.seq_num);

            if (!result.second) {

                // seq_num already seen — this is a retransmission

                ++rec.retransmit_count;

                out_is_retransmit = true; // per-frame flag for JSON

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

// ---------------------------------------------------------------------------

// flow_tracker

// ---------------------------------------------------------------------------

FlowRecord flow_tracker(const EnrichedFrame& frame, FlowTable& table,

                        bool& out_is_retransmit) {

    table.update(frame, out_is_retransmit);

    return table.get(frame.flow_key);

}

} // namespace pipeline