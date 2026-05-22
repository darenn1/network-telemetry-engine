#pragma once

#include "pipeline/stats_stage.h"

#include <cstdint>
#include <mutex>
#include <set>
#include <string>
#include <unordered_map>

namespace pipeline {

// ── FlowRecord ────────────────────────────────────────────────────────────────
// Stateful per-flow record accumulated across packets.
// Fields required by Rules 8, 10, 13:
//   Rule 8  (failed_handshake):  syn_count, syn_ack_count
//   Rule 10 (long_lived_idle):   first_seen, last_seen, total_bytes
//   Rule 13 (retransmission):    retransmit_set (seq numbers seen)
// Also used by Rule 14 (bandwidth spike) and Rule 15 (port asymmetry)
// via total_bytes and the direction breakdown.

struct FlowRecord {
    std::string flow_key;

    uint64_t first_seen_ms = 0;  // capture_ts_ms of first packet in flow
    uint64_t last_seen_ms  = 0;  // capture_ts_ms of most recent packet

    uint64_t total_bytes   = 0;  // cumulative ip.total_length — Rules 10,14
    uint64_t inbound_bytes = 0;  // Direction::Inbound bytes — Rule 15
    uint64_t outbound_bytes= 0;  // Direction::Outbound bytes — Rule 15

    uint32_t syn_count     = 0;  // Rule 8: SYN packets seen
    uint32_t syn_ack_count = 0;  // Rule 8: SYN+ACK packets seen
    uint32_t rst_count     = 0;  // Rule 6 supplement

    uint32_t retransmit_count = 0;

    std::set<uint32_t> retransmit_set; // Rule 13: seq numbers seen; size = retransmit count
};

// ── FlowTable ─────────────────────────────────────────────────────────────────
// Hash map keyed by flow_key string.  Thread-safe — rabbitmq_publisher reads
// flow state from Thread 2 (pipeline) on the same thread; no concurrent
// readers in the current two-thread design, but the mutex is kept for
// correctness when the pipeline is extended.

class FlowTable {
public:
    // Update (or create) the FlowRecord for the frame's flow_key.
    // Called by flow_tracker for every enriched frame.
    void update(const EnrichedFrame& frame, bool& out_is_retransmit);

    // Retrieve a copy of the FlowRecord for a given flow_key.
    // Returns a default-constructed record if the key is not present.
    FlowRecord get(const std::string& flow_key) const;

private:
    mutable std::mutex                            mutex_;
    std::unordered_map<std::string, FlowRecord>   table_;
};

// flow_tracker updates the FlowTable with the enriched frame and returns
// the current FlowRecord for that flow — used by rabbitmq_publisher to
// include flow state in the JSON payload.
FlowRecord flow_tracker(const EnrichedFrame& frame, FlowTable& table,
                        bool& out_is_retransmit);

} // namespace pipeline