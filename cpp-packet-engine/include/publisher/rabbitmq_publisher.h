#pragma once

#include "pipeline/flow_tracker.h"  // EnrichedFrame, FlowRecord

#include <amqp.h>
#include <amqp_tcp_socket.h>

#include <atomic>
#include <cstdint>
#include <string>

namespace pipeline {

// ── PublisherConfig ───────────────────────────────────────────────────────────
// Loaded from environment variables at startup. Mirrors the RabbitMQ
// definitions.json topology from Day 2.
struct PublisherConfig {
    std::string host     = "localhost";
    int         port     = 5672;
    std::string username = "guest";
    std::string password = "guest";
    std::string exchange = "raw_packets";    // topic exchange from Day 2
    std::string routing_key = "packet.raw"; // packet.# binding
    int         channel  = 1;
};

PublisherConfig publisherConfigFromEnv();

// ── RabbitMqPublisher ─────────────────────────────────────────────────────────
// Connects to RabbitMQ on construction, publishes enriched frames as JSON.
// Not thread-safe — owned and called exclusively by Thread 2.
// Delivery mode 1 (non-persistent, in-memory) — matches Day 2 definition.

class RabbitMqPublisher {
public:
    explicit RabbitMqPublisher(const PublisherConfig& config);
    ~RabbitMqPublisher();

    // Non-copyable, non-movable — AMQP connection is a resource
    RabbitMqPublisher(const RabbitMqPublisher&)            = delete;
    RabbitMqPublisher& operator=(const RabbitMqPublisher&) = delete;

    // Returns true if the connection is open and ready to publish.
    bool isConnected() const { return connected_; }

    // Serialize enriched frame + flow record to JSON and publish.
    // Returns false on publish error — caller logs and continues.
    bool publish(const EnrichedFrame& frame, const FlowRecord& flow, bool is_retransmit);

private:
    PublisherConfig     config_;
    amqp_connection_state_t conn_  = nullptr;
    amqp_socket_t*          sock_  = nullptr;
    bool                    connected_ = false;

    bool connect();
    void disconnect();

    // Build the JSON payload string from frame + flow state.
    // All fields required by Day 20 test_full_pipeline.cpp verification.
    static std::string buildJson(
        const EnrichedFrame& frame,
        const FlowRecord&    flow,
        bool                 is_retransmit);
};

} // namespace pipeline