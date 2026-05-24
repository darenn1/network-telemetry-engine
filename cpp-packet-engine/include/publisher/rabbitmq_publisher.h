#pragma once

#include "pipeline/flow_tracker.h"  // EnrichedFrame, FlowRecord

#include <amqp.h>
#include <amqp_tcp_socket.h>

#include <atomic>
#include <cstdint>
#include <string>

namespace pipeline {

struct PublisherConfig {
    std::string host     = "localhost";
    int         port     = 5672;
    std::string username = "guest";
    std::string password = "guest";
    std::string exchange = "raw_packets";  
    std::string routing_key = "packet.raw"; 
    int         channel  = 1;
};

PublisherConfig publisherConfigFromEnv();


class RabbitMqPublisher {
public:
    explicit RabbitMqPublisher(const PublisherConfig& config, std::atomic<bool>&     stop_flag);
    ~RabbitMqPublisher();

    RabbitMqPublisher(const RabbitMqPublisher&)            = delete;
    RabbitMqPublisher& operator=(const RabbitMqPublisher&) = delete;

    bool isConnected() const { return connected_; }

    bool publish(const EnrichedFrame& frame, const FlowRecord& flow, bool is_retransmit);

private:
    PublisherConfig     config_;
    std::atomic<bool>&  stop_flag_;
    amqp_connection_state_t conn_  = nullptr;
    amqp_socket_t*          sock_  = nullptr;
    bool                    connected_ = false;

    bool connect();
    void disconnect();

    static std::string buildJson(
        const EnrichedFrame& frame,
        const FlowRecord&    flow,
        bool                 is_retransmit);
};

} // namespace pipeline