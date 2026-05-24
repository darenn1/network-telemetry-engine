#include "publisher/rabbitmq_publisher.h"
#include "utils/logger.h"
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <thread>
#include <chrono>

namespace pipeline {
 
PublisherConfig publisherConfigFromEnv() {
    PublisherConfig cfg;
    if (const char* v = std::getenv("RABBITMQ_HOST"))        cfg.host        = v;
    if (const char* v = std::getenv("RABBITMQ_PORT"))        cfg.port        = std::atoi(v);
    if (const char* v = std::getenv("RABBITMQ_USER"))        cfg.username    = v;
    if (const char* v = std::getenv("RABBITMQ_PASS"))        cfg.password    = v;
    if (const char* v = std::getenv("RABBITMQ_EXCHANGE"))    cfg.exchange    = v;
    if (const char* v = std::getenv("RABBITMQ_ROUTING_KEY")) cfg.routing_key = v;
    return cfg;
}
 
static std::string ipToStr(uint32_t ip_host) {
    uint32_t ip_net = htonl(ip_host);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip_net, buf, sizeof(buf));
    return std::string(buf);
}
 
static std::string macToStr(const parsers::MACAddress& mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}
 
static const char* directionStr(parsers::Direction d) {
    switch (d) {
        case parsers::Direction::Inbound:  return "\"inbound\"";
        case parsers::Direction::Outbound: return "\"outbound\"";
        default:                           return "null";
    }
}
 
static std::string protocolToStr(uint8_t proto) {
    switch (proto) {
        case 6:  return "TCP";
        case 17: return "UDP";
        case 1:  return "ICMP";
        case 0:  return "ARP";
        default: return "OTHER";
    }
}
 
std::string RabbitMqPublisher::buildJson(
    const EnrichedFrame& f,
    const FlowRecord&    flow,
    bool                 is_retransmit)
{
    std::ostringstream j;
    j << "{"
      << "\"flow_key\":"       << "\"" << f.flow_key << "\","
      << "\"timestamp\":"      << f.timestamp << ","
 
      << "\"src_ip\":"         << "\"" << ipToStr(f.src_ip) << "\","
      << "\"dst_ip\":"         << "\"" << ipToStr(f.dst_ip) << "\","
      << "\"protocol\":"       << "\"" << protocolToStr(f.protocol) << "\","
      << "\"packet_size\":"    << f.packet_size << ","
      << "\"direction\":"      << directionStr(f.direction) << ","
      << "\"ttl\":"            << static_cast<int>(f.ttl) << ","
      << "\"src_mac\":"        << "\"" << macToStr(f.src_mac) << "\","
      << "\"dst_mac\":"        << "\"" << macToStr(f.dst_mac) << "\","
      << "\"checksum_valid\":" << (f.checksum_valid ? "true" : "false") << ","
 
      << "\"src_port\":"       << f.src_port << ","
      << "\"dst_port\":"       << f.dst_port << ","
 
      << "\"flags\":"          << static_cast<int>(f.flags) << ","
      << "\"seq_num\":"        << f.seq_num << ","
      << "\"is_retransmit\":"  << (is_retransmit ? "true" : "false") << ","
 
      << "\"icmp_type\":"      << static_cast<int>(f.icmp_type) << ","
      << "\"icmp_code\":"      << static_cast<int>(f.icmp_code) << ","
 
      << "\"arp_opcode\":"     << f.arp_opcode << ","
      << "\"arp_sender_ip\":"  << "\"" << ipToStr(f.arp_sender_ip) << "\","
      << "\"arp_sender_mac\":" << "\"" << macToStr(f.arp_sender_mac) << "\","
      << "\"arp_target_ip\":"  << "\"" << ipToStr(f.arp_target_ip) << "\","
 
      << "\"first_seen\":"     << flow.first_seen_ms << ","
      << "\"last_seen\":"      << flow.last_seen_ms << ","
      << "\"total_bytes\":"    << flow.total_bytes << ","
      << "\"inbound_bytes\":"  << flow.inbound_bytes << ","
      << "\"outbound_bytes\":" << flow.outbound_bytes << ","
      << "\"syn_count\":"      << flow.syn_count << ","
      << "\"syn_ack_count\":"  << flow.syn_ack_count << ","
      << "\"rst_count\":"      << flow.rst_count
      << "}";
 
    return j.str();
}
 
bool RabbitMqPublisher::connect() {
    if (conn_) disconnect();
 
    constexpr int     MAX_ATTEMPTS   = 3;
    constexpr int     RETRY_DELAY_S  = 2;
 
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt) {
 
        conn_ = amqp_new_connection();
        sock_ = amqp_tcp_socket_new(conn_);
        if (!sock_) {
            utils::log_error("rabbitmq_publisher: amqp_tcp_socket_new failed");
            amqp_destroy_connection(conn_);
            conn_ = nullptr;
            return false;   // allocation failure — no point retrying
        }
 
        int rc = amqp_socket_open(sock_, config_.host.c_str(), config_.port);
        if (rc != AMQP_STATUS_OK) {
            utils::log_warn("rabbitmq_publisher: connect attempt " +
                            std::to_string(attempt) + "/" +
                            std::to_string(MAX_ATTEMPTS) +
                            " failed to " + config_.host + ":" +
                            std::to_string(config_.port) +
                            " — retrying in " +
                            std::to_string(RETRY_DELAY_S) + "s");
            amqp_destroy_connection(conn_);
            conn_ = nullptr;
            sock_ = nullptr;
            if (attempt < MAX_ATTEMPTS)
                std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_S));
            continue;
        }
 
        {
            int flag = 1;
            int sock_fd = amqp_socket_get_sockfd(sock_);
            if (setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY,
                           &flag, sizeof(flag)) != 0) {
                utils::log_warn("rabbitmq_publisher: setsockopt TCP_NODELAY failed (non-fatal)");
            }
        }
 
        amqp_rpc_reply_t reply = amqp_login(
            conn_,
            "/",
            0,
            131072,
            60,
            AMQP_SASL_METHOD_PLAIN,
            config_.username.c_str(),
            config_.password.c_str());
 
        if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
            utils::log_warn("rabbitmq_publisher: login failed on attempt " +
                            std::to_string(attempt));
            amqp_destroy_connection(conn_);
            conn_ = nullptr;
            sock_ = nullptr;
            if (attempt < MAX_ATTEMPTS)
                std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_S));
            continue;
        }
 
        amqp_channel_open(conn_, config_.channel);
        reply = amqp_get_rpc_reply(conn_);
        if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
            utils::log_warn("rabbitmq_publisher: channel open failed on attempt " +
                            std::to_string(attempt));
            amqp_connection_close(conn_, AMQP_REPLY_SUCCESS);
            amqp_destroy_connection(conn_);
            conn_ = nullptr;
            sock_ = nullptr;
            if (attempt < MAX_ATTEMPTS)
                std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_S));
            continue;
        }
 
        amqp_confirm_select(conn_, config_.channel);
        reply = amqp_get_rpc_reply(conn_);
        if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
            utils::log_warn("rabbitmq_publisher: confirm.select failed on attempt " +
                            std::to_string(attempt));
            amqp_channel_close(conn_, config_.channel, AMQP_REPLY_SUCCESS);
            amqp_connection_close(conn_, AMQP_REPLY_SUCCESS);
            amqp_destroy_connection(conn_);
            conn_ = nullptr;
            sock_ = nullptr;
            if (attempt < MAX_ATTEMPTS)
                std::this_thread::sleep_for(std::chrono::seconds(RETRY_DELAY_S));
            continue;
        }
 
        utils::log_info("rabbitmq_publisher: connected to " +
                        config_.host + ":" + std::to_string(config_.port) +
                        " exchange=" + config_.exchange +
                        " (attempt " + std::to_string(attempt) + ")");
        return true;
    }
 
    utils::log_error("rabbitmq_publisher: all " +
                     std::to_string(MAX_ATTEMPTS) +
                     " connection attempts failed");
    return false;
}
 
void RabbitMqPublisher::disconnect() {
    if (conn_) {
        amqp_channel_close(conn_, config_.channel, AMQP_REPLY_SUCCESS);
        amqp_connection_close(conn_, AMQP_REPLY_SUCCESS);
        amqp_destroy_connection(conn_);
        conn_ = nullptr;
        sock_ = nullptr;
    }
}
 
RabbitMqPublisher::RabbitMqPublisher(const PublisherConfig& config, std::atomic<bool>&     stop_flag)
    : config_(config), stop_flag_(stop_flag), connected_(false)
{
    connected_ = connect();
}
 
RabbitMqPublisher::~RabbitMqPublisher() {
    disconnect();
}
 
bool RabbitMqPublisher::publish(
    const EnrichedFrame& frame,
    const FlowRecord&    flow,
    bool                 is_retransmit)
{
    if (frame.protocol != 1  &&
        frame.protocol != 6  &&
        frame.protocol != 17 &&
        frame.protocol != 0) {
        return true;
    }

    if (!connected_) {
        utils::log_warn("rabbitmq_publisher: attempting reconnect...");
        connected_ = connect();
        if (!connected_) {
            utils::log_error("rabbitmq_publisher: reconnect failed — frame dropped");
            return false;
        }
    }

    const std::string json = buildJson(frame, flow, is_retransmit);

    amqp_basic_properties_t props{};
    props._flags        = AMQP_BASIC_DELIVERY_MODE_FLAG |
                          AMQP_BASIC_CONTENT_TYPE_FLAG;
    props.delivery_mode = 1;
    props.content_type  = amqp_cstring_bytes("application/json");

    int rc = amqp_basic_publish(
        conn_,
        config_.channel,
        amqp_cstring_bytes(config_.exchange.c_str()),
        amqp_cstring_bytes(config_.routing_key.c_str()),
        0, 0, &props,
        amqp_cstring_bytes(json.c_str()));

    if (rc != AMQP_STATUS_OK) {
        utils::log_error("rabbitmq_publisher: publish failed (rc=" +
                         std::to_string(rc) + ")");
        connected_ = false;
        return false;
    }

    constexpr int MAX_CONFIRM_WAIT_MS = 5000;
    constexpr int POLL_INTERVAL_MS    = 50;
    int           waited_ms           = 0;
    bool          confirmed           = false;

    while (waited_ms < MAX_CONFIRM_WAIT_MS) {
        amqp_frame_t   confirm_frame{};
        struct timeval timeout{
            .tv_sec  = 0,
            .tv_usec = POLL_INTERVAL_MS * 1000
        };

        int wait_rc = amqp_simple_wait_frame_noblock(
            conn_, &confirm_frame, &timeout);

        if (wait_rc == AMQP_STATUS_TIMEOUT) {
            waited_ms += POLL_INTERVAL_MS;
            if (stop_flag_.load(std::memory_order_relaxed)) {
                return false;
            }
            continue;
        }

        if (wait_rc != AMQP_STATUS_OK) {
            utils::log_error("rabbitmq_publisher: confirm wait error rc=" +
                             std::to_string(wait_rc));
            connected_ = false;
            return false;
        }

        if (confirm_frame.frame_type == AMQP_FRAME_METHOD) {
            if (confirm_frame.payload.method.id == AMQP_BASIC_ACK_METHOD) {
                confirmed = true;
                break;
            } else if (confirm_frame.payload.method.id ==
                       AMQP_BASIC_NACK_METHOD) {
                utils::log_error("rabbitmq_publisher: Basic.Nack received");
                return false;
            }
        }

        waited_ms += POLL_INTERVAL_MS;
    }

    if (!confirmed) {
        utils::log_error("rabbitmq_publisher: confirm timeout after " +
                         std::to_string(MAX_CONFIRM_WAIT_MS) + "ms");
        connected_ = false;
        return false;
    }

    return true;
}
}