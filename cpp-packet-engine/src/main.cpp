#include "utils/logger.h"
#include "capture/raw_socket.h"
#include "capture/packet_buffer.h"
#include "capture/capture_session.h"
#include "pipeline/filter_stage.h"
#include "pipeline/dissector_stage.h"
#include "pipeline/stats_stage.h"    
#include "pipeline/flow_tracker.h"      
#include "publisher/rabbitmq_publisher.h"

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

static std::atomic<bool>       stop_flag{false};
static std::mutex              buffer_mutex;
static std::condition_variable data_available;
static std::condition_variable space_available;

static void signalHandler(int /* sig */) {
    stop_flag.store(true, std::memory_order_relaxed);
    data_available.notify_all();
    space_available.notify_all();
}

int main() {

    std::signal(SIGINT,  signalHandler);
    std::signal(SIGTERM, signalHandler);
    std::signal(SIGPIPE, SIG_IGN);

    utils::Logger::instance().setLevel(utils::LogLevel::INFO);
    utils::log_info("Engine starting");

    const int fd = capture::openRawSocket();
    if (fd < 0) {
        utils::log_error("Failed to open raw socket — exiting");
        return 1;
    }

    const char* cap_env = std::getenv("RING_BUFFER_CAPACITY");
    const size_t capacity = cap_env ? static_cast<size_t>(std::stoul(cap_env))
                                    : 1024;

    utils::log_info("Initializing packet buffer — capacity: " +
                    std::to_string(capacity) + " slots (" +
                    std::to_string(capacity * 2048 / 1024) + " KB)");

    utils::PacketBuffer packet_buf(
        capacity,
        buffer_mutex,
        data_available,
        space_available,
        stop_flag
    );

    utils::log_info("Packet buffer initialized");

    // ── Flow table — shared state across pipeline iterations ─────────────
    pipeline::FlowTable flow_table;
 
    // ── RabbitMQ publisher ────────────────────────────────────────────────
    pipeline::PublisherConfig pub_cfg = pipeline::publisherConfigFromEnv();
    pipeline::RabbitMqPublisher publisher(pub_cfg);
 
    if (!publisher.isConnected()) {
        utils::log_error("Failed to connect to RabbitMQ — exiting");
        capture::closeRawSocket(fd);
        return 1;
    }

    utils::log_info("Spawning Thread 1 — capture");

    std::thread t1([&] {
        capture::captureLoop(fd, packet_buf, stop_flag);
    });

    utils::log_info("Thread 1 started — capturing on socket fd " +
                    std::to_string(fd));

    utils::log_info("Spawning Thread 2 — pipeline");

    std::thread t2([&] {
        utils::log_info("Thread 2: pipeline loop started");

        static uint8_t frame_buf[2040];

        pipeline::LocalIpSet local_ips = capture::getLocalIps();

        while (!stop_flag.load(std::memory_order_relaxed)) {

          auto filtered = pipeline::filter_stage(
            packet_buf, frame_buf, sizeof(frame_buf)
          );



          if (!filtered.has_value()) {
              break;   // stop_flag fired inside read()
          }

          auto dissected = pipeline::dissector_stage(*filtered, local_ips);
          if (!dissected.has_value()) {
              continue;  // malformed L3 frame — logged, get next
          }

          auto enriched = pipeline::stats_stage(*dissected);                 
          if (!enriched.has_value()) continue;                               

          bool is_retransmit = false;
          auto flow = pipeline::flow_tracker(*enriched, flow_table, is_retransmit);
 
          publisher.publish(*enriched, flow, is_retransmit);
        }

        utils::log_info("Thread 2: pipeline loop stopped");
    });

    utils::log_info("Thread 2 started — pipeline stub running");
    utils::log_info("Engine running — press Ctrl+C to stop");

    t1.join();
    t2.join();

    capture::closeRawSocket(fd);
    utils::log_info("Engine stopped cleanly");

    return 0;
}