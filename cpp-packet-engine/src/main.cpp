#include "utils/logger.h"
#include "capture/raw_socket.h"
#include "capture/packet_buffer.h"
#include "capture/capture_session.h"

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

    utils::log_info("Spawning Thread 1 — capture");

    std::thread t1([&] {
        capture::captureLoop(fd, packet_buf, stop_flag);
    });

    utils::log_info("Thread 1 started — capturing on socket fd " +
                    std::to_string(fd));

    utils::log_info("Spawning Thread 2 — pipeline (stub)");

    std::thread t2([&] {
        utils::log_info("Thread 2: pipeline loop started (stub — Day 8)");

        uint8_t  frame[2048];
        size_t   frame_size = 0;
        uint64_t timestamp  = 0;

        uint64_t count = 0;
        while (!stop_flag.load(std::memory_order_relaxed)) {

            if (!packet_buf.read(frame, frame_size, timestamp)) {
                break;  // stop_flag fired
            }

            // DAY 8:  frame discarded — pipeline not built yet
            // DAY 16: filter_stage::process(frame, frame_size)
            // DAY 17: dissector_stage::process(frame, frame_size, timestamp)
            // DAY 18: stats_stage::process(frame, frame_size, timestamp)
            // DAY 19: flow_tracker::process(...)
            //         rabbitmq_publisher::publish(...)
            // DAY 20: all stages wired, test_full_pipeline.cpp confirms
            count++;
            if (count % 10 == 0)
                utils::log_info("Thread 2: frames received: " + std::to_string(count));
            (void)timestamp;
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