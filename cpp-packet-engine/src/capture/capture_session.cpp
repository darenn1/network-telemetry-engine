#include "capture/capture_session.h"
#include "utils/logger.h"
#include "utils/hex_dump.h"

#include <cerrno>
#include <cstring>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace capture {

static constexpr int BATCH_DRAIN = 64;

static constexpr int EPOLL_TIMEOUT_MS = 200;

static constexpr size_t FRAME_BUF_SIZE = 2040;

void captureLoop(
    int                  fd,
    utils::PacketBuffer& packet_buf,
    std::atomic<bool>&   stop_flag
) {
#ifndef __linux__
    utils::log_error("captureLoop: Linux-only — AF_PACKET not available on this OS");
    return;
#else
    const int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        utils::log_error("captureLoop: epoll_create1 failed: " +
                         std::string(strerror(errno)));
        return;
    }

    struct epoll_event ev{};
    ev.events  = EPOLLIN;   
    ev.data.fd = fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        utils::log_error("captureLoop: epoll_ctl failed: " +
                         std::string(strerror(errno)));
        close(epoll_fd);
        return;
    }

    utils::log_info("captureLoop: epoll ready — Level-Triggered, "
                    "BATCH_DRAIN=" + std::to_string(BATCH_DRAIN) +
                    ", timeout=" + std::to_string(EPOLL_TIMEOUT_MS) + "ms");
    utils::log_info("captureLoop: capture loop started");

    uint64_t frame_count = 0;
    uint8_t frame_buf[FRAME_BUF_SIZE];

    struct epoll_event events[1];

    while (!stop_flag.load(std::memory_order_relaxed)) {

        const int n = epoll_wait(epoll_fd, events, 1, EPOLL_TIMEOUT_MS);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            utils::log_error("captureLoop: epoll_wait error: " +
                             std::string(strerror(errno)));
            break;
        }

        if (n == 0) {
            continue;
        }

        for (int i = 0; i < BATCH_DRAIN; i++) {

            const ssize_t bytes = recvfrom(
                fd,
                frame_buf,
                sizeof(frame_buf),
                MSG_DONTWAIT,
                nullptr,
                nullptr
            );

            if (bytes < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                utils::log_error("captureLoop: recvfrom error: " +
                                 std::string(strerror(errno)));
                break;
            }

            if (bytes == 0) {
                break;
            }
            frame_count++;

            
            if (frame_count % 200 == 0) {
                const uint16_t ethertype = utils::logFrameSummary(
                    frame_buf,
                    static_cast<size_t>(bytes),
                    0 
                );
                (void)ethertype;
            }

            
            if (static_cast<size_t>(bytes) >= 14) {
                const uint16_t ethertype = static_cast<uint16_t>(
                    (frame_buf[12] << 8) | frame_buf[13]
                );
                if (ethertype == 0x0806) {        
                    utils::hexDump(
                        frame_buf,
                        static_cast<size_t>(bytes),
                        "ARP FRAME"
                    );
                }
            }

            
            if (frame_count % 1000 == 0) {
                if (static_cast<size_t>(bytes) >= 14) {
                    const uint16_t ethertype = static_cast<uint16_t>(
                        (frame_buf[12] << 8) | frame_buf[13]
                    );
                    if (ethertype == 0x0800) {       
                        utils::hexDump(
                            frame_buf,
                            static_cast<size_t>(bytes),
                            "IPv4 SAMPLE (frame " + std::to_string(frame_count) + ")"
                        );
                    }
                }
            }

            if (!packet_buf.write(frame_buf, static_cast<size_t>(bytes))) {
                utils::log_warn("captureLoop: write() returned false — stopping");
                goto cleanup;
            }
        }
    }

cleanup:
    close(epoll_fd);
    utils::log_info("captureLoop: capture loop stopped — epoll fd closed");

#endif 
}

} 
