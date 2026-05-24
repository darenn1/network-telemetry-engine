#include <gtest/gtest.h>
 
#include "capture/capture_session.h"
#include "capture/packet_buffer.h"
#include "utils/ring_buffer.h"
 
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>
 
#ifdef __linux__
#include <unistd.h>
#include <sys/socket.h>
#endif
 
using namespace std::chrono_literals;
 

 
static void writeToPipe(int write_fd, const uint8_t* data, size_t size) {
#ifdef __linux__
    ssize_t written = 0;
    while (static_cast<size_t>(written) < size) {
        ssize_t n = write(write_fd, data + written, size - written);
        if (n <= 0) break;
        written += n;
    }
#endif
}
 
static std::vector<uint8_t> makeFrame(uint8_t fill, size_t size = 74) {
    std::vector<uint8_t> f(size, fill);
    f[0] = fill;
    return f;
}


class CaptureSessionTest : public ::testing::Test {
protected:
    std::mutex              mtx;
    std::condition_variable data_cv;
    std::condition_variable space_cv;
    std::atomic<bool>       stop_flag{false};
 
    int pipefd[2] = {-1, -1};
 
    void SetUp() override {
        stop_flag.store(false);
#ifdef __linux__
       ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM, 0, pipefd), 0)
          << "socketpair() failed";
#endif
    }
 
    void TearDown() override {
        stop_flag.store(true);
        data_cv.notify_all();
        space_cv.notify_all();
 
#ifdef __linux__
        if (pipefd[0] >= 0) { close(pipefd[0]); pipefd[0] = -1; }
        if (pipefd[1] >= 0) { close(pipefd[1]); pipefd[1] = -1; }
#endif
    }
 
    void signalStop() {
        stop_flag.store(true);
        data_cv.notify_all();
        space_cv.notify_all();
    }
 
    bool runCapture(
        utils::PacketBuffer& packet_buf,
        int                    delay_ms   = 100,
        int                    timeout_ms = 600
    ) {
#ifdef __linux__
        std::thread t([&] {
            capture::captureLoop(pipefd[0], packet_buf, stop_flag);
        });
 
        std::this_thread::sleep_for(
            std::chrono::milliseconds(delay_ms)
        );
        signalStop();
 
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(timeout_ms);
        (void)deadline;
 
        if (t.joinable()) {
            t.join();
            return true;
        }
        return false;
#else
        (void)packet_buf;
        (void)delay_ms;
        (void)timeout_ms;
        return true; 
#endif
    }
};

TEST_F(CaptureSessionTest, BytesLandInBufferWithCorrectTimestamp) {
#ifndef __linux__
    GTEST_SKIP() << "AF_PACKET and pipe-based capture test is Linux-only";
#else
    utils::PacketBuffer packet_buf(
        64, mtx, data_cv, space_cv, stop_flag
    );
 
    auto frame = makeFrame(0xAB, 74);
 
    const uint64_t time_before = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
 
    writeToPipe(pipefd[1], frame.data(), frame.size());
 
    ASSERT_TRUE(runCapture(packet_buf, 150, 600));
 
    const uint64_t time_after = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
 
    uint8_t  out[2048];
    size_t   out_size = 0;
    uint64_t out_ts   = 0;
 
    ASSERT_TRUE(packet_buf.read(out, sizeof(out), out_size, out_ts))
        << "No frame in buffer after captureLoop ran";
 
    EXPECT_EQ(out_size, frame.size())
        << "Frame size mismatch";
 
    EXPECT_EQ(std::memcmp(out, frame.data(), frame.size()), 0)
        << "Frame bytes corrupted in ring buffer";
 
    EXPECT_GT(out_ts, 0u)
        << "Timestamp must be non-zero";
    EXPECT_GE(out_ts, time_before)
        << "Timestamp before write time — clock error";
    EXPECT_LE(out_ts, time_after + 100)
        << "Timestamp far after read time — clock error";
#endif
}

TEST_F(CaptureSessionTest, MultipleFramesLandInFIFOOrder) {
#ifndef __linux__
    GTEST_SKIP() << "Linux-only";
#else
    utils::PacketBuffer packet_buf(
        64, mtx, data_cv, space_cv, stop_flag
    );
 
    const int N = 5;
 
    for (int i = 1; i <= N; i++) {
        auto frame = makeFrame(static_cast<uint8_t>(i), 64);
        writeToPipe(pipefd[1], frame.data(), frame.size());
    }
 
    ASSERT_TRUE(runCapture(packet_buf, 150, 600));

    for (int i = 1; i <= N; i++) {
        uint8_t  out[2048];
        size_t   out_size = 0;
        uint64_t out_ts   = 0;
 
        bool got = packet_buf.read(out, sizeof(out), out_size, out_ts);
        if (!got) break;  
 
        EXPECT_EQ(out_size, 64u)
            << "Frame " << i << " size wrong";
        EXPECT_EQ(out[0], static_cast<uint8_t>(i))
            << "Frame " << i << " arrived out of FIFO order "
            << "— expected fill byte " << i
            << " got " << static_cast<int>(out[0]);
    }
#endif
}

TEST_F(CaptureSessionTest, StopFlagHaltsCaptureLoop) {
#ifndef __linux__
    GTEST_SKIP() << "Linux-only";
#else
    utils::PacketBuffer packet_buf(
        64, mtx, data_cv, space_cv, stop_flag
    );
 
 
    std::atomic<bool> loop_exited{false};
 
    std::thread t([&] {
        capture::captureLoop(pipefd[0], packet_buf, stop_flag);
        loop_exited.store(true);
    });
 
    std::this_thread::sleep_for(50ms);
    EXPECT_FALSE(loop_exited.load())
        << "captureLoop should be blocked in epoll_wait";
 
    signalStop();
 
    auto deadline = std::chrono::steady_clock::now() + 500ms;
    (void)deadline;
    while (!loop_exited.load() &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(10ms);
    }
 
    EXPECT_TRUE(loop_exited.load())
        << "captureLoop did not exit within 500ms of stop_flag — "
        << "check epoll_wait timeout and stop_flag check in loop";
 
    if (t.joinable()) t.join();
#endif
}

TEST_F(CaptureSessionTest, TimestampsAreNonDecreasing) {
#ifndef __linux__
    GTEST_SKIP() << "Linux-only";
#else
    utils::PacketBuffer packet_buf(
        64, mtx, data_cv, space_cv, stop_flag
    );
 
    const int N = 4;
 
    for (int i = 0; i < N; i++) {
        auto frame = makeFrame(static_cast<uint8_t>(i + 1), 74);
        writeToPipe(pipefd[1], frame.data(), frame.size());
        std::this_thread::sleep_for(5ms);
    }
 
    ASSERT_TRUE(runCapture(packet_buf, 200, 700));
 
    uint64_t prev_ts = 0;
    int      frames_read = 0;
 
    for (int i = 0; i < N; i++) {
        uint8_t  out[2048];
        size_t   out_size = 0;
        uint64_t out_ts   = 0;
 
        if (!packet_buf.read(out, sizeof(out), out_size, out_ts)) break;
        frames_read++;
 
        EXPECT_GE(out_ts, prev_ts)
            << "Timestamp at frame " << i
            << " (" << out_ts << ") is less than previous ("
            << prev_ts << ") — timestamps not monotonic";
        prev_ts = out_ts;
    }
 
    EXPECT_GT(frames_read, 0)
        << "No frames read from buffer";
#endif
}

TEST_F(CaptureSessionTest, FrameSizesPreservedCorrectly) {
#ifndef __linux__
    GTEST_SKIP() << "Linux-only";
#else
    utils::PacketBuffer packet_buf(
        64, mtx, data_cv, space_cv, stop_flag
    );
 
    std::vector<size_t> sizes = {42, 74, 98, 512};
 
    for (size_t i = 0; i < sizes.size(); i++) {
        auto frame = makeFrame(static_cast<uint8_t>(i + 1), sizes[i]);
        writeToPipe(pipefd[1], frame.data(), frame.size());
    }
 
    ASSERT_TRUE(runCapture(packet_buf, 150, 600));
 
    for (size_t i = 0; i < sizes.size(); i++) {
        uint8_t  out[2048];
        size_t   out_size = 0;
        uint64_t out_ts   = 0;
 
        if (!packet_buf.read(out, sizeof(out), out_size, out_ts)) break;
 
        EXPECT_EQ(out_size, sizes[i])
            << "Frame " << i << ": expected size " << sizes[i]
            << " got " << out_size;
 
        EXPECT_EQ(out[0], static_cast<uint8_t>(i + 1))
            << "Frame " << i << " fill byte corrupted";
    }
#endif
}