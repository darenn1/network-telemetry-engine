#include <gtest/gtest.h>

#include "utils/ring_buffer.h"
#include "capture/packet_buffer.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

using namespace utils;

class RingBufferTest : public ::testing::Test {
protected:
    std::mutex              mtx;
    std::condition_variable data_cv;
    std::condition_variable space_cv;
    std::atomic<bool>       stop_flag{false};

    // Helper: make a small frame of known bytes
    static std::vector<uint8_t> makeFrame(uint8_t fill, size_t size = 64) {
        return std::vector<uint8_t>(size, fill);
    }

    void SetUp() override {
        stop_flag.store(false);
    }

    void TearDown() override {
        stop_flag.store(true);
        data_cv.notify_all();
        space_cv.notify_all();
    }
};

TEST_F(RingBufferTest, ConstructsWithCorrectCapacity) {
    RingBuffer rb(8, mtx, data_cv, space_cv, stop_flag);
    EXPECT_EQ(rb.capacity(), 8u);
    EXPECT_EQ(rb.count(),    0u);
    EXPECT_TRUE(rb.isEmpty());
    EXPECT_FALSE(rb.isFull());
}

TEST_F(RingBufferTest, ZeroCapacityThrows) {
    EXPECT_THROW(
        RingBuffer rb(0, mtx, data_cv, space_cv, stop_flag),
        std::invalid_argument
    );
}

TEST_F(RingBufferTest, WriteAndReadSingleFrame) {
    RingBuffer rb(4, mtx, data_cv, space_cv, stop_flag);

    auto frame = makeFrame(0xAB, 74);
    EXPECT_TRUE(rb.write(frame.data(), frame.size()));
    EXPECT_EQ(rb.count(), 1u);

    uint8_t out[RingBuffer::SLOT_SIZE];
    size_t  out_size = 0;
    EXPECT_TRUE(rb.read(out, out_size));

    EXPECT_EQ(out_size, 74u);
    EXPECT_EQ(std::memcmp(out, frame.data(), 74), 0);
    EXPECT_TRUE(rb.isEmpty());
}

TEST_F(RingBufferTest, WriteAndReadMultipleFrames) {
    RingBuffer rb(4, mtx, data_cv, space_cv, stop_flag);

    for (uint8_t i = 0; i < 3; i++) {
        auto frame = makeFrame(i, 64);
        EXPECT_TRUE(rb.write(frame.data(), frame.size()));
    }
    EXPECT_EQ(rb.count(), 3u);

    for (uint8_t i = 0; i < 3; i++) {
        uint8_t out[RingBuffer::SLOT_SIZE];
        size_t  out_size = 0;
        EXPECT_TRUE(rb.read(out, out_size));
        EXPECT_EQ(out_size, 64u);
        // Every byte in the frame should match the fill value
        for (size_t j = 0; j < out_size; j++) {
            EXPECT_EQ(out[j], i) << "Mismatch at frame " << (int)i
                                  << " byte " << j;
        }
    }
    EXPECT_TRUE(rb.isEmpty());
}

TEST_F(RingBufferTest, WrapAroundBehaviour) {
    RingBuffer rb(4, mtx, data_cv, space_cv, stop_flag);

    uint8_t out[RingBuffer::SLOT_SIZE];
    size_t  out_size = 0;

    for (uint8_t i = 0; i < 4; i++) {
        auto frame = makeFrame(i, 42);
        EXPECT_TRUE(rb.write(frame.data(), frame.size()));
    }
    EXPECT_TRUE(rb.isFull());

    for (uint8_t i = 0; i < 4; i++) {
        EXPECT_TRUE(rb.read(out, out_size));
        EXPECT_EQ(out[0], i);
    }
    EXPECT_TRUE(rb.isEmpty());

    for (uint8_t i = 10; i < 14; i++) {
        auto frame = makeFrame(i, 42);
        EXPECT_TRUE(rb.write(frame.data(), frame.size()));
    }

    for (uint8_t i = 10; i < 14; i++) {
        EXPECT_TRUE(rb.read(out, out_size));
        EXPECT_EQ(out[0], i) << "Wrap-around FIFO order broken at i=" << (int)i;
    }
}


TEST_F(RingBufferTest, FullBufferBlocksWriter) {
    RingBuffer rb(2, mtx, data_cv, space_cv, stop_flag);

    auto frame = makeFrame(0xFF, 64);

    // Fill to capacity
    EXPECT_TRUE(rb.write(frame.data(), frame.size()));
    EXPECT_TRUE(rb.write(frame.data(), frame.size()));
    EXPECT_TRUE(rb.isFull());

    std::atomic<bool> write_completed{false};

    std::thread writer([&] {
        rb.write(frame.data(), frame.size());
        write_completed.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(write_completed.load())
        << "write() should block when buffer is full";

    uint8_t out[RingBuffer::SLOT_SIZE];
    size_t  out_size = 0;
    rb.read(out, out_size);

    writer.join();
    EXPECT_TRUE(write_completed.load());
}

TEST_F(RingBufferTest, StopFlagUnblocksBlockedReader) {
    RingBuffer rb(4, mtx, data_cv, space_cv, stop_flag);
    // Buffer is empty — read() will block

    std::atomic<bool> read_returned{false};

    std::thread reader([&] {
        uint8_t out[RingBuffer::SLOT_SIZE];
        size_t  out_size = 0;
        rb.read(out, out_size);   
        read_returned.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(read_returned.load()) << "read() should be blocking";

    stop_flag.store(true);
    data_cv.notify_all();

    reader.join();
    EXPECT_TRUE(read_returned.load()) << "stop_flag must unblock read()";
}

TEST_F(RingBufferTest, StopFlagUnblocksBlockedWriter) {
    RingBuffer rb(1, mtx, data_cv, space_cv, stop_flag);

    auto frame = makeFrame(0x01, 64);
    rb.write(frame.data(), frame.size());  
    EXPECT_TRUE(rb.isFull());

    std::atomic<bool> write_returned{false};

    std::thread writer([&] {
        rb.write(frame.data(), frame.size());  
        write_returned.store(true);
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_FALSE(write_returned.load()) << "write() should be blocking";

    stop_flag.store(true);
    space_cv.notify_all();

    writer.join();
    EXPECT_TRUE(write_returned.load()) << "stop_flag must unblock write()";
}

TEST_F(RingBufferTest, ConcurrentReadWriteCorrectness) {
    RingBuffer rb(32, mtx, data_cv, space_cv, stop_flag);

    const int    NUM_FRAMES  = 500;
    const size_t FRAME_SIZE  = 128;

    std::thread writer([&] {
        for (int i = 0; i < NUM_FRAMES; i++) {
            std::vector<uint8_t> frame(FRAME_SIZE, static_cast<uint8_t>(i % 256));
            frame[0] = static_cast<uint8_t>(i % 256);
            while (!rb.write(frame.data(), frame.size())) {
                if (stop_flag.load()) return;
            }
        }
    });

    std::vector<uint8_t> received;
    received.reserve(NUM_FRAMES);

    std::thread reader([&] {
        uint8_t out[RingBuffer::SLOT_SIZE];
        size_t  out_size = 0;
        for (int i = 0; i < NUM_FRAMES; i++) {
            if (!rb.read(out, out_size)) return;
            received.push_back(out[0]);
        }
    });

    writer.join();
    reader.join();

    EXPECT_EQ(received.size(), static_cast<size_t>(NUM_FRAMES));
    for (int i = 0; i < NUM_FRAMES; i++) {
        EXPECT_EQ(received[i], static_cast<uint8_t>(i % 256))
            << "Frame " << i << " arrived out of order or corrupted";
    }
}

TEST_F(RingBufferTest, VariableFrameSizes) {
    RingBuffer rb(8, mtx, data_cv, space_cv, stop_flag);

    std::vector<size_t> sizes = {42, 74, 98, 512, 1514};

    for (size_t sz : sizes) {
        auto frame = makeFrame(static_cast<uint8_t>(sz & 0xFF), sz);
        EXPECT_TRUE(rb.write(frame.data(), frame.size()));
    }

    uint8_t out[RingBuffer::SLOT_SIZE];
    size_t  out_size = 0;

    for (size_t sz : sizes) {
        EXPECT_TRUE(rb.read(out, out_size));
        EXPECT_EQ(out_size, sz) << "Frame size mismatch for expected size " << sz;
    }
}

class PacketBufferTest : public ::testing::Test {
protected:
    std::mutex              mtx;
    std::condition_variable data_cv;
    std::condition_variable space_cv;
    std::atomic<bool>       stop_flag{false};

    void SetUp()    override { stop_flag.store(false); }
    void TearDown() override {
        stop_flag.store(true);
        data_cv.notify_all();
        space_cv.notify_all();
    }
};

TEST_F(PacketBufferTest, TimestampAttachedAtWriteTime) {
    PacketBuffer pb(4, mtx, data_cv, space_cv, stop_flag);

    uint8_t  frame[64];
    std::memset(frame, 0xAB, sizeof(frame));

    auto before = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    EXPECT_TRUE(pb.write(frame, sizeof(frame)));

    uint8_t  out[RingBuffer::SLOT_SIZE];
    size_t   out_size    = 0;
    uint64_t out_ts      = 0;

    EXPECT_TRUE(pb.read(out, sizeof(out), out_size, out_ts));

    auto after = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    EXPECT_GE(out_ts, static_cast<uint64_t>(before))
        << "Timestamp before write time";
    EXPECT_LE(out_ts, static_cast<uint64_t>(after))
        << "Timestamp after read time";

    EXPECT_EQ(out_size, sizeof(frame));
    EXPECT_EQ(std::memcmp(out, frame, sizeof(frame)), 0);
}

TEST_F(PacketBufferTest, TimestampsAscending) {
    PacketBuffer pb(8, mtx, data_cv, space_cv, stop_flag);

    const int N = 5;
    uint8_t frame[64];
    std::memset(frame, 0x01, sizeof(frame));

    for (int i = 0; i < N; i++) {
        EXPECT_TRUE(pb.write(frame, sizeof(frame)));
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    uint64_t prev_ts = 0;
    for (int i = 0; i < N; i++) {
        uint8_t  out[RingBuffer::SLOT_SIZE];
        size_t   out_size = 0;
        uint64_t ts       = 0;

        EXPECT_TRUE(pb.read(out, sizeof(out), out_size, ts));
        EXPECT_GE(ts, prev_ts)
            << "Timestamp at index " << i << " is less than previous";
        prev_ts = ts;
    }
}

TEST_F(PacketBufferTest, TimestampNonZero) {
    PacketBuffer pb(4, mtx, data_cv, space_cv, stop_flag);

    uint8_t frame[74];
    std::memset(frame, 0xFF, sizeof(frame));
    pb.write(frame, sizeof(frame));

    uint8_t  out[RingBuffer::SLOT_SIZE];
    size_t   out_size = 0;
    uint64_t ts       = 0;

    pb.read(out, sizeof(out), out_size, ts);

    EXPECT_GT(ts, 0u) << "Timestamp must be non-zero";

    EXPECT_GT(ts, 1577836800000ULL) << "Timestamp looks wrong — too old";
}