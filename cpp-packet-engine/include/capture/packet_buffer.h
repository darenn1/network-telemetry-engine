#pragma once

#include "utils/ring_buffer.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>

namespace utils {

static constexpr size_t TIMESTAMP_SIZE = sizeof(uint64_t);

class PacketBuffer {
public:
    PacketBuffer(
        size_t                   capacity,
        std::mutex&              mtx,
        std::condition_variable& data_cv,
        std::condition_variable& space_cv,
        std::atomic<bool>&       stop_flag
    );

    bool write(const uint8_t* frame_data, size_t frame_size);

    bool read(
        uint8_t*  out_data,
        size_t    out_capacity,
        size_t&   out_size,
        uint64_t& out_timestamp
    );

    bool   isEmpty()  const;
    bool   isFull()   const;
    size_t count()    const;
    size_t capacity() const;

private:
    RingBuffer ring_;

    uint8_t slot_buf_[RingBuffer::SLOT_SIZE];

    static uint64_t nowMillis();
};

} 