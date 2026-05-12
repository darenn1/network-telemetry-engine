#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace utils {



class RingBuffer {

public:
static constexpr size_t SLOT_SIZE = 2048;
    RingBuffer(
        size_t                   capacity,
        std::mutex&              mtx,
        std::condition_variable& data_cv,
        std::condition_variable& space_cv,
        std::atomic<bool>&       stop_flag
    );

    ~RingBuffer() = default;

    // No copy, no move — sync primitive references cannot be reseated
    RingBuffer(const RingBuffer&)            = delete;
    RingBuffer& operator=(const RingBuffer&) = delete;

    bool write(const uint8_t* data, size_t size);

    bool read(uint8_t* out_data, size_t& out_size);

    bool   isEmpty()   const;
    bool   isFull()    const;
    size_t count()     const;
    size_t capacity()  const;

private:
    alignas(64) size_t head_{0};   
    char pad1_[64 - sizeof(size_t)];

    alignas(64) size_t tail_{0};   
    char pad2_[64 - sizeof(size_t)];

    size_t               capacity_;
    std::vector<uint8_t> buffer_;        
    std::vector<size_t>  slot_sizes_;   
    size_t               count_{0};     

    std::mutex&              mtx_;
    std::condition_variable& data_cv_;
    std::condition_variable& space_cv_;
    std::atomic<bool>&       stop_flag_;
};

} 