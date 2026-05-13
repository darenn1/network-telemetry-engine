#include "utils/ring_buffer.h"

#include <cassert>
#include <stdexcept>

namespace utils {

RingBuffer::RingBuffer(
    size_t                   capacity,
    std::mutex&              mtx,
    std::condition_variable& data_cv,
    std::condition_variable& space_cv,
    std::atomic<bool>&       stop_flag
)
    : capacity_  (capacity)
    , buffer_    (capacity * SLOT_SIZE)   
    , slot_sizes_(capacity, 0)
    , mtx_       (mtx)
    , data_cv_   (data_cv)
    , space_cv_  (space_cv)
    , stop_flag_ (stop_flag)
{
    if (capacity == 0) {
        throw std::invalid_argument("RingBuffer capacity must be > 0");
    }
    if (capacity > 65536) {
        throw std::invalid_argument("RingBuffer capacity must be <= 65536");
    }
}

bool RingBuffer::write(const uint8_t* data, size_t size) {

    if (size == 0 || size > SLOT_SIZE) {
        return false;
    }

    std::unique_lock<std::mutex> lock(mtx_);

    space_cv_.wait(lock, [this] {
        return !isFull() || stop_flag_.load(std::memory_order_relaxed);
    });

    if (stop_flag_.load(std::memory_order_relaxed) && isFull()) {
        return false;
    }

    uint8_t* slot = buffer_.data() + (head_ * SLOT_SIZE);
    std::memcpy(slot, data, size);
    slot_sizes_[head_] = size;

    head_ = (head_ + 1) % capacity_;
    count_++;

    data_cv_.notify_one();

    return true;
}


bool RingBuffer::read(uint8_t* out_data, size_t& out_size) {

    std::unique_lock<std::mutex> lock(mtx_);

    data_cv_.wait(lock, [this] {
        return !isEmpty() || stop_flag_.load(std::memory_order_relaxed);
    });

    if (stop_flag_.load(std::memory_order_relaxed) && isEmpty()) {
        return false;
    }

    const uint8_t* slot = buffer_.data() + (tail_ * SLOT_SIZE);
    out_size = slot_sizes_[tail_];
    std::memcpy(out_data, slot, out_size);

    tail_ = (tail_ + 1) % capacity_;
    count_--;

    space_cv_.notify_one();

    return true;
}


bool   RingBuffer::isEmpty()  const { return count_ == 0; }
bool   RingBuffer::isFull()   const { return count_ == capacity_; }
size_t RingBuffer::count()    const { return count_; }
size_t RingBuffer::capacity() const { return capacity_; }

}