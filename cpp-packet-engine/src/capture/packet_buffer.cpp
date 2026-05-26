#include "capture/packet_buffer.h"
#include "utils/logger.h"

#include <chrono>
#include <cstring>
#include <stdexcept>

namespace utils {

PacketBuffer::PacketBuffer(
    size_t                   capacity,
    std::mutex&              mtx,
    std::condition_variable& data_cv,
    std::condition_variable& space_cv,
    std::atomic<bool>&       stop_flag
)
    : ring_(capacity, mtx, data_cv, space_cv, stop_flag)
{
}

uint64_t PacketBuffer::nowMillis() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(
            system_clock::now().time_since_epoch()
        ).count()
    );
}

bool PacketBuffer::write(const uint8_t* frame_data, size_t frame_size) {

    if (frame_size == 0 || frame_size > RingBuffer::SLOT_SIZE - TIMESTAMP_SIZE) {
        return false;
    }

    const uint64_t ts = nowMillis();
    uint8_t slot_buf[RingBuffer::SLOT_SIZE];

    std::memcpy(slot_buf,                   &ts,        TIMESTAMP_SIZE);
    std::memcpy(slot_buf + TIMESTAMP_SIZE,  frame_data, frame_size);

    return ring_.write(slot_buf, TIMESTAMP_SIZE + frame_size);
}


bool PacketBuffer::read(
    uint8_t*  out_data,
    size_t    out_capacity,
    size_t&   out_size,
    uint64_t& out_timestamp
) {
    size_t slot_size = 0;
    uint8_t slot_buf[RingBuffer::SLOT_SIZE];

    if (!ring_.read(slot_buf, slot_size)) {
        return false;   
    }

    if (slot_size < TIMESTAMP_SIZE) {
        utils::log_error("packet_buffer: slot_size < TIMESTAMP_SIZE — "
                         "memory corruption or constant mismatch");
        return false;
    }

    out_size = slot_size - TIMESTAMP_SIZE;

    if (out_size > out_capacity) {
        utils::log_error("packet_buffer: frame size " +
                         std::to_string(out_size) +
                         " exceeds buffer capacity " +
                         std::to_string(out_capacity));
        return false;
    }

    std::memcpy(&out_timestamp, slot_buf, TIMESTAMP_SIZE);
    std::memcpy(out_data, slot_buf + TIMESTAMP_SIZE, out_size);
    return true;
}

bool   PacketBuffer::isEmpty()  const { return ring_.isEmpty(); }
bool   PacketBuffer::isFull()   const { return ring_.isFull(); }
size_t PacketBuffer::count()    const { return ring_.count(); }
size_t PacketBuffer::capacity() const { return ring_.capacity(); }

} 