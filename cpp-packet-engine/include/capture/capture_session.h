#pragma once

#include "capture/packet_buffer.h"
#include <atomic>

namespace capture {

void captureLoop(
    int                    fd,
    utils::PacketBuffer&   packet_buf,
    std::atomic<bool>&     stop_flag
);

} 