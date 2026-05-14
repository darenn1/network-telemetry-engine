#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace utils {

void hexDump(
    const uint8_t* data,
    size_t         size,
    const std::string& label = ""
);

uint16_t logFrameSummary(
    const uint8_t* data,
    size_t         size,
    uint64_t       timestamp_ms
);

} 