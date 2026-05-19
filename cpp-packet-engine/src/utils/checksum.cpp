#include "utils/checksum.h"

namespace utils {

uint16_t internetChecksum(const uint8_t* data, std::size_t len) {
    uint32_t sum = 0;

    while (len > 1) {
        uint16_t word = static_cast<uint16_t>(
            (static_cast<uint16_t>(data[0]) << 8) | data[1]);
        sum += word;
        data += 2;
        len  -= 2;
    }

    if (len == 1) {
        sum += static_cast<uint16_t>(static_cast<uint16_t>(data[0]) << 8);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

bool verifyIpChecksum(const uint8_t* data, std::size_t len) {
    return internetChecksum(data, len) == 0x0000;
}

} 