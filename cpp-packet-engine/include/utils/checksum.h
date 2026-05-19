#pragma once
#include <cstdint>
#include <cstddef>
namespace utils {

uint16_t internetChecksum(const uint8_t* data, std::size_t len);

bool verifyIpChecksum(const uint8_t* data, std::size_t len);
}