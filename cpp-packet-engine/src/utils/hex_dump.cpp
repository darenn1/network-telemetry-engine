#include "utils/hex_dump.h"
#include "utils/logger.h"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace utils {

static std::string formatMAC(const uint8_t* bytes) {
    std::ostringstream oss;
    for (int i = 0; i < 6; i++) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(bytes[i]);
    }
    return oss.str();
}


void hexDump(
    const uint8_t*     data,
    size_t             size,
    const std::string& label
) {
    if (!data || size == 0) return;

    std::ostringstream out;

    if (!label.empty()) {
        out << label << " (" << std::dec << size << " bytes)\n";
    }

    for (size_t offset = 0; offset < size; offset += 16) {

        out << "  "
            << std::hex << std::setfill('0') << std::setw(4) << offset
            << "  ";

        for (size_t i = 0; i < 16; i++) {
            if (offset + i < size) {
                out << std::hex << std::setfill('0') << std::setw(2)
                    << static_cast<int>(data[offset + i]) << " ";
            } else {
                out << "   ";  
            }
            if (i == 7) out << " ";  
        }

        out << " |";

        for (size_t i = 0; i < 16 && offset + i < size; i++) {
            const uint8_t b = data[offset + i];
            out << (std::isprint(b) ? static_cast<char>(b) : '.');
        }

        out << "|\n";
    }

    utils::log_info(out.str());
}


uint16_t logFrameSummary(
    const uint8_t* data,
    size_t         size,
    uint64_t       timestamp_ms
) {
    if (!data || size < 14) {
        utils::log_warn("logFrameSummary: frame too short (" +
                        std::to_string(size) + " bytes) — skipping");
        return 0;
    }

    const std::string dst_mac = formatMAC(data + 0);   // bytes 0-5
    const std::string src_mac = formatMAC(data + 6);   // bytes 6-11

    const uint16_t ethertype =
        static_cast<uint16_t>((data[12] << 8) | data[13]);

    std::string proto;
    switch (ethertype) {
        case 0x0800: proto = "IPv4"; break;
        case 0x0806: proto = "ARP";  break;
        case 0x86DD: proto = "IPv6"; break;
        default: {
            std::ostringstream oss;
            oss << "0x" << std::hex << std::setw(4)
                << std::setfill('0') << ethertype;
            proto = oss.str();
        }
    }

    std::ostringstream oss;
    oss << "FRAME "
        << std::dec << std::setw(5) << size << "B"
        << "  ts=" << timestamp_ms
        << "  dst=" << dst_mac
        << "  src=" << src_mac
        << "  EtherType=" << proto;

    utils::log_info(oss.str());
    return ethertype;
}

} 