#include "parsers/ethernet_parser.h"

#include <iomanip>
#include <sstream>

namespace parsers {


std::string EthernetFrame::macToString(const MACAddress& mac) {
    std::ostringstream oss;
    for (int i = 0; i < 6; i++) {
        if (i > 0) oss << ":";
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}

namespace ethernet_parser {

EthernetFrame parse(const uint8_t* data, size_t size) {

    EthernetFrame frame{};

    if (!data) {
        return frame;  
    }

    if (size < ETHERNET_MIN_SIZE) {
        return frame;   
    }

    for (int i = 0; i < 6; i++) {
        frame.dst_mac[i] = data[i];
    }

    for (int i = 0; i < 6; i++) {
        frame.src_mac[i] = data[6 + i];
    }

    frame.ethertype = static_cast<uint16_t>(
        (static_cast<uint16_t>(data[12]) << 8) |
         static_cast<uint16_t>(data[13])
    );

    frame.payload      = data + ETHERNET_HEADER_SIZE;
    frame.payload_size = size - ETHERNET_HEADER_SIZE;

    frame.valid = true;
    return frame;
}

}

} 