#include "capture/raw_socket.h"

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <iostream>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>

// Linux capability headers
// Requires: libcap-dev (installed in Dockerfile Day 6)
#include <sys/capability.h>
#include <sys/prctl.h>

namespace capture {

static void dropCapabilities() {
    cap_t caps = cap_get_proc();
    if (!caps) {
        std::cerr << "[raw_socket] cap_get_proc failed: "
                  << strerror(errno) << "\n";
        return;
    }

    cap_value_t drop[] = { CAP_NET_RAW, CAP_NET_ADMIN };

    cap_set_flag(caps, CAP_EFFECTIVE, 2, drop, CAP_CLEAR);
    cap_set_flag(caps, CAP_PERMITTED, 2, drop, CAP_CLEAR);

    if (cap_set_proc(caps) != 0) {
        std::cerr << "[raw_socket] cap_set_proc failed: "
                  << strerror(errno) << "\n";
    }

    cap_free(caps);

    cap_t verify = cap_get_proc();
    if (verify) {
        char* text = cap_to_text(verify, nullptr);
        if (text) {
            // "=" means empty — zero powers
            std::cout << "[raw_socket] Capabilities after drop: "
                      << text << "\n";
            std::cout << "[raw_socket] Capabilities dropped — zero powers\n";
            cap_free(text);
        }
        cap_free(verify);
    }
}


int openRawSocket() {
    const char* iface_env = std::getenv("CAPTURE_INTERFACE");
    const char* iface     = iface_env ? iface_env : "eth0";

    std::cout << "[raw_socket] Opening raw socket on interface: "
              << iface << "\n";

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) {
        std::cerr << "[raw_socket] socket() failed: "
                  << strerror(errno) << "\n";
        std::cerr << "[raw_socket] Check CAP_NET_RAW is granted\n";
        return -1;
    }

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        std::cerr << "[raw_socket] ioctl SIOCGIFINDEX failed for "
                  << iface << ": " << strerror(errno) << "\n";
        close(fd);
        return -1;
    }

    int ifindex = ifr.ifr_ifindex;
    std::cout << "[raw_socket] Interface " << iface
              << " index: " << ifindex << "\n";

    struct sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifindex;

    if (bind(fd,
             reinterpret_cast<struct sockaddr*>(&sll),
             sizeof(sll)) < 0) {
        std::cerr << "[raw_socket] bind() failed: "
                  << strerror(errno) << "\n";
        close(fd);
        return -1;
    }

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        std::cerr << "[raw_socket] ioctl SIOCGIFFLAGS failed: "
                  << strerror(errno) << "\n";
        close(fd);
        return -1;
    }

    ifr.ifr_flags |= IFF_PROMISC;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        std::cerr << "[raw_socket] ioctl SIOCSIFFLAGS (promisc) failed: "
                  << strerror(errno) << "\n";
        close(fd);
        return -1;
    }

    std::cout << "[raw_socket] Promiscuous mode enabled on "
              << iface << "\n";

    dropCapabilities();

    std::cout << "[raw_socket] Raw socket ready — fd: " << fd << "\n";
    return fd;
}

void closeRawSocket(int fd) {
    if (fd >= 0) {
        close(fd);
        std::cout << "[raw_socket] Socket closed\n";
    }
}

} 