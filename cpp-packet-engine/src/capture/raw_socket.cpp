#include "capture/raw_socket.h"
#include "utils/logger.h"

#include <cerrno>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <vector>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <unistd.h>

// Linux capability headers
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

std::unordered_set<uint32_t> getLocalIps() {
    std::unordered_set<uint32_t> result;

    int probe_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (probe_fd < 0) {
        utils::log_warn("getLocalIps: failed to open probe socket: " +
                        std::string(strerror(errno)));
        return result;
    }

    std::vector<char> buf(sizeof(struct ifreq) * 16);

    struct ifconf ifc{};
    for (;;) {
        ifc.ifc_len = static_cast<int>(buf.size());
        ifc.ifc_buf = buf.data();

        if (ioctl(probe_fd, SIOCGIFCONF, &ifc) < 0) {
            utils::log_warn("getLocalIps: SIOCGIFCONF failed: " +
                            std::string(strerror(errno)));
            close(probe_fd);
            return result;
        }

        if (static_cast<std::size_t>(ifc.ifc_len) < buf.size())
            break;

        buf.resize(buf.size() * 2);
    }

    const std::size_t   n      = static_cast<std::size_t>(ifc.ifc_len)
                                 / sizeof(struct ifreq);
    const struct ifreq* ifaces = reinterpret_cast<const struct ifreq*>(buf.data());

    for (std::size_t i = 0; i < n; ++i) {
        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, ifaces[i].ifr_name, IFNAMSIZ - 1);

        if (ioctl(probe_fd, SIOCGIFADDR, &ifr) < 0)
            continue;

        if (ifr.ifr_addr.sa_family != AF_INET)
            continue;

        const auto* sin = reinterpret_cast<const struct sockaddr_in*>(&ifr.ifr_addr);
        const uint32_t addr = ntohl(sin->sin_addr.s_addr);

        if (addr == INADDR_ANY)
            continue;

        result.insert(addr);

        char dotted[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, dotted, sizeof(dotted));
        utils::log_info("Local IP detected: " + std::string(dotted) +
                        " on interface " + ifr.ifr_name);
    }

    close(probe_fd);

    utils::log_info("[raw_socket] " + std::to_string(result.size()) +
                    " local IPv4 address(es) found");
    return result;
}

} 