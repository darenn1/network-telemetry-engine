#pragma once
#include <cstdint>
#include <unordered_set>
 
namespace capture {
  int openRawSocket();
  void closeRawSocket(int fd);

  std::unordered_set<uint32_t> getLocalIps();
}
