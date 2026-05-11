#pragma once
#include <cstdint>
 
namespace capture {
  int openRawSocket();
  void closeRawSocket(int fd);
}
 