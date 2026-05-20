add_gtest(test_dummy 
          ${CMAKE_CURRENT_SOURCE_DIR}/test_dummy.cpp)

add_gtest(test_ring_buffer 
          ${CMAKE_CURRENT_SOURCE_DIR}/test_ring_buffer.cpp)
          
add_gtest(test_capture_session
          ${CMAKE_CURRENT_SOURCE_DIR}/test_capture_session.cpp)

add_gtest(test_ethernet_parser
          ${CMAKE_CURRENT_SOURCE_DIR}/test_ethernet_parser.cpp)

add_gtest(test_ip_parser
          ${CMAKE_CURRENT_SOURCE_DIR}/test_ip_parser.cpp)

add_gtest(test_checksum
          ${CMAKE_CURRENT_SOURCE_DIR}/test_checksum.cpp)

add_gtest(test_tcp_parser
          ${CMAKE_CURRENT_SOURCE_DIR}/test_tcp_parser.cpp)

add_gtest(test_udp_parser
          ${CMAKE_CURRENT_SOURCE_DIR}/test_udp_parser.cpp)