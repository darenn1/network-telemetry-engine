cmake_minimum_required(VERSION 3.25)

project(
    packet-engine
    VERSION     0.1.0
    DESCRIPTION "Network telemetry packet capture engine"
    LANGUAGES   CXX
)

include(CTest)        
enable_testing()

set(CMAKE_CXX_STANDARD          20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter  
)

include_directories(${CMAKE_SOURCE_DIR}/include)

include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
)

FetchContent_MakeAvailable(googletest)  

macro(add_gtest TARGET_NAME SOURCE_FILE)
    if(TARGET GTest::gtest_main)
        add_executable(${TARGET_NAME} ${SOURCE_FILE})
        target_link_libraries(${TARGET_NAME}
            PRIVATE
                GTest::gtest_main
                utils_lib
                capture_lib
                parsers_lib
                pipeline_lib
                publishers_lib
        )
        target_include_directories(${TARGET_NAME}
            PRIVATE ${CMAKE_SOURCE_DIR}/include
        )
        include(GoogleTest)
        gtest_discover_tests(
          ${TARGET_NAME}
          WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        )
    endif()
endmacro()


add_library(utils_lib STATIC
    src/utils/ring_buffer.cpp          
    src/utils/logger.cpp           
    src/utils/hex_dump.cpp         
    src/utils/checksum.cpp         
)

target_include_directories(utils_lib
    INTERFACE ${CMAKE_SOURCE_DIR}/include
)

add_library(capture_lib STATIC
    src/capture/raw_socket.cpp       
    src/capture/packet_buffer.cpp
    src/capture/capture_session.cpp  
)

target_include_directories(capture_lib
    PUBLIC ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(capture_lib
    PUBLIC utils_lib
)

# Linux-only capability support (CAP_NET_RAW / CAP_NET_ADMIN)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(capture_lib PUBLIC cap)
endif()

# parsers — ethernet, ip, tcp, udp, icmp, arp 
add_library(parsers_lib STATIC
    src/parsers/ethernet_parser.cpp   
    src/parsers/ip_parser.cpp         
    # src/parsers/tcp_parser.cpp        
    # src/parsers/udp_parser.cpp        
    # src/parsers/icmp_parser.cpp       
    # src/parsers/arp_parser.cpp       
)

target_include_directories(parsers_lib
    INTERFACE ${CMAKE_SOURCE_DIR}/include
)
target_link_libraries(parsers_lib PUBLIC utils_lib)

# pipeline — filter, dissector, stats, flow_tracker 
add_library(pipeline_lib INTERFACE)
target_include_directories(pipeline_lib
    INTERFACE ${CMAKE_SOURCE_DIR}/include
)
# add_library(pipeline_lib STATIC
#     src/pipeline/filter_stage.cpp     
#     src/pipeline/dissector_stage.cpp  
#     src/pipeline/stats_stage.cpp      
#     src/pipeline/flow_tracker.cpp    
# )

# publishers — rabbitmq_publisher 
add_library(publishers_lib INTERFACE)
target_include_directories(publishers_lib
    INTERFACE ${CMAKE_SOURCE_DIR}/include
)
# add_library(publishers_lib STATIC
#     src/publishers/rabbitmq_publisher.cpp   
# )

add_executable(packet-engine
    src/main.cpp
)

target_include_directories(packet-engine
    PRIVATE ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(packet-engine
    PRIVATE
        utils_lib
        capture_lib
        parsers_lib
        pipeline_lib
        publishers_lib
)

add_subdirectory(tests)  