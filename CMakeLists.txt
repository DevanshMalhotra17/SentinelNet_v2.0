cmake_minimum_required(VERSION 3.10)
project(SentinelNet)

set(CMAKE_CXX_STANDARD 17)

set(NPCAP_SDK "C:/npcap-sdk")
include_directories(${NPCAP_SDK}/Include)
link_directories(${NPCAP_SDK}/Lib/x64)

include_directories(include)

add_executable(SentinelNet
    src/scanner.cpp
    src/detection.cpp
    src/server.cpp
    src/logger.cpp
    src/cli.cpp
    src/network_utils.cpp
    src/main.cpp
    src/packet_monitor.cpp
    src/tunnel.cpp
    resources.rc
)

target_link_libraries(SentinelNet ws2_32 iphlpapi wpcap Packet winhttp advapi32 userenv wtsapi32)

if(MINGW)
    target_link_options(SentinelNet PRIVATE "-static-libgcc" "-static-libstdc++" "-static")
endif()

# Automated Distribution: Copy executable to dist folder after build
add_custom_command(TARGET SentinelNet POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/dist"
    COMMAND ${CMAKE_COMMAND} -E copy "$<TARGET_FILE:SentinelNet>" "${CMAKE_SOURCE_DIR}/dist/SentinelNet.exe"
    COMMENT "Copying SentinelNet to distribution folder..."
)
