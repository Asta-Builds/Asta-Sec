cmake_minimum_required(VERSION 3.16)
project(AstaSec CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (WIN32)
    add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)

    # Check local npcap-sdk or environment variable
    find_path(PCAP_INCLUDE_DIR pcap.h PATHS "${CMAKE_CURRENT_SOURCE_DIR}/npcap-sdk/Include" "$ENV{NPCAP_SDK}/Include" "C:/Npcap-SDK/Include")
    find_library(PCAP_LIBRARY NAMES wpcap pcap PATHS "${CMAKE_CURRENT_SOURCE_DIR}/npcap-sdk/Lib/x64" "$ENV{NPCAP_SDK}/Lib/x64" "C:/Npcap-SDK/Lib/x64")

    if (PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
        include_directories(${PCAP_INCLUDE_DIR})
        add_executable(asta-sec asta-sec.cpp)
        target_link_libraries(asta-sec PRIVATE ${PCAP_LIBRARY} ws2_32)
    else()
        message(FATAL_ERROR "Npcap SDK not found. Ensure npcap-sdk folder exists or set NPCAP_SDK.")
    endif()
else()
    find_package(PkgConfig QUIET)
    find_library(PCAP_LIBRARY pcap REQUIRED)

    add_executable(asta-sec asta-sec.cpp)
    target_link_libraries(asta-sec PRIVATE ${PCAP_LIBRARY})
endif()
