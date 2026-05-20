cmake_minimum_required(VERSION 3.15)
project(csa-attack-test CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

add_executable(csa-attack-test
    src/csa-attack-test.cpp
    src/csa.cpp
    src/mac.cpp
    src/dot11.cpp
    src/util.cpp
    src/pch.cpp
    libyeob/src/radiotap.cpp
)

target_include_directories(csa-attack-test PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/libyeob/include
    ${PCAP_INCLUDE_DIRS}
)

target_compile_options(csa-attack-test PRIVATE -Wall -O2)

target_link_libraries(csa-attack-test PRIVATE ${PCAP_LIBRARIES})