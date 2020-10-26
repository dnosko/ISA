cmake_minimum_required(VERSION 3.15)
project(isa)

set(CMAKE_C_STANDARD 11)
SET(CMAKE_MODULE_PATH "/home/dasa/Dokumenty/school/ISA/sslsniff")
set("-pthread")

include(FindPCAP.cmake)
find_package(PCAP REQUIRED)

include_directories(.)

add_executable(isa
        src/sslsniff.c
        src/analyser.c src/packet.c src/format.c
        src/sslsniff.h src/analyser.h src/packet.h src/format.h src/error.h)

target_link_libraries(isa ${PCAP_LIBRARY})