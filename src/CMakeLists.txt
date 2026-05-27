find_package(PcapPlusPlus QUIET)

if(PcapPlusPlus_FOUND)
    message(STATUS "tsembo: using PcapPlusPlus for pcap parsing")
    set(TSEMBO_PCAP_BACKEND_PCAPPLUSPLUS ON)
else()
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBPCAP libpcap)
    endif()
    if(NOT LIBPCAP_FOUND)
        find_path(LIBPCAP_INCLUDE_DIR pcap.h)
        find_library(LIBPCAP_LIBRARY NAMES pcap)
        if(LIBPCAP_INCLUDE_DIR AND LIBPCAP_LIBRARY)
            set(LIBPCAP_FOUND ON)
            set(LIBPCAP_INCLUDE_DIRS ${LIBPCAP_INCLUDE_DIR})
            set(LIBPCAP_LIBRARIES ${LIBPCAP_LIBRARY})
        endif()
    endif()
    if(NOT LIBPCAP_FOUND)
        message(FATAL_ERROR "tsembo: neither PcapPlusPlus nor libpcap was found")
    endif()
    message(STATUS "tsembo: using libpcap for pcap parsing (${LIBPCAP_LIBRARIES})")
endif()

add_library(tsembo_lib
    PcapLoader.cpp
    Messages.cpp
    MessageParser.cpp
    IndicativeVolumeBook.cpp
)

target_include_directories(tsembo_lib
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_include_directories(tsembo_lib PRIVATE ${LIBPCAP_INCLUDE_DIRS})
target_link_libraries(tsembo_lib PUBLIC ${LIBPCAP_LIBRARIES})
if(LIBPCAP_LIBRARY_DIRS)
    target_link_directories(tsembo_lib PUBLIC ${LIBPCAP_LIBRARY_DIRS})
endif()

target_compile_options(tsembo_lib PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall -Wextra -Wpedantic>
    $<$<CXX_COMPILER_ID:MSVC>:/W4>
)

add_executable(tsembo main.cpp)
target_link_libraries(tsembo PRIVATE tsembo_lib)
