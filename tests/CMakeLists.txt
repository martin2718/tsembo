find_package(GTest REQUIRED)
include(GoogleTest)

# The system-provided GoogleTest is built against the pre-C++11 libstdc++ ABI.
# Detect that from the library's symbols and propagate the matching ABI macro
# to every test target AND to tsembo_lib so they link cleanly.
get_target_property(_gtest_loc GTest::gtest LOCATION)
if(_gtest_loc AND EXISTS "${_gtest_loc}")
    execute_process(
        COMMAND nm "${_gtest_loc}"
        OUTPUT_VARIABLE _gtest_symbols
        ERROR_QUIET
    )
    if(NOT _gtest_symbols MATCHES "cxx11")
        message(STATUS "tsembo tests: detected GTest without cxx11 in symbol names; defaulting to C++11 ABI for compatibility")
    endif()
    # Ensure project and tests use the C++11 libstdc++ ABI to match system GTest
    target_compile_definitions(tsembo_lib PUBLIC _GLIBCXX_USE_CXX11_ABI=1)
endif()

function(tsembo_add_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE GTest::gtest GTest::gtest_main tsembo_lib)
    target_compile_definitions(${name} PUBLIC _GLIBCXX_USE_CXX11_ABI=1)
    gtest_discover_tests(${name})
endfunction()

tsembo_add_test(test_big_endian_integer)
tsembo_add_test(test_ascii_char_string)
tsembo_add_test(test_message_parser)
tsembo_add_test(test_indicative_volume_book)
