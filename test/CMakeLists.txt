# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# One CTest target per suite. A suite is a directory holding exactly one .c with file-scope
# `void test_<name>(void)` cases; harness.py turns that into unity_runner.c through Unity's own
# generator, and refuses a suite whose cases the generator would walk past.

include(FetchContent)

FetchContent_Declare(
    unity
    GIT_REPOSITORY https://github.com/ThrowTheSwitch/Unity.git
    GIT_TAG        v2.6.1
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(unity)

set(IDEMIP_UNITY_RB "${unity_SOURCE_DIR}/auto/generate_test_runner.rb")

find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(IDEMIP_HARNESS "${CMAKE_CURRENT_SOURCE_DIR}/harness.py")

# test/ is exempt from the src/ style rules, so a suite reads as plain host C.
file(GLOB_RECURSE IDEMIP_SUITE_SOURCES CONFIGURE_DEPENDS
     "${CMAKE_CURRENT_SOURCE_DIR}/unit/*/test_*/test_*.c"
     "${CMAKE_CURRENT_SOURCE_DIR}/integration/test_*/test_*.c")

if(NOT IDEMIP_SUITE_SOURCES)
    message(WARNING "idemIP: no test suites found under test/unit or test/integration")
endif()

foreach(suite_src ${IDEMIP_SUITE_SOURCES})
    get_filename_component(suite_dir "${suite_src}" DIRECTORY)
    get_filename_component(suite_name "${suite_dir}" NAME)
    set(runner "${suite_dir}/unity_runner.c")

    # Regenerated whenever the cases change, so a new case is registered without re-configuring.
    add_custom_command(
        OUTPUT "${runner}"
        COMMAND ${Python3_EXECUTABLE} "${IDEMIP_HARNESS}" runners gen "${suite_dir}" --unity "${IDEMIP_UNITY_RB}"
        DEPENDS "${suite_src}" "${IDEMIP_HARNESS}"
        COMMENT "idemIP: generating Unity runner for ${suite_name}"
        VERBATIM
    )

    add_executable(${suite_name} "${suite_src}" "${runner}" "${unity_SOURCE_DIR}/src/unity.c")
    target_include_directories(${suite_name} PRIVATE
        "${unity_SOURCE_DIR}/src"
        "${CMAKE_CURRENT_SOURCE_DIR}"
    )
    target_link_libraries(${suite_name} PRIVATE idemip)
    set_target_properties(${suite_name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test")

    add_test(NAME ${suite_name} COMMAND ${suite_name})
endforeach()

list(LENGTH IDEMIP_SUITE_SOURCES IDEMIP_SUITE_COUNT)
message(STATUS "idemIP: ${IDEMIP_SUITE_COUNT} test suites")
