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

# Which capability each suite needs. A suite whose capability is off is not built, because its
# header compiled to nothing and the suite would fail on undeclared constants. It is SKIPPED
# LOUDLY: silently dropping it would leave a passing run that tested less than it looks like.
set(IDEMIP_SUITE_CAP_test_ethernet ETHERNET)
set(IDEMIP_SUITE_CAP_test_mii      ETHERNET)
set(IDEMIP_SUITE_CAP_test_phy      ETHERNET)
set(IDEMIP_SUITE_CAP_test_netif    ETHERNET)
set(IDEMIP_SUITE_CAP_test_loopif   ETHERNET)
set(IDEMIP_SUITE_CAP_test_dma      ETHERNET)
set(IDEMIP_SUITE_CAP_test_arp      IPV4)
set(IDEMIP_SUITE_CAP_test_arp_table IPV4)
set(IDEMIP_SUITE_CAP_test_ip4_route IPV4)
set(IDEMIP_SUITE_CAP_test_ip4_reass IPV4)
set(IDEMIP_SUITE_CAP_test_ip4_addr IPV4)
set(IDEMIP_SUITE_CAP_test_ipv4     IPV4)
set(IDEMIP_SUITE_CAP_test_icmp     IPV4)
set(IDEMIP_SUITE_CAP_test_acd      IPV4)
set(IDEMIP_SUITE_CAP_test_autoip   IPV4)
set(IDEMIP_SUITE_CAP_test_igmp     IPV4)
set(IDEMIP_SUITE_CAP_test_ipv6     IPV6)
set(IDEMIP_SUITE_CAP_test_icmpv6   IPV6)
set(IDEMIP_SUITE_CAP_test_ip6_addr IPV6)
set(IDEMIP_SUITE_CAP_test_ip6_select IPV6)
set(IDEMIP_SUITE_CAP_test_ip6_reass IPV6)
set(IDEMIP_SUITE_CAP_test_nd6      IPV6)
set(IDEMIP_SUITE_CAP_test_mld6     IPV6)
set(IDEMIP_SUITE_CAP_test_tcp      TCP)
set(IDEMIP_SUITE_CAP_test_udp      UDP)
set(IDEMIP_SUITE_CAP_test_tcp_pcb  TCP)
set(IDEMIP_SUITE_CAP_test_tcp_isn  TCP)
set(IDEMIP_SUITE_CAP_test_tcp_in   TCP)
set(IDEMIP_SUITE_CAP_test_tcp_out  TCP)
set(IDEMIP_SUITE_CAP_test_udp_pcb  UDP)
# raw_pcb.h opens under IPV4 or IPV6, either one being an IP layer to bind a protocol number on. The
# map holds one capability per suite, so this suite is tied to IPV4 and is skipped loudly in an
# IPv6-only build even though the header would compile.
set(IDEMIP_SUITE_CAP_test_raw_pcb  IPV4)
set(IDEMIP_SUITE_CAP_test_dhcp4    IPV4)
set(IDEMIP_SUITE_CAP_test_dhcp6    IPV6)
set(IDEMIP_SUITE_CAP_test_dns      UDP)
# core/ has no gate of its own, and every other capability requires ETHERNET, so that is the gate a
# core unit is present under.
set(IDEMIP_SUITE_CAP_test_timeouts ETHERNET)
set(IDEMIP_SUITE_CAP_test_stats    ETHERNET)
# test_checksum has no gate: checksum.h is a base facility, ungated like ProtoCore's mmgr/endian.h.

set(IDEMIP_SKIPPED "")

foreach(suite_src ${IDEMIP_SUITE_SOURCES})
    get_filename_component(suite_dir "${suite_src}" DIRECTORY)
    get_filename_component(suite_name "${suite_dir}" NAME)
    set(runner "${suite_dir}/unity_runner.c")

    set(cap "${IDEMIP_SUITE_CAP_${suite_name}}")
    if(cap AND NOT IDEMIP_ENABLE_${cap})
        list(APPEND IDEMIP_SKIPPED "${suite_name} (IDEMIP_ENABLE_${cap}=OFF)")
        continue()
    endif()

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
    target_link_libraries(${suite_name} PRIVATE idemip idemip_warnings)
    set_target_properties(${suite_name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test")

    add_test(NAME ${suite_name} COMMAND ${suite_name})
    list(APPEND IDEMIP_BUILT "${suite_name}")
endforeach()

list(LENGTH IDEMIP_BUILT IDEMIP_BUILT_COUNT)
message(STATUS "idemIP: ${IDEMIP_BUILT_COUNT} test suites")
if(IDEMIP_SKIPPED)
    list(LENGTH IDEMIP_SKIPPED IDEMIP_SKIPPED_COUNT)
    message(STATUS "idemIP: ${IDEMIP_SKIPPED_COUNT} suites NOT built, their capability is off:")
    foreach(s ${IDEMIP_SKIPPED})
        message(STATUS "idemIP:   ${s}")
    endforeach()
endif()
