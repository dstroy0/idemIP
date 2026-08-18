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

# Which capabilities each suite needs, as a list. A suite missing any of them is not built, because
# the header compiled to nothing and the suite would fail on undeclared constants. It is SKIPPED
# LOUDLY: silently dropping it would leave a passing run that tested less than it looks like.
#
# The list is what a suite that joins capabilities needs: core/dispatch walks a frame to an IPv4 or
# IPv6 header and on to a TCP or UDP binding, so its suite needs all four. Unity's runner generator
# reads the case names out of the source text and does not see a preprocessor conditional, so a case
# cannot be compiled out of a suite: the whole suite is what a capability gates.
set(IDEMIP_SUITE_CAP_test_ethernet ETHERNET)
set(IDEMIP_SUITE_CAP_test_mii      ETHERNET)
set(IDEMIP_SUITE_CAP_test_phy      ETHERNET)
set(IDEMIP_SUITE_CAP_test_netif    ETHERNET IPV6)
set(IDEMIP_SUITE_CAP_test_loopif   ETHERNET IPV6)
set(IDEMIP_SUITE_CAP_test_dma      ETHERNET)
set(IDEMIP_SUITE_CAP_test_vlan     ETHERNET)
# ethip6.h opens under IPV6: RFC 2464 derives IPv6 addresses, and IPV6 already requires ETHERNET.
set(IDEMIP_SUITE_CAP_test_ethip6   IPV6)
set(IDEMIP_SUITE_CAP_test_arp      IPV4)
set(IDEMIP_SUITE_CAP_test_arp_table IPV4)
set(IDEMIP_SUITE_CAP_test_ip4_route IPV4)
set(IDEMIP_SUITE_CAP_test_ip4_forward IPV4)
set(IDEMIP_SUITE_CAP_test_ip4_reass IPV4)
set(IDEMIP_SUITE_CAP_test_ip4_frag IPV4)
set(IDEMIP_SUITE_CAP_test_ip4_addr IPV4)
set(IDEMIP_SUITE_CAP_test_ipv4     IPV4)
set(IDEMIP_SUITE_CAP_test_icmp     IPV4)
set(IDEMIP_SUITE_CAP_test_icmp_in  IPV4)
set(IDEMIP_SUITE_CAP_test_acd      IPV4)
set(IDEMIP_SUITE_CAP_test_autoip   IPV4)
set(IDEMIP_SUITE_CAP_test_igmp     IPV4)
set(IDEMIP_SUITE_CAP_test_pmtu4    IPV4)
set(IDEMIP_SUITE_CAP_test_pmtu6    IPV6)
set(IDEMIP_SUITE_CAP_test_ipv6     IPV6)
set(IDEMIP_SUITE_CAP_test_icmpv6   IPV6)
set(IDEMIP_SUITE_CAP_test_icmp6_in IPV6)
set(IDEMIP_SUITE_CAP_test_ip6_addr IPV6)
set(IDEMIP_SUITE_CAP_test_ip6_select IPV6)
set(IDEMIP_SUITE_CAP_test_ip6_reass IPV6)
set(IDEMIP_SUITE_CAP_test_ip6_frag IPV6)
set(IDEMIP_SUITE_CAP_test_ip6_forward IPV6)
set(IDEMIP_SUITE_CAP_test_nd6      IPV6)
set(IDEMIP_SUITE_CAP_test_dad      IPV6)
set(IDEMIP_SUITE_CAP_test_slaac    IPV6)
set(IDEMIP_SUITE_CAP_test_rdnss    IPV6)
set(IDEMIP_SUITE_CAP_test_mld6     IPV6)
set(IDEMIP_SUITE_CAP_test_tcp      TCP)
set(IDEMIP_SUITE_CAP_test_udp      UDP)
set(IDEMIP_SUITE_CAP_test_tcp_pcb  TCP)
set(IDEMIP_SUITE_CAP_test_tcp_isn  TCP)
set(IDEMIP_SUITE_CAP_test_tcp_in   TCP)
# tcp_out builds an RFC 8200 sec 8.1 pseudo-header in one case, so its suite needs IPv6 as well.
set(IDEMIP_SUITE_CAP_test_tcp_out  TCP IPV6)
set(IDEMIP_SUITE_CAP_test_udp_pcb  UDP)
# udplite's suite checks the RFC 8200 sec 8.1 pseudo-header as well as the RFC 768 one.
set(IDEMIP_SUITE_CAP_test_udplite  UDP IPV6)
# raw_pcb.h opens under IPV4 or IPV6, either one being an IP layer to bind a protocol number on. Its
# suite exercises both, so it needs both.
set(IDEMIP_SUITE_CAP_test_raw_pcb  IPV4 IPV6)
set(IDEMIP_SUITE_CAP_test_dhcp4    IPV4)
set(IDEMIP_SUITE_CAP_test_dhcp6    IPV6)
set(IDEMIP_SUITE_CAP_test_dns      UDP)
# core/ has no gate of its own, and every other capability requires ETHERNET, so that is the gate a
# core unit is present under.
set(IDEMIP_SUITE_CAP_test_timeouts ETHERNET)
set(IDEMIP_SUITE_CAP_test_stats    ETHERNET)
# tick drives the receive path and the IPv4 services; its IPv6 steps are behind IDEMIP_ENABLE_IPV6.
set(IDEMIP_SUITE_CAP_test_tick     IPV4)
# dispatch is the join, so its suite carries one frame all the way to a binding in each of the four.
set(IDEMIP_SUITE_CAP_test_dispatch IPV4 IPV6 TCP UDP)
# test_checksum has no gate: checksum.h is a base facility, ungated like ProtoCore's mmgr/endian.h.
# test_loopback drives ARP (RFC 826), ICMP (RFC 792), IPv4 fragmentation (RFC 791 sec 3.2), UDP and
# TCP over two instances. Every one of those exchanges is IPv4, and IDEMIP_ENABLE_IPV4 already
# requires IDEMIP_ENABLE_ETHERNET, so IPV4 is the gate whose absence removes the whole suite. The
# map holds one capability per suite, the same limit test_raw_pcb records above: a build with IPV4
# on and TCP or UDP off would still not compile this suite.
set(IDEMIP_SUITE_CAP_test_loopback IPV4)

set(IDEMIP_SKIPPED "")

foreach(suite_src ${IDEMIP_SUITE_SOURCES})
    get_filename_component(suite_dir "${suite_src}" DIRECTORY)
    get_filename_component(suite_name "${suite_dir}" NAME)
    set(runner "${suite_dir}/unity_runner.c")

    set(missing "")
    foreach(cap IN LISTS IDEMIP_SUITE_CAP_${suite_name})
        if(NOT IDEMIP_ENABLE_${cap})
            list(APPEND missing "IDEMIP_ENABLE_${cap}=OFF")
        endif()
    endforeach()
    if(missing)
        list(JOIN missing ", " missing_text)
        list(APPEND IDEMIP_SKIPPED "${suite_name} (${missing_text})")
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
