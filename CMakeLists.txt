# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.20)
project(idemIP VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(FeatureTree)

# Instruments every translation unit for gcov. A coverage build measures which lines the suites
# reach, so it takes no optimizer: -O0 keeps one line to one branch, and the Release -Os and the LTO
# below would fold the namespace indirection the measurement is meant to see through.
option(IDEMIP_COVERAGE "Build instrumented for gcov, which reports which lines the suites reach" OFF)

if(IDEMIP_COVERAGE)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "IDEMIP_COVERAGE needs GCC or Clang: --coverage is theirs")
    endif()
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
    add_compile_options(--coverage -O0)
    add_link_options(--coverage)
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# The namespace shape costs nothing once the compiler can see through a const function pointer,
# which it can at -Os, -O2 and with LTO. Release builds take all three.
option(IDEMIP_LTO "Link-time optimization, which is what folds the namespace indirection" ON)

if(IDEMIP_COVERAGE)
    set(IDEMIP_LTO OFF)
endif()

# --- capabilities ------------------------------------------------------------
# One option per capability, and the edges between them. CMake is the one source for the values: it
# selects the translation units below, passes each value as a definition the library and every
# consumer see, and test/ uses the same values to decide which suites exist.

set(IDEMIP_CAPABILITIES ETHERNET IPV4 IPV6 TCP UDP)

# The link layer is the root. Every other capability names the parent it sits on, and the refusal
# message is the one idemip_config.h stated, RFC citation and all.
add_root_option(IDEMIP_ENABLE_ETHERNET "Build the ETHERNET capability" ON)

add_child_option(IDEMIP_ENABLE_IPV4 "Build the IPV4 capability" ON
    "IDEMIP_ENABLE_IPV4 needs IDEMIP_ENABLE_ETHERNET: arp.h resolves to a 48-bit Ethernet address (RFC 826)"
    IDEMIP_ENABLE_ETHERNET)
add_child_option(IDEMIP_ENABLE_IPV6 "Build the IPV6 capability" ON
    "IDEMIP_ENABLE_IPV6 needs IDEMIP_ENABLE_ETHERNET: the link layer here is Ethernet II (RFC 2464)"
    IDEMIP_ENABLE_ETHERNET)
add_child_option(IDEMIP_ENABLE_TCP "Build the TCP capability" ON
    "IDEMIP_ENABLE_TCP needs IDEMIP_ENABLE_IPV4 or IDEMIP_ENABLE_IPV6: the checksum covers a pseudo-header"
    IDEMIP_ENABLE_IPV4 IDEMIP_ENABLE_IPV6)
add_child_option(IDEMIP_ENABLE_UDP "Build the UDP capability" ON
    "IDEMIP_ENABLE_UDP needs IDEMIP_ENABLE_IPV4 or IDEMIP_ENABLE_IPV6: the checksum covers a pseudo-header"
    IDEMIP_ENABLE_IPV4 IDEMIP_ENABLE_IPV6)

# Determinism in the time domain: each entry runs to a pad it tunes rather than to whatever its
# inputs cost. Not a capability - it selects no translation unit and parses no wire field - so it is
# not in the list above, and it is off unless a build asks for it. now(), stamp() and epoch() are
# there either way; this option is the fourth reading, determinism_pad(), and the per-entry word it
# needs. See src/clock.h.
option(IDEMIP_ENABLE_TIME_DETERMINISM "Enable time determinism" OFF)

# What a pad is measured in. COARSE is milliseconds and costs no reading of its own; FINE is
# microseconds, taken as a second reading beside the epoch; LITERAL is microseconds with the pad
# pinned to a measured ceiling rather than tuned. FINE is the default because every entry in this
# tree measures well under a millisecond, so COARSE would pad each one to many times its own cost.
set(IDEMIP_TIME_DETERMINISM_GRADE "FINE" CACHE STRING "What a determinism pad is measured in")
set_property(CACHE IDEMIP_TIME_DETERMINISM_GRADE PROPERTY STRINGS COARSE FINE LITERAL)

# The benches, which are not tests: they measure and report and assert nothing, so ctest does not
# run them and a normal build does not carry them. They link the library rather than including its
# sources, so what they time is the translation unit this build produced under this build's flags.
option(IDEMIP_BENCH "Build the timing benches under test/bench" OFF)

# --- the translation units each capability is ---------------------------------
# One list per capability, and a file appears in exactly one of them. An option that is off leaves
# its files out of the target, so a disabled capability reaches the compiler as no file at all.

set(IDEMIP_SOURCES "")

feature_sources(IDEMIP_SOURCES IDEMIP_ENABLE_ETHERNET
    src/core/dispatch.c
    src/core/stats.c
    src/core/tick.c
    src/core/timeouts.c
    src/ethernet/phy.c
    src/ethernet/vlan.c
    src/netif/dma.c
    src/netif/loopif.c
    src/netif/netif.c)

feature_sources(IDEMIP_SOURCES IDEMIP_ENABLE_IPV4
    src/acd/acd.c
    src/arp/arp_table.c
    src/autoip/autoip.c
    src/dhcp/dhcp4.c
    src/icmp/icmp_in.c
    src/igmp/igmp.c
    src/ip/ip4_addr.c
    src/ip/ip4_forward.c
    src/ip/ip4_frag.c
    src/ip/ip4_reass.c
    src/ip/ip4_route.c
    src/pmtu/pmtu4.c)

feature_sources(IDEMIP_SOURCES IDEMIP_ENABLE_IPV6
    src/dhcp/dhcp6.c
    src/ethernet/ethip6.c
    src/icmp/icmp6_in.c
    src/ip/ip6_addr.c
    src/ip/ip6_forward.c
    src/ip/ip6_frag.c
    src/ip/ip6_reass.c
    src/ip/ip6_select.c
    src/mld/mld6.c
    src/nd/dad.c
    src/nd/nd6.c
    src/nd/rdnss.c
    src/nd/slaac.c
    src/pmtu/pmtu6.c)

feature_sources(IDEMIP_SOURCES IDEMIP_ENABLE_TCP
    src/tcp/tcp_in.c
    src/tcp/tcp_isn.c
    src/tcp/tcp_out.c
    src/tcp/tcp_pcb.c)

feature_sources(IDEMIP_SOURCES IDEMIP_ENABLE_UDP
    src/dns/dns.c
    src/udp/udp_pcb.c
    src/udp/udplite.c)

# raw_pcb binds a protocol number on an IP layer, so either version carries it.
if(IDEMIP_ENABLE_IPV4 OR IDEMIP_ENABLE_IPV6)
    list(APPEND IDEMIP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/raw/raw_pcb.c")
endif()

# The pseudo-header every transport checksum covers: the version branch once, and one arm per
# version. A transport holds the version at run time, so the arm a build left out is still called
# and answers false.
list(APPEND IDEMIP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/ip/pseudo.c")
feature_source_swap(IDEMIP_SOURCES IDEMIP_ENABLE_IPV4 src/ip/pseudo_v4.c src/ip/pseudo_v4_off.c)
feature_source_swap(IDEMIP_SOURCES IDEMIP_ENABLE_IPV6 src/ip/pseudo_v6.c src/ip/pseudo_v6_off.c)

# --- the library -------------------------------------------------------------

add_library(idemip STATIC ${IDEMIP_SOURCES})

# The tree includes itself as "src/...", so the repo root is the one include path.
target_include_directories(idemip PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

foreach(cap ${IDEMIP_CAPABILITIES})
    if(IDEMIP_ENABLE_${cap})
        target_compile_definitions(idemip PUBLIC IDEMIP_ENABLE_${cap}=1)
    else()
        target_compile_definitions(idemip PUBLIC IDEMIP_ENABLE_${cap}=0)
    endif()
endforeach()

if(IDEMIP_ENABLE_TIME_DETERMINISM)
    target_compile_definitions(idemip PUBLIC IDEMIP_ENABLE_TIME_DETERMINISM=1)
else()
    target_compile_definitions(idemip PUBLIC IDEMIP_ENABLE_TIME_DETERMINISM=0)
endif()

# COARSE is 1, FINE is 2, LITERAL is 3, and clock.h names them. The value is passed as the number
# rather than the word so the header needs no string comparison in the preprocessor.
set(IDEMIP_TIME_DETERMINISM_GRADES COARSE FINE LITERAL)
if(NOT IDEMIP_TIME_DETERMINISM_GRADE IN_LIST IDEMIP_TIME_DETERMINISM_GRADES)
    message(FATAL_ERROR
        "IDEMIP_TIME_DETERMINISM_GRADE is '${IDEMIP_TIME_DETERMINISM_GRADE}': it must be one of "
        "${IDEMIP_TIME_DETERMINISM_GRADES}")
endif()
list(FIND IDEMIP_TIME_DETERMINISM_GRADES "${IDEMIP_TIME_DETERMINISM_GRADE}" IDEMIP_GRADE_INDEX)
math(EXPR IDEMIP_GRADE_VALUE "${IDEMIP_GRADE_INDEX} + 1")
target_compile_definitions(idemip PUBLIC IDEMIP_TIME_DETERMINISM_GRADE=${IDEMIP_GRADE_VALUE})

list(LENGTH IDEMIP_SOURCES IDEMIP_SOURCE_COUNT)
message(STATUS "idemIP: ${IDEMIP_SOURCE_COUNT} translation units")

# The warning set, on an INTERFACE target so it reaches the test suites too. Attached PRIVATE to
# the library it never compiled most of the tree: no .c in src/ includes tcp.h or ipv6.h or
# udp.h, so those headers were built only by a test TU, which had no warning flags at all.
add_library(idemip_warnings INTERFACE)
target_compile_options(idemip_warnings INTERFACE
    $<$<C_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wshadow;-Wconversion;-Wsign-conversion;-Wcast-align;-Wundef>
)

target_compile_options(idemip PRIVATE
    $<$<C_COMPILER_ID:GNU,Clang>:-Wstrict-prototypes;-Wmissing-prototypes>
    $<$<AND:$<C_COMPILER_ID:GNU,Clang>,$<CONFIG:Release>>:-Os>
)
target_link_libraries(idemip PRIVATE idemip_warnings)

if(IDEMIP_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IDEMIP_IPO_OK OUTPUT IDEMIP_IPO_WHY)
    if(IDEMIP_IPO_OK)
        set_property(TARGET idemip PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    else()
        message(STATUS "idemIP: LTO unavailable, ${IDEMIP_IPO_WHY}")
    endif()
endif()

# --- tools -------------------------------------------------------------------
# The footprint is the compiler's arithmetic over idemip_config.h, not a figure kept by hand.

add_executable(idemip_sizes "${CMAKE_CURRENT_SOURCE_DIR}/tools/idemip_sizes.c")
target_link_libraries(idemip_sizes PRIVATE idemip)

# --- benches -----------------------------------------------------------------
# Measurement, not test: nothing here asserts, so ctest never sees these and BUILD_TESTING does not
# gate them. They link idemip, so the entries they time are the ones this build compiled, with this
# build's optimisation and LTO settings, rather than a copy recompiled beside them.

if(IDEMIP_BENCH)
    foreach(b bench_words bench_entries)
        add_executable(${b} "${CMAKE_CURRENT_SOURCE_DIR}/test/bench/${b}.c")
        target_link_libraries(${b} PRIVATE idemip)
        # The bench takes the library's own optimisation, so the two sides of a comparison are
        # compiled the same way. A bench built at a different level than the code it links measures
        # the difference between the two builds and calls it a result.
        target_compile_options(${b} PRIVATE
            $<$<AND:$<C_COMPILER_ID:GNU,Clang>,$<CONFIG:Release>>:-O2>)
        if(b STREQUAL "bench_words")
            # bench_words models a machine whose word is 16, 32 or 64 bits wide, so the compiler must
            # not widen past the word the row names. This host does sixteen octets at a time given the
            # chance, and then every row reads the same and none of them is about a word. As a
            # `#pragma GCC optimize` inside the file this was unreliable - it can reset the rest of the
            # optimisation level with it - so it is a flag on the one target that wants it.
            target_compile_options(${b} PRIVATE
                $<$<C_COMPILER_ID:GNU,Clang>:-fno-tree-vectorize>)
        endif()
        if(IDEMIP_LTO AND IDEMIP_IPO_OK)
            set_property(TARGET ${b} PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
        endif()
    endforeach()
endif()

# --- tests -------------------------------------------------------------------

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()
