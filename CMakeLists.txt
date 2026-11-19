# idemIP v0.2.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.25)
project(idemIP VERSION 0.2.0 LANGUAGES C)

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

# Determinism in the time domain: a padded call gives its result when its pad elapses, and the
# input does not set when. It is not a capability, because it parses no wire field. So it is not in
# the list above, and it is off unless a build asks for it. See src/time_determinism.h.
option(IDEMIP_ENABLE_TIME_DETERMINISM "Enable time determinism" OFF)

# The unit of the window in idemip_config.h, and whether a pad walks. COARSE states the window in
# milliseconds, and FINE and LITERAL state it in microseconds. COARSE and FINE walk a pad up on an
# overrun. LITERAL keeps the pad at its default. Every grade counts the pad in clock ticks.
set(IDEMIP_TIME_DETERMINISM_GRADE "FINE" CACHE STRING "The unit of the pad window, and whether a pad walks")
set_property(CACHE IDEMIP_TIME_DETERMINISM_GRADE PROPERTY STRINGS COARSE FINE LITERAL)

# The clock that a pad counts, which embed_clock.h selects. Each one that is set goes to every
# target as the embed_clock.h macro of the same field. embed_clock.h gives a build warning for each
# one that a build with time determinism leaves unset, and names the value that it took.
set(IDEMIP_CLOCK_HZ "" CACHE STRING "EMBED_CLOCK_HZ: ticks of the pad clock in one second")
set(IDEMIP_CLOCK_SOURCE "" CACHE STRING "EMBED_CLOCK_SOURCE: CALLER or OWN")
set_property(CACHE IDEMIP_CLOCK_SOURCE PROPERTY STRINGS "" CALLER OWN)
set(IDEMIP_CLOCK_CORE "" CACHE STRING "EMBED_CLOCK_CORE: the core of the pinned counter, with OWN")

# The benches, which are not tests: they measure and report and assert nothing, so ctest does not
# run them and a normal build does not carry them. They link the library rather than including its
# sources, so what they time is the translation unit this build produced under this build's flags.
option(IDEMIP_BENCH "Build the timing benches under test/bench" OFF)

# The fuzz harness, which is not a test either: it has no fixed input and nothing to pass. libFuzzer
# drives Dispatch.input over a mutated frame and what it reports is a crash, a sanitizer finding, or
# one of the invariants the harness reads back after every frame.
#
# The sanitizers reach the library and not only the harness, deliberately: the coverage feedback is
# what steers the mutations, and instrumenting only the harness would leave it steering on nothing.
# Link-time optimization is off for the same build, because the coverage counters it would fold are
# the ones being counted.
option(IDEMIP_FUZZ "Build the libFuzzer harness under test/fuzz" OFF)

if(IDEMIP_FUZZ)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        message(FATAL_ERROR "IDEMIP_FUZZ needs Clang: -fsanitize=fuzzer is clang's")
    endif()
    set(IDEMIP_LTO OFF CACHE BOOL "Link-time optimization, which is what folds the namespace indirection" FORCE)
    # -fno-sanitize-recover is what makes a finding stop the run: undefined behaviour is reported
    # and stepped over by default, and a fuzzer that steps over its own findings reports none.
    add_compile_options(-fsanitize=fuzzer-no-link,address,undefined -fno-sanitize-recover=all
                        -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=fuzzer-no-link,address,undefined)
endif()

# --- dependencies ------------------------------------------------------------
# embedded_types gives the vocabulary, and deps/ fetches it. MMgr gives the memory entries that src/
# calls by their own names, and the cells a program takes its borrows from. deps/ comes first, so
# MMgr uses the same embedded_types checkout.
#
# This block comes after the coverage and fuzz options. Their compile options then reach MMgr too,
# because the mem entries are code that the sanitizers and the coverage counters must see.
add_subdirectory(deps)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/include/MMgr/CMakeLists.txt")
    message(FATAL_ERROR "idemIP needs the include/MMgr submodule: git submodule update --init")
endif()
# The suites and benches of MMgr are for that repository. CMP0077 lets a normal variable here take
# precedence over the option() in MMgr. MMgr takes link-time optimization only where idemIP does,
# because a coverage or fuzz build turns it off for the whole program.
set(MMGR_BUILD_TESTS OFF)
set(MMGR_BUILD_BENCH OFF)
set(MMGR_LTO ${IDEMIP_LTO})
# MMgr's own sources take MMgr's warning policy, which MMGR_WERROR sets, and not the -Werror a build
# of idemIP puts in CMAKE_C_FLAGS. Inside include/MMgr the flags drop -Werror, and every other
# directory keeps them as they came.
set(IDEMIP_C_FLAGS "${CMAKE_C_FLAGS}")
string(REGEX REPLACE "(^| )-Werror( |$)" " " CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
add_subdirectory(include/MMgr EXCLUDE_FROM_ALL SYSTEM)
set(CMAKE_C_FLAGS "${IDEMIP_C_FLAGS}")

# --- the translation units each capability is ---------------------------------
# One list per capability, and a file appears in exactly one of them. An option that is off leaves
# its files out of the target, so a disabled capability reaches the compiler as no file at all.

set(IDEMIP_SOURCES "")
# The base modules every build carries: the wire-integer accessors, the RFC 1071 checksum taken
# over them, the epoch, and the readings taken onto it. None of these sits behind a capability.
list(APPEND IDEMIP_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/checksum.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ms.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/clock.c")

feature_sources(IDEMIP_SOURCES IDEMIP_ENABLE_ETHERNET
    src/core/dispatch.c
    src/core/stats.c
    src/core/tick.c
    src/core/timeouts.c
    src/ethernet/ethernet.c
    src/ethernet/mii.c
    src/ethernet/phy.c
    src/ethernet/vlan.c
    src/netif/dma.c
    src/netif/loopif.c
    src/netif/netif.c)

feature_sources(IDEMIP_SOURCES IDEMIP_ENABLE_IPV4
    src/acd/acd.c
    src/arp/arp.c
    src/arp/arp_table.c
    src/autoip/autoip.c
    src/dhcp/dhcp4.c
    src/icmp/icmp.c
    src/icmp/icmp_in.c
    src/igmp/igmp.c
    src/ip/ipv4.c
    src/ip/ip4_addr.c
    src/ip/ip4_forward.c
    src/ip/ip4_frag.c
    src/ip/ip4_reass.c
    src/ip/ip4_route.c
    src/pmtu/pmtu4.c)

feature_sources(IDEMIP_SOURCES IDEMIP_ENABLE_IPV6
    src/dhcp/dhcp6.c
    src/ethernet/ethip6.c
    src/icmp/icmpv6.c
    src/icmp/icmp6_in.c
    src/ip/ipv6.c
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
    src/tcp/tcp.c
    src/tcp/tcp_in.c
    src/tcp/tcp_isn.c
    src/tcp/tcp_out.c
    src/tcp/tcp_pcb.c)

feature_sources(IDEMIP_SOURCES IDEMIP_ENABLE_UDP
    src/dns/dns.c
    src/udp/udp.c
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

# The padded call. A feature, so CMake decides whether the library has it. The grade is a macro of
# the one translation unit. IDEMIP_TIME_DETERMINISM_GRADE is checked against the three names below.
if(IDEMIP_ENABLE_TIME_DETERMINISM)
    list(APPEND IDEMIP_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/time_determinism.c")
endif()

# --- the library -------------------------------------------------------------

add_library(idemip STATIC ${IDEMIP_SOURCES})

# The tree includes itself as "src/...", so the repo root is the one include path.
target_include_directories(idemip PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

# idemIP takes every machine word whose width is a power of two, as MMgr and embedded_types do: 16, 32
# or 64 bits. IDEMIP_WORD_BITS picks the word for the whole build, and the build links the MMgr
# aggregate built at that word. The default is 32 bits, the word of the ESP32 that idemIP is for.
#
# PUBLIC on all three, because a suite compiles src/idemip_config.h too. The include paths and the
# word must get to the suite as well as to the library.
set(IDEMIP_WORD_BITS "32" CACHE STRING "The machine word idemIP builds at, in bits: 16, 32 or 64")
set_property(CACHE IDEMIP_WORD_BITS PROPERTY STRINGS 16 32 64)
if(IDEMIP_WORD_BITS STREQUAL "16")
    target_compile_definitions(idemip PUBLIC EMBED_WORD_BITS=16)
    target_link_libraries(idemip PUBLIC embedded_types::embedded_types mmgr_word16)
elseif(IDEMIP_WORD_BITS STREQUAL "32")
    target_compile_definitions(idemip PUBLIC EMBED_WORD_BITS=32)
    target_link_libraries(idemip PUBLIC embedded_types::embedded_types mmgr_word32)
elseif(IDEMIP_WORD_BITS STREQUAL "64")
    # mmgr_host is MMgr's aggregate at the word this host's pointer width gives, which embed_types.h
    # derives. So a 64-bit word needs a host with 64-bit pointers.
    if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
        message(FATAL_ERROR "IDEMIP_WORD_BITS=64 needs a host with 64-bit pointers")
    endif()
    target_link_libraries(idemip PUBLIC embedded_types::embedded_types mmgr_host)
else()
    message(FATAL_ERROR "IDEMIP_WORD_BITS is '${IDEMIP_WORD_BITS}': it must be 16, 32 or 64")
endif()
message(STATUS "idemIP: a ${IDEMIP_WORD_BITS}-bit machine word")

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

# COARSE is 1, FINE is 2, LITERAL is 3, and time_determinism.h names them. The value is the number
# and not the word, so the header needs no string comparison in the preprocessor.
set(IDEMIP_TIME_DETERMINISM_GRADES COARSE FINE LITERAL)
if(NOT IDEMIP_TIME_DETERMINISM_GRADE IN_LIST IDEMIP_TIME_DETERMINISM_GRADES)
    message(FATAL_ERROR
        "IDEMIP_TIME_DETERMINISM_GRADE is '${IDEMIP_TIME_DETERMINISM_GRADE}': it must be one of "
        "${IDEMIP_TIME_DETERMINISM_GRADES}")
endif()
list(FIND IDEMIP_TIME_DETERMINISM_GRADES "${IDEMIP_TIME_DETERMINISM_GRADE}" IDEMIP_GRADE_INDEX)
math(EXPR IDEMIP_GRADE_VALUE "${IDEMIP_GRADE_INDEX} + 1")
target_compile_definitions(idemip PUBLIC IDEMIP_TIME_DETERMINISM_GRADE=${IDEMIP_GRADE_VALUE})

if(NOT IDEMIP_CLOCK_HZ STREQUAL "")
    target_compile_definitions(idemip PUBLIC EMBED_CLOCK_HZ=${IDEMIP_CLOCK_HZ}u)
endif()
if(NOT IDEMIP_CLOCK_SOURCE STREQUAL "")
    if(NOT IDEMIP_CLOCK_SOURCE MATCHES "^(CALLER|OWN)$")
        message(FATAL_ERROR "IDEMIP_CLOCK_SOURCE is '${IDEMIP_CLOCK_SOURCE}': it must be CALLER or OWN")
    endif()
    target_compile_definitions(idemip PUBLIC EMBED_CLOCK_SOURCE=EMBED_CLOCK_${IDEMIP_CLOCK_SOURCE})
endif()
if(NOT IDEMIP_CLOCK_CORE STREQUAL "")
    target_compile_definitions(idemip PUBLIC EMBED_CLOCK_CORE=${IDEMIP_CLOCK_CORE}u)
endif()

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

# --- the program around idemIP on this host -----------------------------------
# The sizes tool, a suite, a bench and the fuzz harness are each a program on this host. A program
# defines the three hooks locus_carcerum's turnstiles wait, wake and read the clock through:
# embed_word_wait, embed_word_wake and embed_clock_ns. It defines embed_thread_place too where the
# build sets MMGR_CARCER_REGIONS above 0. idemip_host_hooks holds the host definitions
# MMgr's own suites link, from include/MMgr/test/support/host_wait.c, compiled at idemIP's word. That
# file sets the GNU feature set itself, ahead of its first include.
#
# A suite, a bench and the fuzz harness also take their borrows as cells. idemip_test_program holds
# their memory: support/borrows.c, with the pool, the LocusCarcerum site over it and the owner table.
add_library(idemip_host_hooks OBJECT "${CMAKE_CURRENT_SOURCE_DIR}/include/MMgr/test/support/host_wait.c")
target_link_libraries(idemip_host_hooks PUBLIC idemip)
if(WIN32)
    # WaitOnAddress and WakeByAddressAll are in the synchronization library.
    target_link_libraries(idemip_host_hooks PUBLIC synchronization)
endif()

add_library(idemip_test_program OBJECT "${CMAKE_CURRENT_SOURCE_DIR}/test/support/borrows.c")
target_include_directories(idemip_test_program PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/test")
target_link_libraries(idemip_test_program PUBLIC idemip)

# --- tools -------------------------------------------------------------------
# The footprint is the compiler's arithmetic over idemip_config.h, not a figure kept by hand.

add_executable(idemip_sizes "${CMAKE_CURRENT_SOURCE_DIR}/tools/idemip_sizes.c")
target_link_libraries(idemip_sizes PRIVATE idemip idemip_warnings idemip_host_hooks)

# --- benches -----------------------------------------------------------------
# Measurement, not test: nothing here asserts, so ctest never sees these and BUILD_TESTING does not
# gate them. They link idemip, so the entries they time are the ones this build compiled, with this
# build's optimisation and LTO settings, rather than a copy recompiled beside them.

if(IDEMIP_BENCH)
    foreach(b bench_words bench_entries)
        add_executable(${b} "${CMAKE_CURRENT_SOURCE_DIR}/test/bench/${b}.c")
        # The benches take the suites' support headers, by the path a suite writes them.
        target_include_directories(${b} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/test")
        target_link_libraries(${b} PRIVATE idemip idemip_warnings idemip_test_program idemip_host_hooks)
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

# --- the fuzz harness ---------------------------------------------------------
# One target over one entry. fuzz_dispatch.c includes src/idemip.h, so building it is also the only
# compile the front door gets: nothing in the library includes it, and an application is the only
# other thing that would.

if(IDEMIP_FUZZ)
    add_executable(fuzz_dispatch "${CMAKE_CURRENT_SOURCE_DIR}/test/fuzz/fuzz_dispatch.c")
    # The harness takes the suites' support headers, by the path a suite writes them.
    target_include_directories(fuzz_dispatch PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/test")
    target_link_libraries(fuzz_dispatch PRIVATE idemip idemip_warnings idemip_test_program idemip_host_hooks)
    target_compile_options(fuzz_dispatch PRIVATE -fsanitize=fuzzer)
    target_link_options(fuzz_dispatch PRIVATE -fsanitize=fuzzer)
endif()

# --- examples -----------------------------------------------------------------
# An example is an application, so it links idemip through the same front door a consumer uses and
# takes the warning set the library takes. The tree is optional because it is not here yet: the
# guard keeps a configure step working in a checkout without it, and picks it up on the first
# configure after one lands. tools/build.py examples drives this option.

option(IDEMIP_EXAMPLES "Build the examples/ tree" OFF)

if(IDEMIP_EXAMPLES)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/examples/CMakeLists.txt")
        add_subdirectory(examples)
    else()
        message(STATUS "IDEMIP_EXAMPLES is ON, but examples/CMakeLists.txt is not in this tree")
    endif()
endif()

# --- tests -------------------------------------------------------------------

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()
