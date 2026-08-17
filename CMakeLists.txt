# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.20)
project(idemIP VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# The namespace shape costs nothing once the compiler can see through a const function pointer,
# which it can at -Os, -O2 and with LTO. Release builds take all three.
option(IDEMIP_LTO "Link-time optimization, which is what folds the namespace indirection" ON)

# --- capabilities ------------------------------------------------------------
# Every capability header wraps its declarations in its gate, so a capability that is off compiles
# to nothing. CMake is the one source for the values: it passes each as a definition the library
# and every consumer see, and test/ uses the same values to decide which suites exist. A gate set
# only in idemip_config.h would be invisible to the build, and a suite for a disabled capability
# would then fail to compile.

set(IDEMIP_CAPABILITIES ETHERNET IPV4 IPV6 TCP UDP)
foreach(cap ${IDEMIP_CAPABILITIES})
    option(IDEMIP_ENABLE_${cap} "Build the ${cap} capability" ON)
endforeach()

# --- the library -------------------------------------------------------------

file(GLOB_RECURSE IDEMIP_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/idemIP/*.c")

add_library(idemip STATIC ${IDEMIP_SOURCES})

# The tree includes itself as "idemIP/...", so the repo root is the one include path.
target_include_directories(idemip PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

foreach(cap ${IDEMIP_CAPABILITIES})
    if(IDEMIP_ENABLE_${cap})
        target_compile_definitions(idemip PUBLIC IDEMIP_ENABLE_${cap}=1)
    else()
        target_compile_definitions(idemip PUBLIC IDEMIP_ENABLE_${cap}=0)
    endif()
endforeach()

# The warning set, on an INTERFACE target so it reaches the test suites too. Attached PRIVATE to
# the library it never compiled most of the tree: no .c in idemIP/ includes tcp.h or ipv6.h or
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

# --- tests -------------------------------------------------------------------

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()
