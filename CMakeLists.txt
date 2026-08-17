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

# --- the library -------------------------------------------------------------

file(GLOB_RECURSE IDEMIP_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/idemIP/*.c")

add_library(idemip STATIC ${IDEMIP_SOURCES})

# The tree includes itself as "idemIP/...", so the repo root is the one include path.
target_include_directories(idemip PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

target_compile_options(idemip PRIVATE
    $<$<C_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wshadow;-Wconversion;-Wsign-conversion;-Wcast-align;-Wstrict-prototypes;-Wmissing-prototypes;-Wundef>
    $<$<AND:$<C_COMPILER_ID:GNU,Clang>,$<CONFIG:Release>>:-Os>
)

if(IDEMIP_LTO)
    include(CheckIPOSupported)
    check_ipo_supported(RESULT IDEMIP_IPO_OK OUTPUT IDEMIP_IPO_WHY)
    if(IDEMIP_IPO_OK)
        set_property(TARGET idemip PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
    else()
        message(STATUS "idemIP: LTO unavailable, ${IDEMIP_IPO_WHY}")
    endif()
endif()

# --- tests -------------------------------------------------------------------

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(test)
endif()
