# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

# --- embedded_types ----------------------------------------------------------
# The dispatch tables, the call shape, the truth value, the word and the compiler wrappers come from
# embedded_types. idemIP and MMgr both use it, and this declaration comes first. FetchContent keeps
# the first declaration of a name, so MMgr's declaration of embedded_types then uses this checkout.
#
# SOURCE_DIR puts the checkout at deps/embedded_types, so each build tree in this clone uses the
# same one. FetchContent keeps its own records in the build tree.
include(FetchContent)

FetchContent_Declare(
    embedded_types
    GIT_REPOSITORY https://github.com/dstroy0/embedded_types.git
    GIT_TAG main
    GIT_SHALLOW TRUE
    SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/embedded_types"
    SYSTEM)

# The suites of embedded_types are for that repository. This build compiles the suites of idemIP.
set(EMBEDDED_TYPES_BUILD_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(embedded_types)
