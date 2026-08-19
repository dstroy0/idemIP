# idemIP v0.1.0 - Copyright (C) 2026 Douglas Quigg (dstroy0) <dquigg123@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# The feature tree: the options a build selects capabilities with, and the edge from each child to
# the parent it sits on. A capability is a set of translation units, so an option that is off keeps
# its files out of the target and the branch it selects is the only one the compiler is given.

# A capability with nothing under it.
function(add_root_option name doc default)
    option(${name} "${doc}" ${default})
endfunction()

# A capability and the parents it sits on, one of which must be on. Declared child to parent, so a
# chain resolves as it is read: a parent is declared before the children that name it.
function(add_child_option name doc default why)
    option(${name} "${doc}" ${default})
    if(NOT ${name})
        return()
    endif()
    foreach(parent IN LISTS ARGN)
        if(${parent})
            return()
        endif()
    endforeach()
    message(FATAL_ERROR "${why}")
endfunction()

# Refuses a set with more than one member on, and turns the fallback on when the set is empty.
function(enforce_mutually_exclusive_with_fallback fallback message)
    set(on "")
    foreach(opt IN LISTS ARGN)
        if(${opt})
            list(APPEND on ${opt})
        endif()
    endforeach()
    list(LENGTH on count)
    if(count GREATER 1)
        list(JOIN on ", " named)
        message(FATAL_ERROR "${message} (${named})")
    elseif(count EQUAL 0)
        set(${fallback} ON CACHE BOOL "" FORCE)
        message(STATUS "FeatureTree: the set is empty, falling back to ${fallback}")
    endif()
endfunction()

# Appends on_path when the capability is on and off_path when it is not, so a caller that cannot
# branch at build time still finds one definition. Paths are relative to the calling file.
function(feature_source_swap out_var capability on_path off_path)
    if(${capability})
        set(pick "${on_path}")
    else()
        set(pick "${off_path}")
    endif()
    set(${out_var} ${${out_var}} "${CMAKE_CURRENT_SOURCE_DIR}/${pick}" PARENT_SCOPE)
endfunction()

# Appends the named capability's sources to out_var when its option is on. A path is relative to
# the directory of the file that calls this.
function(feature_sources out_var capability)
    if(NOT ${capability})
        return()
    endif()
    set(paths "")
    foreach(rel IN LISTS ARGN)
        list(APPEND paths "${CMAKE_CURRENT_SOURCE_DIR}/${rel}")
    endforeach()
    set(${out_var} ${${out_var}} ${paths} PARENT_SCOPE)
endfunction()
