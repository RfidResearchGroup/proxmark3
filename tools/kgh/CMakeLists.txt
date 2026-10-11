#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------

cmake_minimum_required(VERSION 3.10)
project(legic_kgh_tool)

set(PM3_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)

add_subdirectory(${PM3_ROOT}/client/experimental_lib ${CMAKE_BINARY_DIR}/experimental_lib)

add_executable(legic_kgh_tool legic_kgh_tool.c)
target_link_libraries(legic_kgh_tool PRIVATE pm3rrg_rdv4_static)
target_include_directories(legic_kgh_tool PRIVATE
        ${PM3_ROOT}/common
        ${PM3_ROOT}/client/include
        ${PM3_ROOT}/client/src
        ${PM3_ROOT}/include
)

if (MINGW)
    target_link_options(legic_kgh_tool PRIVATE -static -static-libgcc)
endif()
