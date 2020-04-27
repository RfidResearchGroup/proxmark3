add_library(lua STATIC
        liblua/lapi.c
        liblua/lcode.c
        liblua/lctype.c
        liblua/ldebug.c
        liblua/ldo.c
        liblua/ldump.c
        liblua/lfunc.c
        liblua/lgc.c
        liblua/llex.c
        liblua/lmem.c
        liblua/lobject.c
        liblua/lopcodes.c
        liblua/lparser.c
        liblua/lstate.c
        liblua/lstring.c
        liblua/ltable.c
        liblua/ltm.c
        liblua/lundump.c
        liblua/lvm.c
        liblua/lzio.c
        liblua/lauxlib.c
        liblua/lbaselib.c
        liblua/lbitlib.c
        liblua/lcorolib.c
        liblua/ldblib.c
        liblua/liolib.c
        liblua/lmathlib.c
        liblua/loslib.c
        liblua/lstrlib.c
        liblua/ltablib.c
        liblua/loadlib.c
        liblua/linit.c
)

target_compile_definitions(lua PRIVATE LUA_COMPAT_ALL)

if (NOT MINGW)
    if (APPLE)
        target_compile_definitions(lua PRIVATE LUA_USE_MACOSX)
    else (APPLE)
        target_compile_definitions(lua PRIVATE LUA_USE_LINUX)
        target_link_libraries(lua INTERFACE dl)
    endif (APPLE)
endif (NOT MINGW)

target_include_directories(lua INTERFACE liblua)
target_compile_options(lua PRIVATE -Wall -Werror -O3)
