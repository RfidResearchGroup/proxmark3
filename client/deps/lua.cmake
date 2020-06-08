add_library(pm3rrg_rdv4_lua STATIC
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

target_compile_definitions(pm3rrg_rdv4_lua PRIVATE LUA_COMPAT_ALL)

if (NOT MINGW)
    if (APPLE)
        target_compile_definitions(pm3rrg_rdv4_lua PRIVATE LUA_USE_MACOSX)
    elseif (ANDROID)
        # Required:
        add_definitions(-D"getlocaledecpoint\(\)='.'")
        # Same as for LUA_USE_LINUX except LUA_USE_POSIX and client-specific LUA_USE_READLINE
        target_compile_definitions(pm3rrg_rdv4_lua PRIVATE LUA_USE_DLOPEN LUA_USE_STRTODHEX LUA_USE_AFORMAT LUA_USE_LONGLONG)
        # Same as for LUA_USE_POSIX except client-specific LUA_USE_ISATTY. LUA_USE_MKSTEMP is needed.
        target_compile_definitions(pm3rrg_rdv4_lua PRIVATE LUA_USE_MKSTEMP LUA_USE_POPEN LUA_USE_ULONGJMP LUA_USE_GMTIME_R)
    else (APPLE)
        target_compile_definitions(pm3rrg_rdv4_lua PRIVATE LUA_USE_LINUX)
        target_link_libraries(pm3rrg_rdv4_lua INTERFACE dl)
    endif (APPLE)
endif (NOT MINGW)

target_include_directories(pm3rrg_rdv4_lua INTERFACE liblua)
target_compile_options(pm3rrg_rdv4_lua PRIVATE -Wall -Werror -O3)
set_property(TARGET pm3rrg_rdv4_lua PROPERTY POSITION_INDEPENDENT_CODE ON)
