add_definitions(-DLUA_COMPAT_ALL $(SYSCFLAGS))
include_directories(liblua)

set(SYSCFLAGS "-DLUA_COMPAT_ALL")

if (UNIX)
    set(SYSCFLAGS "-DLUA_USE_LINUX")
endif (UNIX)

if (WIN32)
    set(SYSCFLAGS "-DLUA_USE_LINUX")
endif (WIN32)

if (MINGW)
    set(SYSCFLAGS "-DLUA_COMPAT_ALL $(SYSCFLAGS)")
endif (MINGW)

if (APPLE)
    set(SYSCFLAGS "-DLUA_USE_MACOSX")
endif (APPLE)

add_definitions($(SYSCFLAGS))

add_library(lua
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

