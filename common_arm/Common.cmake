#[[ VPATH in cmake is unavailable, so we need append path for source or include dir...
# Also search prerequisites in the common directory (for usb.c), the fpga directory (for fpga.bit), and the lz4 directory
VPATH = . ../common_arm ../common ../common/crapto1 ../common/mbedtls ../common/lz4 ../fpga ../armsrc/Standalone ../common/hitag2
]]

set(ARMCFLAGS -mthumb-interwork -fno-builtin)
set(DEFCFLAGS -Wall -Werror -Os -pedantic -fstrict-aliasing -pipe)

# Some more warnings we want as errors:
set(DEFCFLAGS ${DEFCFLAGS}
    -Wbad-function-cast
    -Wchar-subscripts
    -Wundef
    -Wunused
    -Wuninitialized
    -Wpointer-arith
    -Wformat
    -Wformat-security
    -Winit-self
    -Wmissing-include-dirs
    -Wnested-externs
    -Wempty-body
    -Wignored-qualifiers
    -Wmissing-field-initializers
    -Wtype-limits)

# Some more warnings we need first to eliminate, so temporarely tolerated:
set(DEFCFLAGS ${DEFCFLAGS}
    -Wshadow
    -Wno-error=shadow
    -Winline
    -Wno-error=inline
    -Wmissing-prototypes
    -Wno-error=missing-prototypes
    -Wmissing-declarations
    -Wno-error=missing-declarations
    -Wstrict-prototypes
    -Wno-error=strict-prototypes
)

# still vsnprintf etc to sort out...
# for makefile: DEFCFLAGS += -Wredundant-decls -Wno-error=redundant-decls
# for makefile: DEFCFLAGS += -Wcast-align -Wno-error=cast-align

# Next ones are activated only if GCCEXTRA=1
set(EXTRACFLAGS
    -Wunused-parameter
    -Wno-error=unused-parameter
    -Wswitch-enum
    -Wno-error=switch-enum
    -Wsign-compare
    -Wno-error=sign-compare
    -Wold-style-definition
    -Wno-error=old-style-definition
    -Wconversion
    -Wno-error=conversion
    -Wno-error=sign-conversion
    -Wno-error=float-conversion
)

# unknown to clang or old gcc:
# First we activate Wextra then we explicitly list those we know about
# Those without -Wno-error are supposed to be completely solved
set(GCCEXTRACFLAGS -Wextra)

# unknown to arm-none-eabi/4.9.3
set(GCCEXTRACFLAGS ${GCCEXTRACFLAGS}
    -Wwrite-strings
    -Wno-error=discarded-qualifiers)

set(GCCEXTRACFLAGS ${GCCEXTRACFLAGS}
    -Wold-style-declaration
    -Wno-error=old-style-declaration
    -Wimplicit-fallthrough=3
    -Wno-error=implicit-fallthrough
    -Wclobbered
    -Wcast-function-type
    -Wmissing-parameter-type
    -Woverride-init
    -Wshift-negative-value
    -Wunused-but-set-parameter
)

# Not yet enabled in DEFCFLAGS:
set(GCCEXTRACFLAGS ${GCCEXTRACFLAGS}
    -Wredundant-decls
    -Wno-error=redundant-decls
    -Wcast-align
    -Wno-error=cast-align
)

if (GCCEXTRA)
    set(DEFCFLAGS ${DEFCFLAGS} ${GCCEXTRACFLAGS} ${EXTRACFLAGS})
endif ()

if (NOERROR)
    set(DEFCFLAGS ${DEFCFLAGS} -Wno-error)
endif ()

if (NOT DEFINED CROSS_CFLAGS)
    set(CROSS_CFLAGS ${DEFCFLAGS})
endif ()
set(CROSS_CFLAGS ${CROSS_CFLAGS}
    ${ARMCFLAGS}
    -c
    ${INCLUDE}
    # -std=c99  TODO 暂时切换为c11标准，因为新的平台需要c11标准，AT32的官方库一堆c11写法，不这么做的话改起来很麻烦
    -std=c11
    -DON_DEVICE
    ${APP_CFLAGS})
set(CROSS_LDFLAGS ${CROSS_LDFLAGS}
    -Wl,-gc-sections
    -nostartfiles
    -nodefaultlibs
    -Wl,--build-id=none
    -Wl,-n)
set(LIBS gcc)
