set_property(SOURCE PROPERTY C_STANDARD 99)
add_definitions(-D_ISOC99_SOURCE -DZ_SOLO -DNO_GZIP -DZLIB_PM3_TUNED)
include_directories(common/zlib)

add_library(z
        common/zlib/deflate.c
        common/zlib/adler32.c
        common/zlib/trees.c
        common/zlib/zutil.c
        common/zlib/inflate.c
        common/zlib/inffast.c
        common/zlib/inftrees.c
)


