MYSRCPATHS = ../../common/zlib
MYSRCS     = deflate.c adler32.c trees.c zutil.c inflate.c inffast.c inftrees.c
MYINCLUDES = -I../../common/zlib
MYCFLAGS   = -std=c99 -D_ISOC99_SOURCE
MYDEFS     = -DZ_SOLO -DNO_GZIP -DZLIB_PM3_TUNED
#-DDEBUG -Dverbose=1

LIB_A = libz.a

include ../../Makefile.host
