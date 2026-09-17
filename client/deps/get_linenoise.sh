#!/bin/bash

# Can be used if Readline is unavailable or explicitely disabled
# Note that ConvertUTF.cpp is under redis-only license therefore
# if you are maintainer, think twice before including it

version=1.0.1
mkdir -p linenoise
ZP=linenoise-ng-$version
if [ ! -f "${ZP}.zip" ]; then
    wget -O "${ZP}.zip" https://github.com/arangodb/linenoise-ng/archive/v$version.zip
fi
unzip -o -j "${ZP}.zip" $ZP/src/ConvertUTF.cpp $ZP/src/ConvertUTF.h $ZP/LICENSE $ZP/src/linenoise.cpp $ZP/include/linenoise.h $ZP/README.md $ZP/src/wcwidth.cpp -d linenoise
#echo "Please do make style"

echo "Generating linenoise.cmake..."
cat > linenoise.cmake << EOF
add_library(pm3rrg_rdv4_linenoise STATIC
        linenoise/ConvertUTF.cpp
        linenoise/linenoise.cpp
        linenoise/wcwidth.cpp
)

target_compile_definitions(pm3rrg_rdv4_linenoise PRIVATE NDEBUG)
target_include_directories(pm3rrg_rdv4_linenoise INTERFACE linenoise)
target_compile_options(pm3rrg_rdv4_linenoise PRIVATE -Wall -Werror -O3)
set_property(TARGET pm3rrg_rdv4_linenoise PROPERTY POSITION_INDEPENDENT_CODE ON)
EOF

cd linenoise
echo "Generating linenoise/Makefile..."
cat > Makefile << EOF
MYSRCPATHS =
MYINCLUDES =
MYCXXFLAGS = -DNDEBUG -std=c++11 -fomit-frame-pointer
MYDEFS =
MYCXXSRCS = ConvertUTF.cpp linenoise.cpp wcwidth.cpp

LIB_A = liblinenoise.a

include ../../../Makefile.host
EOF

# Patch to get proper autocompletion of subcommands
patch << EOF
diff -Naur linenoise.cpp linenoise.cpp
+++ linenoise.cpp 2017-03-06 17:01:33.000000000 +0100
--- linenoise.cpp 2022-01-29 10:37:19.656202922 +0100
@@ -1956,7 +1956,7 @@
   // character and
   // extract a copy to parse.  we also handle the case where tab is hit while
   // not at end-of-line.
-  int startIndex = pos;
+  int startIndex = 0;
   while (--startIndex >= 0) {
     if (strchr(breakChars, buf32[startIndex])) {
       break;
EOF
