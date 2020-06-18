#!/bin/bash

version=1.0.1
mkdir -p linenoise-ng
wget https://github.com/arangodb/linenoise-ng/archive/v$version.zip
ZP=linenoise-ng-$version
unzip -o -j v$version $ZP/src/ConvertUTF.cpp $ZP/src/ConvertUTF.h $ZP/LICENSE $ZP/src/linenoise.cpp $ZP/include/linenoise.h $ZP/README.md $ZP/src/wcwidth.cpp -d linenoise-ng
rm v$version.zip
echo "Please do make style"
