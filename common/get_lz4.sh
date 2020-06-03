version=1.9.2
mkdir -p lz4
wget https://github.com/lz4/lz4/archive/v$version.zip
unzip -o -j v$version "lz4-$version/LICENSE" "lz4-$version/lib/lz4.h" "lz4-$version/lib/lz4.c" "lz4-$version/lib/lz4hc.h" "lz4-$version/lib/lz4hc.c" -d lz4
rm v$version.zip