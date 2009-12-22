#!/bin/bash

# Some things for you to configure
BINUTILS_VER="2.19.1"
GCC_VER="4.3.3"
GDB_VER="6.8"
NEWLIB_VER="1.17.0"
GMP_VER="4.2.4"
MPFR_VER="2.4.2"
INSIGHT_VER="6.8"

# Where you want to install the tools
if [ "${1}" = "" ]; then
        echo "Syntax: ${0} </installation/target/directory> [download & build directory (default ${PWD})]"
        exit 1
else
	DESTDIR="${1}"
fi

# Where do you want to build the tools. This is where the log files
# will be written (which you can monitor with 'tail' during compilation).
# You can delete this directory after everything is done.
if [ ! "${2}" = "" ]; then
	SRCDIR="${2}"
else
	SRCDIR="${PWD}"
fi
BUILDDIR=${SRCDIR}/build-gnuarm4

# Where to get each of the toolchain components
BINUTILS=http://ftp.gnu.org/gnu/binutils/binutils-${BINUTILS_VER}.tar.bz2
GCCCORE=http://ftp.gnu.org/gnu/gcc/gcc-${GCC_VER}/gcc-core-${GCC_VER}.tar.bz2
GPP=http://ftp.gnu.org/gnu/gcc/gcc-${GCC_VER}/gcc-g++-${GCC_VER}.tar.bz2
NEWLIB=ftp://sources.redhat.com/pub/newlib/newlib-${NEWLIB_VER}.tar.gz
#INSIGHT=ftp://sourceware.org/pub/insight/releases/insight-${INSIGHT_VER}.tar.bz2
INSIGHT=http://mirrors.kernel.org/sources.redhat.com/insight/releases/insight-${INSIGHT_VER}.tar.bz2
#INSIGHT=http://www.mirrorservice.org/sites/sources.redhat.com/pub/insight/releases/insight-${INSIGHT_VER}.tar.bz2
GDB=ftp://sourceware.org/pub/gdb/releases/gdb-${GDB_VER}.tar.bz2
GMP=http://ftp.sunet.se/pub/gnu/gmp/gmp-${GMP_VER}.tar.bz2
MPFR=http://mpfr.loria.fr/mpfr-current/mpfr-${MPFR_VER}.tar.bz2

# Common configuration options (i.e., things to pass to 'configure')
COMMON_CFG="--enable-interwork --target=arm-elf --program-prefix=arm-elf- --prefix=${DESTDIR} --disable-werror --enable-languages=c,c++ --enable-multilib --disable-shared"

# Extra configuration options for each toolchain component
BINUTILS_CFG=
GCCCORE_CFG="--disable-nls --disable-threads --with-gcc --with-gnu-ld --with-gnu-as --with-dwarf2 --with-newlib --with-headers=${BUILDDIR}/newlib-${NEWLIB_VER}/newlib/libc/include --disable-libssp --disable-libstdcxx-pch --disable-libmudflap --disable-libgomp -v"
NEWLIB_CFG=
INSIGHT_CFG=
GDB_CFG=

# Make flags
MAKEFLAGS="-j 4"

# wget options
# -nv: non-verbose but not too quiet (still print errors/warnings)
# -nc: no-clobber, do not download a file that already exists
# -t 0: retry indefinitely
# -a wget.log: append errors/warnings to wget.log file
# -c continue
#WGET_OPTS="-nv -nc -t 0 -a wget.log"
WGET_OPTS="-c -t 0"

# Compiler flags for compiling Newlib (-O2 is already hard-coded)
NEWLIB_FLAGS="-march=armv4t -mcpu=arm7tdmi -g"

############################################################################
# End of configuration section. You shouldn't have to modify anything below.
############################################################################

if [[ `whoami` != "root" ]]; then
  echo "*** Warning! Not running as root!"
  echo "Installation may fail if you do not have appropriate permissions!"
fi

mkdir -p ${BUILDDIR}
cd ${SRCDIR}

if [[ -f all.downloaded ]]; then
  echo Looks like all downloads are complete, skipping downloads
else
  echo Now downloading BINUTILS...
  wget ${WGET_OPTS} ${BINUTILS}

  echo Now downloading GCC...
  wget ${WGET_OPTS} ${GCCCORE}

  echo Now downloading G++...
  wget ${WGET_OPTS} ${GPP}

  echo Now downloading NEWLIB...
  wget ${WGET_OPTS} ${NEWLIB}

  echo Now downloading INSIGHT...
  wget ${WGET_OPTS} ${INSIGHT}

  echo Now downloading GDB...
  wget ${WGET_OPTS} ${GDB}

  echo Now downloading GMP...
  wget ${WGET_OPTS} ${GMP}

  echo Now downloading MPFR...
  wget ${WGET_OPTS} ${MPFR}

  touch all.downloaded
fi

cd ${BUILDDIR}
if [[ -f binutils.built ]]; then
  echo Looks like BINUTILS was already built.
else
  echo Building BINUTILS...
  tar -xjf ../`basename ${BINUTILS}`
  echo ___________________  > make.log
  echo Building binutils... >> make.log
  cd `find . -maxdepth 1 -type d -name 'binutils*'`
  mkdir gnuarm
  cd gnuarm
  ../configure ${COMMON_CFG} ${BINUTILS_CFG} >> ../../make.log 2>&1
  make ${MAKEFLAGS} MAKEINFO=`which makeinfo` >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..
  touch binutils.built
fi

  echo ___________________  >> make.log
  echo Adding ${DESTDIR}/bin to PATH >> make.log
export PATH; PATH=${DESTDIR}/bin:$PATH
  echo ___________________  >> make.log

if [[ -f gcc.built ]]; then
  echo Looks like GCC was already built.
else
  echo Building GCC...
  tar -xjf ../`basename ${GCCCORE}`
  tar -xjf ../`basename ${GPP}`
  tar -xjf ../`basename ${GMP}`
  ln -s "${BUILDDIR}/gmp-${GMP_VER}" "${BUILDDIR}/gcc-${GCC_VER}/gmp"
  tar -xjf ../`basename ${MPFR}`
  ln -s "${BUILDDIR}/mpfr-${MPFR_VER}" "${BUILDDIR}/gcc-${GCC_VER}/mpfr"
  tar -xzf ../`basename ${NEWLIB}`

  echo ___________________  >> make.log

cat << EOF > gcc.patch
--- gcc-4.3.3.orig/gcc/config/arm/t-arm-elf
+++ gcc-4.3.3.mod/gcc/config/arm/t-arm-elf
@@ -33,8 +33,8 @@
 # MULTILIB_DIRNAMES   += fpu soft
 # MULTILIB_EXCEPTIONS += *mthumb/*mhard-float*
 # 
-# MULTILIB_OPTIONS    += mno-thumb-interwork/mthumb-interwork
-# MULTILIB_DIRNAMES   += normal interwork
+MULTILIB_OPTIONS    += mno-thumb-interwork/mthumb-interwork
+MULTILIB_DIRNAMES   += normal interwork
 # 
 # MULTILIB_OPTIONS    += fno-leading-underscore/fleading-underscore
 # MULTILIB_DIRNAMES   += elf under
EOF

  echo Patching GCC >> make.log
  cd `find . -maxdepth 1 -type d -name 'gcc*'`
  patch -p1 < ../gcc.patch
  echo Building gcc... >> make.log
  mkdir gnuarm
  cd gnuarm
  ../configure ${COMMON_CFG} ${GCCCORE_CFG} >> ../../make.log 2>&1
  make ${MAKEFLAGS} all-gcc >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..
  touch gcc.built
fi

if [[ -f newlib.built ]]; then
  echo Looks like NEWLIB was already built.
else
  echo Building NEWLIB...
  echo ___________________  >> make.log
  echo Building newlib... >> make.log
  cd `find . -maxdepth 1 -type d -name 'newlib*'`
  mkdir gnuarm
  cd gnuarm
  ../configure ${COMMON_CFG} ${NEWLIB_CFG}  >> ../../make.log 2>&1

  # This line adds our NEWLIB_CFLAGS to the configure.host file in the
  # newlib subdirectory. This is the only way I could find to tell Newlib to
  # compile itself with the -mmarch=armv4t and -mcpu=arm7tdmi flags.
#  sed -i "/^newlib_cflags=/s/=.*\$/=\"${NEWLIB_FLAGS}\"/" ../newlib/configure.host
  make ${MAKEFLAGS} >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..
  touch newlib.built
fi

  echo ___________________  >> make.log
  echo "Now that newlib is built, second pass for GCC..." >> make.log
  cd `find . -maxdepth 1 -type d -name 'gcc*'`
  cd gnuarm
  make ${MAKEFLAGS} >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..


if [[ -f insight.built ]]; then
  echo Looks like INSIGHT was already built.
else
  echo Building INSIGHT...
  tar -xjf ../`basename ${INSIGHT}`
  echo ___________________  >> make.log
  echo Building insight... >> make.log
  cd `find . -maxdepth 1 -type d -name 'insight*'`
  mkdir gnuarm
  cd gnuarm
  ../configure ${COMMON_CFG} ${INSIGHT_CFG} >> ../../make.log 2>&1
  make ${MAKEFLAGS} >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..
  touch insight.built
fi

if [[ -f gdb.built ]]; then
  echo Looks like GDB was already built.
else
  echo Building GDB...
  tar -xjf ../`basename ${GDB}`
  echo ___________________  >> make.log
  echo Building insight... >> make.log
  cd `find . -maxdepth 1 -type d -name 'gdb*'`
  mkdir gnuarm
  cd gnuarm
  ../configure ${COMMON_CFG} ${GDB_CFG} >> ../../make.log 2>&1
  make ${MAKEFLAGS} >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..
  touch gdb.built
fi

echo ___________________  >> make.log
echo Build complete. >> make.log

cd ${DESTDIR}
chmod -R a+rX .

echo Downloaded archives are in ${SRCDIR}
echo build driectory: ${BUILDDIR}
echo set environment variable ARMLIB to ${DESTDIR}/lib/gcc/arm-elf/4.3.3/interwork for Makefile.linux
exit 0
