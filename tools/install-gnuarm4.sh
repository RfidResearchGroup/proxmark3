#!/bin/bash

# Some things for you to configure

# Where you want to install the tools
DESTDIR=/usr/local/gnuarm-4.3.0

# Where do you want to build the tools. This is where the log files
# will be written (which you can monitor with 'tail' during compilation).
# You can delete this directory after everything is done.
SRCDIR="/home/lafargue/Documents/Hobbies/RFID/Toolchain/linux"

# Where to get each of the toolchain components
BINUTILS=ftp://ftp.gnu.org/gnu/binutils/binutils-2.18.tar.bz2
GCCCORE=ftp://ftp.gnu.org/gnu/gcc/gcc-4.3.0/gcc-core-4.3.0.tar.bz2
GPP=ftp://ftp.gnu.org/gnu/gcc/gcc-4.3.0/gcc-g++-4.3.0.tar.bz2
NEWLIB=ftp://sources.redhat.com/pub/newlib/newlib-1.16.0.tar.gz
#INSIGHT=ftp://sourceware.org/pub/insight/releases/insight-6.8.tar.bz2
INSIGHT=http://mirrors.kernel.org/sources.redhat.com/insight/releases/insight-6.8.tar.bz2
#INSIGHT=http://www.mirrorservice.org/sites/sources.redhat.com/pub/insight/releases/insight-6.8.tar.bz2

# Common configuration options (i.e., things to pass to 'configure')
COMMON_CFG="--enable-interwork --target=arm-elf --program-prefix=arm-elf- --prefix=${DESTDIR} --disable-werror --enable-languages=c,c++ --enable-multilib --disable-shared"

# Extra configuration options for each toolchain component
BINUTILS_CFG=
GCCCORE_CFG="--disable-libssp --disable-threads --with-newlib"  # Not sure about these last 2 options...there to try to make C++ support work
NEWLIB_CFG=
INSIGHT_CFG=

# Compiler flags for compiling Newlib (-O2 is already hard-coded)
NEWLIB_FLAGS="-march=armv4t -mcpu=arm7tdmi -g"

############################################################################
# End of configuration section. You shouldn't have to modify anything below.
############################################################################

if [[ `whoami` != "root" ]]; then
  echo You must be root to run this script
  exit 1
fi

mkdir -p ${SRCDIR}
cd ${SRCDIR}

if [[ -f `basename ${BINUTILS}` ]]; then
  echo Looks like BINUTILS has already been downloaded.
else
  echo Now downloading BINUTILS...
  # -nv: non-verbose but not too quiet (still print errors/warnings)
  # -nc: no-clobber, do not download a file that already exists
  # -t 0: retry indefinitely
  # -a wget.log: append errors/warnings to wget.log file
  wget -nv -nc -t 0 -a wget.log ${BINUTILS}
fi

if [[ -f `basename ${GCCCORE}` ]]; then
  echo Looks like GCC has already been downloaded.
else
  echo Now downloading GCC...
  wget -nv -nc -t 0 -a wget.log ${GCCCORE}
fi

if [[ -f `basename ${GPP}` ]]; then
  echo Looks like G++ has already been downloaded.
else
  echo Now downloading G++...
  wget -nv -nc -t 0 -a wget.log ${GPP}
fi

if [[ -f `basename ${NEWLIB}` ]]; then
  echo Looks like NEWLIB has already been downloaded.
else
  echo Now downloading NEWLIB...
  wget -nv -nc -t 0 -a wget.log ${NEWLIB}
fi

if [[ -f `basename ${INSIGHT}` ]]; then
  echo Looks like INSIGHT has already been downloaded.
else
  echo Now downloading INSIGHT...
  wget -nv -nc -t 0 -a wget.log ${INSIGHT}
fi

if [[ -f binutils.built ]]; then
  echo Looks like BINUTILS was already built.
else
  echo Building BINUTILS...
  tar -xjf `basename ${BINUTILS}`
  echo ___________________  > make.log
  echo Building binutils... >> make.log
  cd `find . -maxdepth 1 -type d -name 'binutils*'`
  mkdir gnuarm
  cd gnuarm
  ../configure ${COMMON_CFG} ${BINUTILS_CFG} >> ../../make.log 2>&1
  make MAKEINFO=`which makeinfo` >> ../../make.log 2>&1
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
  tar -xjf `basename ${GCCCORE}`
  tar -xjf `basename ${GPP}`
  echo ___________________  >> make.log

cat << EOF > gcc.patch
--- gcc-4.2.2.orig/gcc/config/arm/t-arm-elf	2006-11-06 13:13:53.000000000 +0100
+++ gcc-4.2.2.mod/gcc/config/arm/t-arm-elf	2007-10-05 12:13:00.000000000 +0200
@@ -23,8 +23,8 @@
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
  make >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..
  touch gcc.built
fi

if [[ -f newlib.built ]]; then
  echo Looks like NEWLIB was already built.
else
  echo Building NEWLIB...
  tar -xzf `basename ${NEWLIB}`
  echo ___________________  >> make.log
  echo Building newlib... >> make.log
  cd `find . -maxdepth 1 -type d -name 'newlib*'`
  mkdir gnuarm
  cd gnuarm
  ../configure ${COMMON_CFG} ${NEWLIB_CFG}  >> ../../make.log 2>&1

  # This line adds our NEWLIB_CFLAGS to the configure.host file in the
  # newlib subdirectory. This is the only way I could find to tell Newlib to
  # compile itself with the -mmarch=armv4t and -mcpu=arm7tdmi flags.
  sed -i "/^newlib_cflags=/s/=.*\$/=\"${NEWLIB_FLAGS}\"/" ../newlib/configure.host
  make >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..
  touch newlib.built
fi

  echo ___________________  >> make.log
  echo "Now that newlib is built, second pass for GCC..." >> make.log
  cd `find . -maxdepth 1 -type d -name 'gcc*'`
  cd gnuarm
  make >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..


if [[ -f insight.built ]]; then
  echo Looks like INSIGHT was already built.
else
  echo Building INSIGHT...
  tar -xjf `basename ${INSIGHT}`
  echo ___________________  >> make.log
  echo Building insight... >> make.log
  cd `find . -maxdepth 1 -type d -name 'insight*'`
  mkdir gnuarm
  cd gnuarm
  ../configure ${COMMON_CFG} ${INSIGHT_CFG} >> ../../make.log 2>&1
  make >> ../../make.log 2>&1
  make install >> ../../make.log 2>&1
  cd ../..
  touch insight.built
fi

echo ___________________  >> make.log
echo Build complete. >> make.log

cd ${DESTDIR}
chmod -R a+rX .

exit 0
