@echo off
make -C .. -s _test
IF ERRORLEVEL 1 GOTO fail
SET MAKE_FAILED=0
GOTO end
:fail
echo ************************************************
echo * A compatible (GNU) make was not detected     *
echo * Please get an updated version of the Windows *
echo * compile environment, or install GNU make     *
echo * manually                                     *
echo ************************************************
SET MAKE_FAILED=1
:end
