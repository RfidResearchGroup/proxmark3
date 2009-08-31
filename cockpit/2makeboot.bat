@echo off
call _checkmake
IF %MAKE_FAILED%==1 GOTO end
cd ..\bootrom
rem make clean
make
cd ..\cockpit
:end
