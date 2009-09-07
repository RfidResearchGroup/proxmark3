@echo off
call _checkmake
IF %MAKE_FAILED%==1 GOTO end
cd ..\bootrom
@echo ***************
@echo *** bootrom ***
@echo ***************
make %1
cd ..\cockpit
:end
