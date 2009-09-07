@echo off
call _checkmake
IF %MAKE_FAILED%==1 GOTO end
cd ..\armsrc
@echo **************
@echo *** armsrc ***
@echo **************
make %1
cd ..\cockpit
:end
