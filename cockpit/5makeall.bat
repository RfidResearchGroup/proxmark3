@echo off
call _checkmake
IF %MAKE_FAILED%==1 GOTO end
call 1makearm.bat %1
call 2makeboot.bat %1
call 3makewin.bat %1
:end