@echo off
color 0a
MODE CON COLS=80 LINES=36
title OS FLASH FILE
echo.
echo.
echo.
echo   ======================================================================
echo   ©¦!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! O__O !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!©¦
echo   ©¦==================================================================©¦
echo   ©¦OS-ONLY FLASHER BATCH FILE                                        ©¦
echo   ©¦                                                                  ©¦
echo   ©¦you will need to have this file (FLASH - OS.bat) in \win32 folder ©¦
echo   ©¦you will need to have flasher.exe in \win32 folder                ©¦
echo   ©¦you will need to have osimage.elf in \firmware_win folder         ©¦
echo   ©¦                                                                  ©¦
echo   ©¦                                                                  ©¦
echo   ©¦IF YOU HAVE THOSE REQUISITES HIT ANY BUTTON TO CONTINUE !         ©¦
echo   ©¦------------------------------------------------------------------©¦
echo   ======================================================================
pause.

cls
echo.
echo                 ====================================
echo                 FLASHING osimage.elf, please wait...
echo                 ====================================
echo.
flasher.exe com3 ..\armsrc\obj\osimage.elf

pause.

cls
title DONE
echo.
echo   ___/   \___/   \___/   \___/   \___/   \___/   \___/   \___/   \___
echo  /   \___/   \___/   \___/   \___/   \___/   \___/   \___/   \___/   \
echo  \___/   \___/   \___/   \___/   \___/   \___/   \___/   \___/   \___/
echo  /   \___/                                                   \___/   \
echo  \___/                                                           \___/
echo  /   \                                                           /   \
echo  \___/                                                           \___/
echo  /   \       FLASHING OPERATION SUCCESSFUL ! Enjoy it !          /   \
echo  \___/                                                           \___/
echo  /   \                                                           /   \
echo  \___/                                                           \___/
echo  /   \                                BATCH FILE BY ASPER        /   \
echo  \___/                                                           \___/
echo  /   \                                                           /   \
echo  \___/                                                           \___/
echo  /   \___                                                     ___/   \
echo  \___/   \___     ___     ___     ___     ___     ___     ___/   \___/
echo  /   \___/   \___/   \___/   \___/   \___/   \___/   \___/   \___/   \
echo  \___/   \___/   \___/   \___/   \___/   \___/   \___/   \___/   \___/
echo      \___/   \___/   \___/   \___/   \___/   \___/   \___/   \___/

echo.
pause.
cls
MODE CON COLS=130 LINES=36
cmd.exe
