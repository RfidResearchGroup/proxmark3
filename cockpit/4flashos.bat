@echo off
echo ********************************************************************
echo * REMEMBER: hold button down for the duration of the FLASH process *
echo ********************************************************************

REM next line is a dummy. It causes PM3 to reboot and enter the FLASH process
..\winsrc\prox.exe load ..\armsrc\obj\osimage.s19

REM these actually do the real work
..\winsrc\prox.exe load ..\armsrc\obj\osimage.s19
..\winsrc\prox.exe fpga ..\armsrc\obj\fpgaimage.s19
