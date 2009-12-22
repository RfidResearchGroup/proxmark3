@echo off
REM these actually do the real work
..\client\prox.exe os,fpga ..\armsrc\obj\osimage.s19 ..\armsrc\obj\fpgaimage.s19
