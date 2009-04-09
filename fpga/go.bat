@echo off

rmdir/s/q xst

del fpga.ngc
xst -ifn xst.scr
if errorlevel 0 goto ok1
goto done
:ok1

del fpga.ngd
ngdbuild -aul -p xc2s30-6vq100 -nt timestamp -uc fpga.ucf fpga.ngc fpga.ngd
if errorlevel 0 goto ok2
goto done
:ok2

del fpga.ncd
map -p xc2s30-6vq100 fpga.ngd
if errorlevel 0 goto ok3
goto done
:ok3

del fpga-placed.ncd
par fpga.ncd fpga-placed.ncd
if errorlevel 0 goto ok4
goto done
:ok4

del fpga.bit fpga.drc fpga.rbt
bitgen -b fpga-placed.ncd fpga.bit
if errorlevel 0 goto ok5
goto done
:ok5

echo okay
perl ..\tools\rbt2c.pl fpga.rbt > ..\armsrc\fpgaimg.c

:done
