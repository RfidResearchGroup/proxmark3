@echo off

rmdir/s/q xst

del fpga_lf.ngc
xst -ifn xst_lf.scr
if errorlevel 0 goto ok1
goto done
:ok1

del fpga_lf.ngd
ngdbuild -aul -p xc2s30-6vq100 -nt timestamp -uc fpga.ucf fpga_lf.ngc fpga_lf.ngd
if errorlevel 0 goto ok2
goto done
:ok2

del fpga_lf.ncd
map -p xc2s30-6vq100 fpga_lf.ngd
if errorlevel 0 goto ok3
goto done
:ok3

del fpga_lf-placed.ncd
par fpga_lf.ncd fpga_lf-placed.ncd
if errorlevel 0 goto ok4
goto done
:ok4

del fpga_lf.bit fpga_lf.drc fpga_lf.rbt
bitgen -b fpga_lf-placed.ncd fpga_lf.bit
if errorlevel 0 goto ok5
goto done
:ok5

del fpga_hf.ngc
xst -ifn xst_hf.scr
if errorlevel 0 goto ok6
goto done
:ok6

del fpga_hf.ngd
ngdbuild -aul -p xc2s30-6vq100 -nt timestamp -uc fpga.ucf fpga_hf.ngc fpga_hf.ngd
if errorlevel 0 goto ok7
goto done
:ok7

del fpga_hf.ncd
map -p xc2s30-6vq100 fpga_hf.ngd
if errorlevel 0 goto ok8
goto done
:ok8

del fpga_hf-placed.ncd
par fpga_hf.ncd fpga_hf-placed.ncd
if errorlevel 0 goto ok9
goto done
:ok9

del fpga_hf.bit fpga_hf.drc fpga_hf.rbt
bitgen -b fpga_hf-placed.ncd fpga_hf.bit
if errorlevel 0 goto ok10
goto done
:ok10

echo okay
perl ..\tools\rbt2c.pl fpga_lf.rbt > ..\armsrc\fpgaimg.c

:done
