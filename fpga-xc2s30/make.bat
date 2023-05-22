@ECHO OFF

REM PATH change only applies inside this batch file
SETLOCAL

REM Customize settings here
SET PATH=C:\Xilinx\10.1\ISE_DS\ISE\bin\nt64;C:\Xilinx\10.1\ISE_DS\ISE\lib\nt64;%PATH%
SET FPGA_TYPE=xc2s30-5-vq100
SET FILES=fpga_lf fpga_hf fpga_hf_15 fpga_felica

REM Call compilation subroutine for each bitstream file
FOR %%X IN (%FILES%) DO CALL :MAKE_BITSTREAM %%X
EXIT /B

REM ###############################################
REM This subroutine is called to do the compilation
:MAKE_BITSTREAM

REM Cleanup any previous mess (print no errors)
RMDIR/S/Q _make_%1 2>NUL
MKDIR _make_%1
PUSHD _make_%1

REM Generate XST script file
ECHO run -ifn ..\%1.v -ifmt Verilog -ofn %1.ngc -ofmt NGC -p %FPGA_TYPE% -top %1 -opt_mode area -opt_level 2 -resource_sharing yes -fsm_style bram -fsm_encoding compact>%1.scr

REM Call XST with script
xst -ifn %1.scr
IF NOT ERRORLEVEL 0 POPD & EXIT /B

REM Run Ngdbuild
ngdbuild -aul -p %FPGA_TYPE% -nt timestamp -uc ..\fpga.ucf %1.ngc %1.ngd
IF NOT ERRORLEVEL 0 POPD & EXIT /B

REM Run Map
map -p %FPGA_TYPE% %1.ngd
IF NOT ERRORLEVEL 0 POPD & EXIT /B

REM Run Place and Route
par %1.ncd %1-placed.ncd
IF NOT ERRORLEVEL 0 POPD & EXIT /B

REM Generate FPGA bitstream
bitgen -w %1-placed.ncd %1.bit
MOVE /Y %1.bit ..
POPD
EXIT /B
