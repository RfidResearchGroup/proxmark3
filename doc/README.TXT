This is a bare minimum compile environment for the proxmark3 sources. 

CONTENTS

This bundle contains the ARM cross compiler in devkitARM and a _tiny_ subset
of the Visual C++ 2008 Express Edition in devkitWIN which is the bare minimum
required for compilation of this current source.

If you plan on further source code development you are strongly encouraged
to download the full Visual C++ 2008 available for free download from
http://www.microsoft.com/express/download/

CAVEATS

There is no provision in this environment for compiling the FPGA source. To
do that you need to download the free (registration required) ISE WebPack
from Xilinx at http://www.xilinx.com/ise/logic_design_prod/webpack.htm
Be warned, the pack is huge, 2Gb download and >4Gb installed.

USAGE

First of all run the .msi file in devkitWIN\vcredist_x86 to install the VC++
redistributables, without these, nmake, cl and link won't run.

Get a command prompts in the cockpit directory and pretty much run the batch
files in the order they appear:

0setpath.bat  - sets the environment vars for the compile environment
1makearm.bat  - compiles the files in armsrc, output files in armsrc\obj
2makeboot.bat - compiles the files in bootrom, output files in bootrom\obj
3makewin.bat  - compiles the files in winsrc, output files in winsrc\obj
4flashos.bat  - attempts to upload the OS image to the proxmark3 board

ACKNOWLEDGMENTS

Thanks to J Westhues for the original proxmark, Roel and the proxmark.org
community. This pack may contain F/OSS or free but copyrighted software
from Xilinx, Microsoft and others. All trademarks are the property of
their respective owners. All rights reserved.
