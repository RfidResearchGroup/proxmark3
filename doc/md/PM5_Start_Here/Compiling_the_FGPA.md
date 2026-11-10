# Compiling the FGPA code

## Contents

- [Build the FPGA image from source](#Build-the-FPGA-Image-From-Source)
---


## Build the FPGA Image From Source
The PM5 bitstream is built with the open source toolchain (yosys, nextpnr-himbaechel, apicula) from [oss-cad-suite](https://github.com/YosysHQ/oss-cad-suite-build/releases). Use the release pinned in `.github/workflows/fpga-pm5.yml`: older yosys builds give images with a weaker antenna drive. Unpack it next to the repository (`../oss-cad-suite`) or point `OSS_CAD_SUITE` at it.

Build the fpga/fpga_pm5.bin binary
```
make -C fpga pm5
```

Build the fpga/fpga_pm5.bin binary and copy it to client/resources This is where `script run upgrade_fpga` looks to for an image to flash.
```
make -C fpga fpga_pm5_release
```

The build is reproducible: the same sources and toolchain give the same bytes as the CI artifact. To try an image without touching the FPGA flash, load it into SRAM with `hw fpga config -s -f fpga/fpga_pm5.bin`. A power cycle returns to the image in flash.

