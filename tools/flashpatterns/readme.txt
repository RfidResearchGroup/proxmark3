An ELF file builder for testing MCU flash writing issues.

The generated .ELF files can be flashed using the regular
proxmark3 flashing tool. To verify the results, READ MEM
was extended to allow dumping all of flash to a file.

The generated files target:
    - the top 256KB half of flash, or
    - all flash except the bootloader.

And fill those areas with:
    - a fixed hex value, or
    - a pattern based on the memory address, alternately inverted.

Why?

I got a chinese proxmark3 easy with 512KB flash that crashed on a firmware
larger than 256KB. This turned out to be due to data errors in the upper half
of flash memory. For my device, writing FF before writing the actual firmware
file works around the issue.
