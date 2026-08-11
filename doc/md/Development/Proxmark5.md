1. Some hardware abstractions are still incomplete; all 'TODO DXL' items need to be addressed.
2. Certain timeout mechanisms (`timeout--`) are not cross-platform compatible. If `timeout--` is not used with additional clock conditions, please replace it with a timeout mechanism tied to a specific clock source, as the main clock frequency varies across different platforms.
3. The ADC waveform is inverted, which differs from the RDV4.
4. All future modifications to ARM should consider cross-platform compatibility.
5. Please avoid modifying `/armsrc/fpgaloader.c` and files within the `common_arm` directory before this PR is merged into the `master` branch.
6. The client-side logic for identifying the chip capacity of the AT32F435 is not yet complete, which may result in an incorrect estimation of the CODE FLASH capacity.
7. To maintain compatibility with the PM5 power button, the bootrom behavior has been changed: instead of entering flash mode immediately upon power-up when the button is pressed, it will now enter flash mode only after the button is held for 3 seconds.
   > After pressing and holding the button, connect to the USB and wait for 3 seconds. After 3 seconds, LED_B and LED_D will light up. Release the button. At this time, the device has entered FLASH mode and can perform firmware FLASH.
8. The Proxmark5 does not require J-Link or similar tools for unbricking. Simply connect it via USB, power it on, and hold the button for 6 seconds to enter ISP mode. You can then use the AT32 ISP tool to flash the complete firmware.
9. The FPGA code for the Proxmark5 has not yet been pushed to the repository and is currently being organized. A new PR will be created for merging once the cleanup is complete.
10. Chinese comments will remain in the code temporarily. You may translate them into English, but **please ensure the 'TODO DXL' tags are preserved**, otherwise we might lose track of pending tasks.
11. The armsrc can only build by cmake, the client can only build by makefile. it is need to be addressed.
12. The 'hw fpga config' command can be used to configure the FPGA firmware.
13. The 'hw fpga pwrpwm' command can be used to adjust the antenna's drive voltage.
14. The `hw ant_pm5 -m <8bit data>` command can be used to modify the frequency and Q value. Note: High Q is only allowed at 125kHz/134kHz to prevent excessive resonant voltage from damaging the device.
    > 8bit map: 125 134 250 375 500 HFLED LFLED Q (lsb)
15. We will release documentation for the RGB controller and antenna controller as soon as possible.
16. ~The bootrom depends on version_pm3.c, but currently there is no logic in the bootrom's CMakeLists.txt to generate this source file, so the bootrom project cannot be compiled yet.~
17. **Currently, only the client and firmware of this PR can support PM5. Please do not use the client and firmware from the master branch to flash PM5 for the time being.**
18. If you flashed the wrong firmware to PM5 using the xxx link probe, or if the PM5 firmware fails to run for unknown reasons, you can try the following methods to fix it:
    > 1. Download AT32 ISP tool [GO](https://www.arterychip.com/file/download/1764) & Extract
    > 2. Install the driver for ISP USB(The driver is in the `Artery_DFU_DriverInstall` dir)
    > 3. Connect the USB to the USB port on the same side as the button (instead of the CEP port).
    > 4. Press and hold the button for 6-8 seconds. The device will reboot to ISP mode, usb will startup.
    > 5. To open the `Artery ISP Programmer` to select `HEX` file to flash, the bootrom & fullimage is required.
    > 6. When flash done, disconnect usb and reconnect for restart device to exit ISP mode.
    > 7. Open the proxmark client to try to connect to verify your device is re-working.
19. **[IMPORTANT]**: After the PM5 starts up, it needs to immediately pull PB0 high to enable power supply. If PB0 is released during the enable process, it means that the device needs to be shut down. This causes a problem. The CMD_HARDWARE_RESET command calls the `void ResetChip(void)` function, which is implemented using NVIC Reset in the factory firmware. According to the AT32 manual, NVIC RESET takes up to 10-25ms to start. During this period, PB0 has already been released for a long time, so the RESET operation becomes a shutdown. Therefore, the flash process will fail.
    > The latest commit resolves this issue, and users can fix it by forcibly entering FLASH MODE to update BOOTROM+FULLIMAGE according to the instructions in item 7.
20. To make debugging easier, I disabled standalone mod. Now, when the device is powered on, pressing and holding the button for a few seconds will start displaying a running light, and then releasing the button will power off the device. This is suitable for users who have installed BWM.
21. **[IMPORTANT]**: It is worth noting that Proxmark5's SRAM is much larger than RDV4's (8 times larger), so Bigbuf will also be much larger. If some variables are related to the size/index of Bigbuf, be sure to use uint32_t instead of uint16_t, otherwise it will definitely be incompatible with Proxmark5 and there is a risk of overflow.
    > For example, this [BUG](https://github.com/RfidResearchGroup/proxmark3/pull/3449/commits/8f550a8c0f6ccd1b345eedb72c12af11bae17ebe)
      caused all data blocks in the `hf mfu dump` to be empty because an index overflow caused access to the wrong memory address.
      BUG found: [mifarecmd.c#L660](https://github.com/RfidResearchGroup/proxmark3/blob/master/armsrc/mifarecmd.c#L660)
22. The speed of I2C has been modified, and hardware abstraction of I2C is not yet complete. This is also a TODO.
    > Ideally, I2C should also perform HAL in common_arm.
