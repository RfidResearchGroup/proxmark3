These notes are mostly intended for developers.
 - Read first the [Proxmark5 Instructions](../PM5_Start_Here/Getting_Started_With_PM5.md). IMPORTANT !!!
 - Read the technical manual to develop new features for PM5: [Proxmark5 Technical Manual](./PM5_VERE_Hardware_RM.md)

---

- Some hardware abstractions are still incomplete; all 'TODO DXL' items need to be addressed.
- Certain timeout mechanisms (`timeout--`) are not cross-platform compatible. If `timeout--` is not used with additional clock conditions, please replace it with a timeout mechanism tied to a specific clock source, as the main clock frequency varies across different platforms.
- The ADC waveform is inverted, which differs from the RDV4.
- All future modifications to ARM must ensure cross-platform compatibility.
- The client-side logic for identifying the chip capacity of the AT32F435 is not yet complete, which may result in an incorrect estimation of the CODE FLASH capacity.
- The FPGA code for the Proxmark5 has not yet been pushed to the repository and is currently being organized. A new PR will be created for merging once the cleanup is complete.
- Chinese comments will remain in the code temporarily. You may translate them into English, but **please ensure the 'TODO DXL' tags are preserved**, otherwise we might lose track of pending tasks.
- We will release documentation for the RGB controller and antenna controller as soon as possible.
- **[IMPORTANT]**: After the PM5 starts up, it needs to immediately pull PB0 high to enable power supply. If PB0 is released during the enable process, it means that the device needs to be shut down. This causes a problem. The CMD_HARDWARE_RESET command calls the `void ResetChip(void)` function, which is implemented using NVIC Reset in the factory firmware. According to the AT32 manual, NVIC RESET takes up to 10-25ms to start. During this period, PB0 has already been released for a long time, so the RESET operation becomes a shutdown. Therefore, the flash process will fail. The current code takes care of it.
- **[IMPORTANT]**: It is worth noting that Proxmark5's SRAM is much larger than RDV4's (8 times larger), so Bigbuf will also be much larger. If some variables are related to the size/index of Bigbuf, be sure to use uint32_t instead of uint16_t, otherwise it will definitely be incompatible with Proxmark5 and there is a risk of overflow.
    > For example, this [BUG](https://github.com/RfidResearchGroup/proxmark3/pull/3449/commits/8f550a8c0f6ccd1b345eedb72c12af11bae17ebe)
      caused all data blocks in the `hf mfu dump` to be empty because an index overflow caused access to the wrong memory address.
      BUG found: [mifarecmd.c#L660](https://github.com/RfidResearchGroup/proxmark3/blob/master/armsrc/mifarecmd.c#L660)
- The speed of I2C has been modified, and hardware abstraction of I2C is not yet complete. This is also a TODO.
    > Ideally, I2C should also perform HAL in common_arm.
- The communication driver between BWM and PM5_ARM is currently on the TODO list, therefore, operating PM5 via BWM is not supported at this time. (Communication between ARM and BWM is protocol-based, unlike RDV4 which is transparent.)
    > Having a protocol allows for better flow control, preventing packet loss caused by UART being too 'fast' and BLE being too 'slow'.
- The HAL work related to HITAG has been completed. For details, see: [HitagS & HitagU](https://github.com/RfidResearchGroup/proxmark3/pull/3449#issuecomment-5303520489)
- The code of the BWM Battery Wireless Module is [hosted here](https://github.com/RfidResearchGroup/Proxmark5_BWM_esp32)

The ARM code is primarily compiled with the Makefiles, but it also supports Cmake.
```
mkdir build && cd build
cmake -DPLATFORM:STRING=PM5 ..
cmake --build .
cd ..
client/proxmark3 --port /dev/ttyACM0 --flash --unlock-bootloader --image build/obj/bootrom.elf --image build/obj/fullimage.elf
```
