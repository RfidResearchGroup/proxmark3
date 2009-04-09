.extern CopyBootToRAM
    
.text
.code 32
.align 0

.global start
start:
    b       Reset
    b       UndefinedInstruction
    b       SoftwareInterrupt
    b       PrefetchAbort
    b       DataAbort
    b       Reserved
    b       Irq
    b       Fiq

Reset:
    ldr     sp,     = 0x0020FFF8	@ initialize stack pointer to top of RAM
    bl      CopyBootToRAM			@ copy bootloader to RAM (in case the
    								@ user re-flashes the bootloader)
    ldr     r3,     = 0x00200000	@ start address of RAM bootloader
    bx      r3						@ jump to it

Fiq:
    b       Fiq
UndefinedInstruction:
    b       UndefinedInstruction
SoftwareInterrupt:
    b       SoftwareInterrupt
PrefetchAbort:
    b       PrefetchAbort
DataAbort:
    b       DataAbort
Reserved:
    b       Reserved
Irq:
    b       Irq
