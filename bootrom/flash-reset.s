@-----------------------------------------------------------------------------
@ This code is licensed to you under the terms of the GNU GPL, version 2 or,
@ at your option, any later version. See the LICENSE.txt file for the text of
@ the license.
@-----------------------------------------------------------------------------
@ Reset vector for running from FLASH
@-----------------------------------------------------------------------------

.extern CopyBootToRAM

.section .startup,"ax"
         .code 32
         .align 0

.global flashstart
flashstart:
    b       Reset
    b       UndefinedInstruction
    b       SoftwareInterrupt
    b       PrefetchAbort
    b       DataAbort
    b       Reserved
    b       Irq
    b       Fiq

Reset:
    ldr     sp,     .stack_end	@ initialize stack pointer to top of RAM
    bl      CopyBootToRAM			@ copy bootloader to RAM (in case the
    								@ user re-flashes the bootloader)
    ldr     r3,     .bootphase2_start	@ start address of RAM bootloader
    bx      r3						@ jump to it

	.stack_end:
	.word _stack_end
	.bootphase2_start:
	.word __bootphase2_start__

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
