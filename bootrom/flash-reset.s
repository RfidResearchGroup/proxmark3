@-----------------------------------------------------------------------------
@ This code is licensed to you under the terms of the GNU GPL, version 2 or,
@ at your option, any later version. See the LICENSE.txt file for the text of
@ the license.
@-----------------------------------------------------------------------------
@ Reset vector for running from FLASH
@-----------------------------------------------------------------------------

.section .startup,"ax"

.arm

.global flashstart
flashstart:
    b   reset
    b   undefined_instruction
    b   software_interrupt
    b   prefetch_abort
    b   data_abort
    b   . @reserved
    ldr pc, [pc,#-0xF20]    @ IRQ - read the AIC
    b   fiq

reset:
    ldr sp, =_stack_end     @ initialize stack pointer to top of RAM

    @ copy bootloader to RAM (in case the user re-flashes the bootloader)
    ldr r0, =__bootphase2_src_start__
    ldr r1, =__bootphase2_start__
    ldr r2, =__bootphase2_end__
1:
    ldr r3, [r0], #4
    str r3, [r1], #4
    cmp r1, r2
    blo 1b

    ldr r3, =ram_start      @ start address of RAM bootloader
    bx  r3                  @ jump to it

    .ltorg

undefined_instruction:
    b   .
software_interrupt:
    b   .
prefetch_abort:
    b   .
data_abort:
    b   .
fiq:
    b   .
