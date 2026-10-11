@-----------------------------------------------------------------------------
@ Copyright (C) Jonathan Westhues, Mar 2006
@ Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
@
@ This program is free software: you can redistribute it and/or modify
@ it under the terms of the GNU General Public License as published by
@ the Free Software Foundation, either version 3 of the License, or
@ (at your option) any later version.
@
@ This program is distributed in the hope that it will be useful,
@ but WITHOUT ANY WARRANTY; without even the implied warranty of
@ MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
@ GNU General Public License for more details.
@
@ See LICENSE.txt for the text of the license.
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
