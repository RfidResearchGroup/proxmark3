@-----------------------------------------------------------------------------
@ This code is licensed to you under the terms of the GNU GPL, version 2 or,
@ at your option, any later version. See the LICENSE.txt file for the text of
@ the license.
@-----------------------------------------------------------------------------
@ RAM reset vector for relaunching the bootloader
@-----------------------------------------------------------------------------

.extern BootROM

.section .startphase2,"ax"
         .code 32
         .align 0

.global ramstart
ramstart:
    ldr     sp,     .stack_end
    bl      BootROM

	.stack_end:
	.word _stack_end
