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
@ RAM reset vector for relaunching the bootloader
@-----------------------------------------------------------------------------

.extern BootROM

.section .startphase2,"ax"

.arm

.global ram_start
ram_start:
    ldr sp,     =_stack_end
    bl  BootROM

    .ltorg
