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
