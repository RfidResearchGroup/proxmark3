.extern BootROM
    
.section .startphase2,"ax"
         .code 32
         .align 0

.global ramstart
ramstart:
    ldr     sp,     = 0x0020FFF8
    bl      BootROM
