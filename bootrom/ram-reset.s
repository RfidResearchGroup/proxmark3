.extern BootROM
    
.text
.code 32
.align 0

.global start
start:
    ldr     sp,     = 0x0020FFF8
    bl      BootROM
