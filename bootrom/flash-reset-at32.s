.section .startup,"ax"
.syntax unified
.cpu cortex-m4
.fpu softvfp
.thumb

/* ------------------------------------------------------------------- */

.global  flashstart
.type flashstart, %object
flashstart:

  .word _stack_end
  .word reset
  .word default_handler
  .word default_handler
  .word default_handler
  .word default_handler
  .word default_handler
  .word 0
  .word 0
  .word 0
  .word 0
  .word default_handler
  .word default_handler
  .word 0
  .word default_handler
  .word default_handler

/* ------------------------------------------------------------------- */

.thumb_func
.type reset, %function
reset:
  /* Copy the bootrom to sram */
  ldr r0, =__bootphase2_src_start__
  ldr r1, =__bootphase2_start__
  ldr r2, =__bootphase2_end__
1:
  ldr r3, [r0], #4
  str r3, [r1], #4
  cmp r1, r2
  blo 1b

  /*
   * DXL Note:
   * It is very important to ensure that the memory expansion configuration is correct before accessing the memory!
   * Do not use _stack_end, because this memory area may be temporarily inaccessible.
   * If you adjust from small sram to large sram, using _stack_end and function call will result in hardware fault.
   */
  ldr sp, =__stack_boot_end__
  bl Extend_SRAM

  /* Load the stack pointer(Such as _stack_end?) from the first word of the bootphase2. */
  ldr sp, =_stack_end /* Reset the stack pointer once to call JumpToAnyImage. */
  ldr r0, =__bootphase2_start__
  ldr r0, [r0]
  ldr r1, =__bootphase2_start__  /* Vector table base / entry point. */
  ldr r2, =JumpToAnyImage
  blx r2

/* ------------------------------------------------------------------- */

.thumb_func
.type default_handler, %function
default_handler:
1:
  b   1b

  .ltorg
