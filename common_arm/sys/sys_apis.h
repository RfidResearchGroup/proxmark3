#ifndef SYS_APIS_H_
#define SYS_APIS_H_

#include "common.h"

//-----------------------------------------------------------------------------
// Jump to the Any image after setting the stack pointer.(You jump, i jump)
// For chips that require setting the interrupt vector table,
// this function assumes by default that it is in the header of AnyImage.
//-----------------------------------------------------------------------------
void __attribute__((noreturn)) JumpToAnyImage(uint32_t stack_top, uint32_t entry_point);

//-----------------------------------------------------------------------------
// Config system clock
// This is usually done in the BOOTROM firmware.
//-----------------------------------------------------------------------------
void ConfigSystemClocks(void);

//-----------------------------------------------------------------------------
// Get the main chip type of the current firmware.
// Note: It is determined at compile time, rather than through some register information.
//-----------------------------------------------------------------------------
STATIC_FORCE_INLINE main_chip_type_t GetChipType(void);

//-----------------------------------------------------------------------------
// Get ID of the chip
// Note: It is not the unique ID of the chip. It is the ID related the chip model.
//-----------------------------------------------------------------------------
STATIC_FORCE_INLINE uint32_t GetChipId(void);

//-----------------------------------------------------------------------------
// Get the unique ID of the chip
// size: the size of the unique ID in bytes, set to 0 if no unique id available(and return null ptr).
// Note: Not all chips have a unique ID(Such as AT91SAM7S).
//-----------------------------------------------------------------------------
STATIC_FORCE_INLINE uint8_t *GetChipUniqueId(uint8_t *size);

//-----------------------------------------------------------------------------
// Reset the chip processor
// Note: Resetting the chip will restart code execution from the bootROM.
//-----------------------------------------------------------------------------
STATIC_FORCE_INLINE void ResetChip(void);

//-----------------------------------------------------------------------------
// Get flash size of chip
// ROM size max in bytes
//-----------------------------------------------------------------------------
STATIC_FORCE_INLINE uint32_t GetChipFlashSize(void);

//-----------------------------------------------------------------------------
// Check if the reset is caused by a reset with SRAM retention,
// which means the RAM content is retained and not cleared.
//-----------------------------------------------------------------------------
STATIC_FORCE_INLINE bool CheckRSTWithSRAMRetention(void);

#ifdef PM5
#include "sys_hw_at32.h"
#else
#include "sys_hw_at91.h"
#endif

#endif // SYS_APIS_H_
