#ifndef SYS_HW_AT32_H
#define SYS_HW_AT32_H

#include "common.h"
#include "at32f435_437_misc.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_pwc.h"

void NMI_Handler(void);

void HardFault_Handler(void);

void MemManage_Handler(void);

void BusFault_Handler(void);

void UsageFault_Handler(void);

void SVC_Handler(void);

void DebugMon_Handler(void);

void PendSV_Handler(void);

void SysTick_Handler(void);

void system_clock_config_48m(void);

void system_clock_config_288m(void);

STATIC_FORCE_INLINE main_chip_type_t GetChipType(void) {
    return MAIN_CHIP_TYPE_AT32;
}

STATIC_FORCE_INLINE uint32_t GetChipId(void) {
    // DEBUG_IDCODE
    return *((uint32_t *) 0xE0042000);
}

STATIC_FORCE_INLINE uint8_t* GetChipUniqueId(uint8_t *size) {
    // See: Unique device ID register, doc 1.3.2
    //  The unique device ID is a 96-bit value that is programmed by the manufacturer.
    //  It is used to uniquely identify each device and can be used for various purposes such as licensing, security, and tracking.
    if (size) {
        *size = 12; // 96 bits = 12 bytes
    }
    return (uint8_t *) 0x1FFFF7E8;
}

STATIC_FORCE_INLINE void ResetChip(void) {
    // Why not call it?
    //  warning: inlining failed in call to '__NVIC_SystemReset': call is unlikely and code size would grow
    // NVIC_SystemReset();
    nvic_system_reset();
}

STATIC_FORCE_INLINE uint32_t GetChipFlashSize(void) {
    // See: Flash capacity register, doc 1.3.1
    //  Flash storage capacity, measured in KBytes
    //  For example: 0x0080 = 128KByte
    return *((uint32_t *) 0x1FFFF7E0) * 1024; // '<< 10' or '* 1024', Best to reduce the difficulty of understanding.
}

STATIC_FORCE_INLINE bool CheckRSTWithSRAMRetention(void) {
    // If enter Standby Mode, the sram will power off.
    if (CRM->ctrlsts_bit.lprstf && PWC->ctrlsts_bit.swef && PWC->ctrlsts_bit.sef) {
        return false;
    }
    // WDT reset & WWDT reset
    if (CRM->ctrlsts_bit.wwdtrstf || CRM->ctrlsts_bit.wdtrstf) {
        return true;
    }
    // CPU software reset
    if (CRM->ctrlsts_bit.swrstf) {
        return true;
    }
    // NRST reset (pin)
    if (CRM->ctrlsts_bit.nrstf) {
        return true;
    }
    // POR/LVR reset flag? Or otherwise case...
    return false;
}

#endif //SYS_HW_AT32_H
