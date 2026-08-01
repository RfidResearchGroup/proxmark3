#ifndef SYS_HW_AT32_H
#define SYS_HW_AT32_H

#include "common.h"
#include "at32f435_437_misc.h"
#include "at32f435_437_crm.h"
#include "at32f435_437_pwc.h"

/**
 * What's method for system reset we are using?
 * 0(default): system_simple_reset() + jump to bootrom
 * 1: nvic_system_reset() [NOT IMPLEMENT]
 */
extern uint8_t g_system_reset_method;

// --- Handlers

void NMI_Handler(void);

void HardFault_Handler(void);

void MemManage_Handler(void);

void BusFault_Handler(void);

void UsageFault_Handler(void);

void SVC_Handler(void);

void DebugMon_Handler(void);

void PendSV_Handler(void);

void SysTick_Handler(void);

// ---

void system_clock_config_48m(void);

void system_clock_config_288m(void);

void system_simple_reset(void);

bool system_bpr_chk_clear(void);

STATIC_FORCE_INLINE main_chip_type_t GetChipType(void) {
    return MAIN_CHIP_TYPE_AT32;
}

STATIC_FORCE_INLINE uint32_t GetChipId(void) {
    // DEBUG_IDCODE
    return *((uint32_t *) 0xE0042000);
}

STATIC_FORCE_INLINE uint8_t *GetChipUniqueId(uint8_t *size) {
    // See: Unique device ID register, doc 1.3.2
    //  The unique device ID is a 96-bit value that is programmed by the manufacturer.
    //  It is used to uniquely identify each device and can be used for various purposes such as licensing, security, and tracking.
    if (size) {
        *size = 12; // 96 bits = 12 bytes
    }
    return (uint8_t *) 0x1FFFF7E8;
}

STATIC_FORCE_INLINE void ResetChip(void) {
    // Which reset method should be used?
    if (g_system_reset_method == 0) {
        // Call system_simple_reset() to simply reset the state of most peripherals, and jump to boot.
        system_simple_reset();
    } else {
        // On current hardware, resetting the NVIC will cause the ARM_POWER_ON pin to return to input mode. However,
        // it takes 10ms to 25ms from RESET to startup, during which time the device has already been powered off.
        // If future hardware support keeping the GPIO level of ARM_POWER_ON during RESET, then NVIC reset can be enabled.
        nvic_system_reset();
    }
}

STATIC_FORCE_INLINE uint32_t GetChipFlashSize(void) {
    // See: Flash capacity register, doc 1.3.1
    //  Flash storage capacity, measured in KBytes
    //  For example: 0x0080 = 128KByte
    return *((uint32_t *) 0x1FFFF7E0) * 1024; // '<< 10' or '* 1024', Best to reduce the difficulty of understanding.
}

STATIC_FORCE_INLINE bool CheckRSTWithSRAMRetention(void) {
    if (system_bpr_chk_clear()) {
        crm_flag_clear(CRM_ALL_RESET_FLAG);
        return true;
    }
    // If enter Standby Mode, the sram will power off.
    if (CRM->ctrlsts_bit.lprstf && PWC->ctrlsts_bit.swef && PWC->ctrlsts_bit.sef) {
        crm_flag_clear(CRM_ALL_RESET_FLAG);
        return false;
    }
    // WDT reset & WWDT reset
    if (CRM->ctrlsts_bit.wwdtrstf || CRM->ctrlsts_bit.wdtrstf) {
        crm_flag_clear(CRM_ALL_RESET_FLAG);
        return true;
    }
    // CPU software reset
    if (CRM->ctrlsts_bit.swrstf) {
        crm_flag_clear(CRM_ALL_RESET_FLAG);
        return true;
    }
    // NRST reset (pin)
    // When powered on for the first time, nrstf will also be set, which we need to confirm together with por.
    if (CRM->ctrlsts_bit.nrstf && CRM->ctrlsts_bit.porrstf == 0 && CRM->ctrlsts_bit.swrstf == 0) {
        crm_flag_clear(CRM_ALL_RESET_FLAG);
        return true;
    }
    // POR/LVR reset flag? Or otherwise case...
    crm_flag_clear(CRM_ALL_RESET_FLAG);
    return false;
}

#endif //SYS_HW_AT32_H
