//
// Created by dxl on 2026/5/23.
//

#include "sys_apis.h"

// --- at32 ---
#include "at32f435_437_crm.h"
#include "at32f435_437_pwc.h"
#include "at32f435_437_flash.h"
#include "at32f435_437_misc.h"
// ---

/**
 * @brief empty call definition, avoid errors linking libc.a
 * @param fn_name function name to define for libc.a
 */
#define EMPTY_CALL(fn_name)      \
    void fn_name(void);          \
    __WEAK void fn_name(void) {}

// Empty init definition to avoid errors linking libc.a
EMPTY_CALL(_init)

// Empty _fini definition to avoid errors linking libc.a
EMPTY_CALL(_fini)

/**
  * @brief  this function handles nmi exception.
  * @retval none
  */
void NMI_Handler(void) {
}

/**
  * @brief  this function handles hard fault exception.
  * @retval none
  */
void HardFault_Handler(void) {
    /* go to infinite loop when hard fault exception occurs */
    while (1) {
    }
}

/**
  * @brief  this function handles memory manage exception.
  * @retval none
  */
void MemManage_Handler(void) {
    /* go to infinite loop when memory manage exception occurs */
    while (1) {
    }
}

/**
  * @brief  this function handles bus fault exception.
  * @retval none
  */
void BusFault_Handler(void) {
    /* go to infinite loop when bus fault exception occurs */
    while (1) {
    }
}

/**
  * @brief  this function handles usage fault exception.
  * @retval none
  */
void UsageFault_Handler(void) {
    /* go to infinite loop when usage fault exception occurs */
    while (1) {
    }
}

/**
  * @brief  this function handles svcall exception.
  * @retval none
  */
void SVC_Handler(void) {
}

/**
  * @brief  this function handles debug monitor exception.
  * @retval none
  */
void DebugMon_Handler(void) {
}

/**
  * @brief  this function handles pendsv_handler exception.
  * @retval none
  */
void PendSV_Handler(void) {
}

/**
  * @brief  this function handles systick handler.
  * @retval none
  */
void SysTick_Handler(void) {
}

/**
  * @brief  system clock config program
  * @note   the system clock is configured as follow:
  *         system clock (sclk)   = (hext * pll_ns)/(pll_ms * pll_fr)
  *         system clock source   = HEXT_VALUE
  *         - hext                = 8000000
  *         - sclk                = 48000000
  *         - ahbdiv              = 1
  *         - ahbclk              = 48000000
  *         - apb1div             = 2
  *         - apb1clk             = 24000000
  *         - apb2div             = 1
  *         - apb2clk             = 48000000
  *         - pll_ns              = 96
  *         - pll_ms              = 1
  *         - pll_fr              = 16
  * @param  none
  * @retval none
  */
void system_clock_config_48m(void)
{
  /* reset crm */
  crm_reset();

  /* enable pwc periph clock */
  crm_periph_clock_enable(CRM_PWC_PERIPH_CLOCK, TRUE);

  /* config ldo voltage */
  pwc_ldo_output_voltage_set(PWC_LDO_OUTPUT_1V1);

  /* set the flash clock divider */
  flash_clock_divider_set(FLASH_CLOCK_DIV_2);

  /* enable hext */
  crm_clock_source_enable(CRM_CLOCK_SOURCE_HEXT, TRUE);

   /* wait till hext is ready */
  while(crm_hext_stable_wait() == ERROR)
  {
  }

  /* config pll clock resource
  common frequency config list: pll source selected  hick or hext(8mhz)
  _________________________________________________________________________________________________
  |        |         |         |         |         |         |         |         |        |        |
  |pll(mhz)|   288   |   252   |   216   |   192   |   180   |   144   |   108   |   72   |   36   |
  |________|_________|_________|_________|_________|_________|_________|_________|_________________|
  |        |         |         |         |         |         |         |         |        |        |
  |pll_ns  |   144   |   126   |   108   |   96    |   90    |   72    |   108   |   72   |   72   |
  |        |         |         |         |         |         |         |         |        |        |
  |pll_ms  |   1     |   1     |   1     |   1     |   1     |   1     |   1     |   1    |   1    |
  |        |         |         |         |         |         |         |         |        |        |
  |pll_fr  |   FR_4  |   FR_4  |   FR_4  |   FR_4  |   FR_4  |   FR_4  |   FR_8  |   FR_8 |   FR_16|
  |________|_________|_________|_________|_________|_________|_________|_________|________|________|

  if pll clock source selects hext with other frequency values, or configure pll to other
  frequency values, please use the at32 new clock  configuration tool for configuration.  */
  crm_pll_config(CRM_PLL_SOURCE_HEXT, 96, 1, CRM_PLL_FR_16);

  /* enable pll */
  crm_clock_source_enable(CRM_CLOCK_SOURCE_PLL, TRUE);

  /* wait till pll is ready */
  while(crm_flag_get(CRM_PLL_STABLE_FLAG) != SET)
  {
  }

  /* config ahbclk */
  crm_ahb_div_set(CRM_AHB_DIV_1);

  /* config apb2clk */
  crm_apb2_div_set(CRM_APB2_DIV_1);

  /* config apb1clk */
  crm_apb1_div_set(CRM_APB1_DIV_2);

  /* select pll as system clock source */
  crm_sysclk_switch(CRM_SCLK_PLL);

  /* wait till pll is used as system clock source */
  while(crm_sysclk_switch_status_get() != CRM_SCLK_PLL)
  {
  }

  /* update system_core_clock global variable */
  system_core_clock_update();
}

/**
  * @brief  system clock config
  * @note   the system clock is configured as follow:
  *         system clock (sclk)   = (hext * pll_ns)/(pll_ms * pll_fr)
  *         system clock source   = pll (hext)
  *         - hext                = HEXT_VALUE
  *         - sclk                = 288000000
  *         - ahbdiv              = 1
  *         - ahbclk              = 288000000
  *         - apb2div             = 2
  *         - apb2clk             = 144000000
  *         - apb1div             = 2
  *         - apb1clk             = 144000000
  *         - pll_ns              = 144
  *         - pll_ms              = 1
  *         - pll_fr              = 4
  * @retval none
  */
void system_clock_config_288m(void) {
    nvic_priority_group_config(NVIC_PRIORITY_GROUP_4);

    /* reset crm */
    crm_reset();

    /* enable pwc periph clock */
    crm_periph_clock_enable(CRM_PWC_PERIPH_CLOCK, TRUE);

    /* config ldo voltage */
    pwc_ldo_output_voltage_set(PWC_LDO_OUTPUT_1V3);

    /* set the flash clock divider */
    flash_clock_divider_set(FLASH_CLOCK_DIV_3);

    crm_clock_source_enable(CRM_CLOCK_SOURCE_HEXT, TRUE);

    /* wait till hext is ready */
    while (crm_hext_stable_wait() == ERROR) {
    }

    /* config pll clock resource
    common frequency config list: pll source selected  hick or hext(8mhz)
    _________________________________________________________________________________________________
    |        |         |         |         |         |         |         |         |        |        |
    |pll(mhz)|   288   |   252   |   216   |   192   |   180   |   144   |   108   |   72   |   36   |
    |________|_________|_________|_________|_________|_________|_________|_________|_________________|
    |        |         |         |         |         |         |         |         |        |        |
    |pll_ns  |   144   |   126   |   108   |   96    |   90    |   72    |   108   |   72   |   72   |
    |        |         |         |         |         |         |         |         |        |        |
    |pll_ms  |   1     |   1     |   1     |   1     |   1     |   1     |   1     |   1    |   1    |
    |        |         |         |         |         |         |         |         |        |        |
    |pll_fr  |   FR_4  |   FR_4  |   FR_4  |   FR_4  |   FR_4  |   FR_4  |   FR_8  |   FR_8 |   FR_16|
    |________|_________|_________|_________|_________|_________|_________|_________|________|________|

    if pll clock source selects hext with other frequency values, or configure pll to other
    frequency values, please use the at32 new clock  configuration tool for configuration.  */
    crm_pll_config(CRM_PLL_SOURCE_HEXT, 144, 1, CRM_PLL_FR_4);

    /* enable pll */
    crm_clock_source_enable(CRM_CLOCK_SOURCE_PLL, TRUE);

    /* wait till pll is ready */
    while (crm_flag_get(CRM_PLL_STABLE_FLAG) != SET) {
    }

    /* config ahbclk */
    crm_ahb_div_set(CRM_AHB_DIV_1); // 288mhz

    /* config apb2clk, the maximum frequency of APB1/APB2 clock is 144 MHz  */
    crm_apb2_div_set(CRM_APB2_DIV_2); // 144mhz(288mhz / 2)

    /* config apb1clk, the maximum frequency of APB1/APB2 clock is 144 MHz  */
    crm_apb1_div_set(CRM_APB1_DIV_2); // 144mhz(288mhz / 2)

    /* enable auto step mode */
    crm_auto_step_mode_enable(TRUE);

    /* select pll as system clock source */
    crm_sysclk_switch(CRM_SCLK_PLL);

    /* wait till pll is used as system clock source */
    while (crm_sysclk_switch_status_get() != CRM_SCLK_PLL) {
    }

    /* disable auto step mode */
    crm_auto_step_mode_enable(FALSE);

    /* update system_core_clock global variable */
    system_core_clock_update();
}

/**
  * @brief  system clock config
  * @note   the system clock is configured as follow:
  *         system clock (sclk)   = (hext * pll_ns)/(pll_ms * pll_fr)
  *         system clock source   = pll (hext)
  *         - hext                = HEXT_VALUE
  *         - sclk                = 288000000
  *         - ahbdiv              = 1
  *         - ahbclk              = 288000000
  *         - apb2div             = 2
  *         - apb2clk             = 144000000
  *         - apb1div             = 2
  *         - apb1clk             = 144000000
  *         - pll_ns              = 144
  *         - pll_ms              = 1
  *         - pll_fr              = 4
  * @retval none
  */
void ConfigSystemClocks(void) {
    // system_clock_config_48m();
    system_clock_config_288m();
}

// Refer to the code described in the following link to implement the jump.
// https://community.st.com/t5/stm32-mcus-products/jump-to-application-from-bootloader-not-working/td-p/620734
void __NO_RETURN JumpToAnyImage(uint32_t stack_top, uint32_t entry_point) {
    // Disable and clear all pending interrupts in the Bootloader
    __disable_irq();
    for (int i = 0; i < sizeof(NVIC->ICER) / sizeof(NVIC->ICER[0]); i++) {
        NVIC->ICER[i] = 0xFFFFFFFF;
        NVIC->ICPR[i] = 0xFFFFFFFF;
    }

    // Disable SysTick
    SysTick->CTRL = 0;
    SysTick->LOAD = 0;
    SysTick->VAL = 0;

    SCB->VTOR = entry_point; // Update the Vector Table Offset Register (VTOR)
    __set_MSP(stack_top); // Set the Main Stack Pointer to the App's stack address

    __DSB(); // Ensure the VTOR and SP operations are complete
    __ISB(); // Flush the pipeline because of SP change

    // Re-enable all interrupts before new application running.
    __enable_irq();

    // Run the Application Reset Handler
    ((void (*)(void)) *(uint32_t *) (entry_point + 4))();

    while (1); // No Warning.
}
