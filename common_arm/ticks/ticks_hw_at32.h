//
// Created by dxl on 2026/2/7.
//

#ifndef TICKS_HW_AT32_H
#define TICKS_HW_AT32_H

#include "at32f435_437_crm.h"
#include "at32f435_437_tmr.h"

// TODO DXL 用 TIMER2 的 ch2 来统计来自于外部ssp-clk的时钟数量
//  用于 at32 不支持类似 at91 那种 gpio 的输入直接两个外设就能同时使用的情况，所以必须要将实际上 ssp-clk 的脚，连接到 ch2 上
//  这样子 TIMER2 选中为外部时钟输入模式时，才能最终链接 SSP 和 TMR

// ssp clk counter
#define AT32_CRM_TMR_PERIPH_COUNT_SSP_CLK   CRM_TMR2_PERIPH_CLOCK
#define AT32_TMR_COUNT_SSP_CLK              TMR2
#define AT32_TMR_COUNT_SSP_CLK_IN_CH        TMR_SELECT_CHANNEL_2

// 32bit timer
#define AT32_CRM_TMR_PERIPH_32B_TIMER_CLK   CRM_TMR5_PERIPH_CLOCK
#define AT32_TMR_32B_TIMER                  TMR5

#endif //TICKS_HW_AT32_H
