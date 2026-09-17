#ifndef __WDT_HW_AT91_H__
#define __WDT_HW_AT91_H__

#include "common.h"
#include "at91sam7s512.h"

STATIC_FORCE_INLINE void WDT_HIT(void) {
    AT91C_BASE_WDTC->WDTC_WDCR = 0xa5000001;
}

#endif
