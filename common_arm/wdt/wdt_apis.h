#ifndef WDT_APIS_H_
#define WDT_APIS_H_

#include "common.h"


/*
 * The AT32 platform cannot disable the watchdog!
 * So it is important to handle the gap between blocking tasks and HIT operations.
 */


// feed the dog
STATIC_FORCE_INLINE void WDT_HIT(void);

// hardware watch dog setup and enable
void WDTSetup(void);

#ifdef PM5
#include "wdt_hw_at32.h"
#else
#include "wdt_hw_at91.h"
#endif

#endif // WDT_APIS_H_
