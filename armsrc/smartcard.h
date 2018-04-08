#ifndef __SMARTCARD_H
#define __SMARTCARD_H

#include "usb_cdc.h"
#include "proxmark3.h"
#include "apps.h"
#include "ticks.h"
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
extern void Dbprintf(const char *fmt, ...);

void SmartCard_setup(void);
void SmartCard_stop(void);
bool SmartCard_init();

void SMART_CARD_ServiceSmartCard( void );
void SmartCard_print_status(void);
#endif