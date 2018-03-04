//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
//						Common Instructions 						  //
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
#ifndef __SMARTCARD_H
#define __SMARTCARD_H

#include "proxmark3.h"
#include "apps.h"
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
extern void Dbprintf(const char *fmt, ...);

void SmartCardSetup(void);
void SmartCardStop(void);
bool SmartCardInit();

 #endif