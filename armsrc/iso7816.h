#ifndef __ISO7816_H
#define __ISO7816_H

#include "proxmark3.h"
#include "apps.h"
#include "ticks.h"

//	Used Command
#define ID				0x90

#define SPI_CLK       75000000       //Hex equivalent of 75MHz

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~//
extern void Dbprintf(const char *fmt, ...);

void ISO7816_setup(void);
void ISO7816_stop(void);
bool ISO7816_waitidle(void);
uint16_t ISO7816_sendbyte(uint32_t data);
bool ISO7816_init();
void ISO7816_test(void);

#endif