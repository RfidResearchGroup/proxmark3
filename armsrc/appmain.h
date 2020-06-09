//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions internal to the app source.
//-----------------------------------------------------------------------------
#ifndef __APPMAIN_H
#define __APPMAIN_H

#include "common.h"

extern int g_rsamples;   // = 0;
extern uint8_t g_trigger;

// ADC Vref = 3300mV, and an (10M+1M):1M voltage divider on the HF input can measure voltages up to 36300 mV
#define MAX_ADC_HF_VOLTAGE 36300
// ADC Vref = 3300mV,  (240k-10M):240k voltage divider,  140800 mV
#define MAX_ADC_HF_VOLTAGE_RDV40 140800
// ADC Vref = 3300mV, and an (10000k+240k):240k voltage divider on the LF input can measure voltages up to 140800 mV
#define MAX_ADC_LF_VOLTAGE 140800

extern int ToSendMax;
extern uint8_t ToSend[];

void send_wtx(uint16_t wtx);
void ReadMem(int addr);
void __attribute__((noreturn)) AppMain(void);

uint16_t AvgAdc(int ch);
uint16_t SumAdc(int ch, int NbSamples);

//void PrintToSendBuffer(void);
void ToSendStuffBit(int b);
void ToSendReset(void);
void ListenReaderField(uint8_t limit);
void StandAloneMode(void);
void printStandAloneModes(void);

#endif
