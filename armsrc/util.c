//-----------------------------------------------------------------------------
// Jonathan Westhues, Sept 2005
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Utility functions used in many places, not specific to any piece of code.
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "util.h"
#include "string.h"

void num_to_bytes(uint64_t n, size_t len, uint8_t* dest)
{
	while (len--) {
		dest[len] = (uint8_t) n;
		n >>= 8;
	}
}

uint64_t bytes_to_num(uint8_t* src, size_t len)
{
	uint64_t num = 0;
	while (len--)
	{
		num = (num << 8) | (*src);
		src++;
	}
	return num;
}

void LEDsoff()
{
	LED_A_OFF();
	LED_B_OFF();
	LED_C_OFF();
	LED_D_OFF();
}

// LEDs: R(C) O(A) G(B) -- R(D) [1, 2, 4 and 8]
void LED(int led, int ms)
{
	if (led & LED_RED)
		LED_C_ON();
	if (led & LED_ORANGE)
		LED_A_ON();
	if (led & LED_GREEN)
		LED_B_ON();
	if (led & LED_RED2)
		LED_D_ON();

	if (!ms)
		return;

	SpinDelay(ms);

	if (led & LED_RED)
		LED_C_OFF();
	if (led & LED_ORANGE)
		LED_A_OFF();
	if (led & LED_GREEN)
		LED_B_OFF();
	if (led & LED_RED2)
		LED_D_OFF();
}


// Determine if a button is double clicked, single clicked,
// not clicked, or held down (for ms || 1sec)
// In general, don't use this function unless you expect a
// double click, otherwise it will waste 500ms -- use BUTTON_HELD instead
int BUTTON_CLICKED(int ms)
{
	// Up to 500ms in between clicks to mean a double click
	int ticks = (48000 * (ms ? ms : 1000)) >> 10;

	// If we're not even pressed, forget about it!
	if (!BUTTON_PRESS())
		return BUTTON_NO_CLICK;

	// Borrow a PWM unit for my real-time clock
	AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(0);
	// 48 MHz / 1024 gives 46.875 kHz
	AT91C_BASE_PWMC_CH0->PWMC_CMR = PWM_CH_MODE_PRESCALER(10);
	AT91C_BASE_PWMC_CH0->PWMC_CDTYR = 0;
	AT91C_BASE_PWMC_CH0->PWMC_CPRDR = 0xffff;

	uint16_t start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

	int letoff = 0;
	for(;;)
	{
		uint16_t now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

		// We haven't let off the button yet
		if (!letoff)
		{
			// We just let it off!
			if (!BUTTON_PRESS())
			{
				letoff = 1;

				// reset our timer for 500ms
				start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;
				ticks = (48000 * (500)) >> 10;
			}

			// Still haven't let it off
			else
				// Have we held down a full second?
				if (now == (uint16_t)(start + ticks))
					return BUTTON_HOLD;
		}

		// We already let off, did we click again?
		else
			// Sweet, double click!
			if (BUTTON_PRESS())
				return BUTTON_DOUBLE_CLICK;

			// Have we ran out of time to double click?
			else
				if (now == (uint16_t)(start + ticks))
					// At least we did a single click
					return BUTTON_SINGLE_CLICK;

		WDT_HIT();
	}

	// We should never get here
	return BUTTON_ERROR;
}

// Determine if a button is held down
int BUTTON_HELD(int ms)
{
	// If button is held for one second
	int ticks = (48000 * (ms ? ms : 1000)) >> 10;

	// If we're not even pressed, forget about it!
	if (!BUTTON_PRESS())
		return BUTTON_NO_CLICK;

	// Borrow a PWM unit for my real-time clock
	AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(0);
	// 48 MHz / 1024 gives 46.875 kHz
	AT91C_BASE_PWMC_CH0->PWMC_CMR = PWM_CH_MODE_PRESCALER(10);
	AT91C_BASE_PWMC_CH0->PWMC_CDTYR = 0;
	AT91C_BASE_PWMC_CH0->PWMC_CPRDR = 0xffff;

	uint16_t start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

	for(;;)
	{
		uint16_t now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

		// As soon as our button let go, we didn't hold long enough
		if (!BUTTON_PRESS())
			return BUTTON_SINGLE_CLICK;

		// Have we waited the full second?
		else
			if (now == (uint16_t)(start + ticks))
				return BUTTON_HOLD;

		WDT_HIT();
	}

	// We should never get here
	return BUTTON_ERROR;
}

// attempt at high resolution microsecond timer
// beware: timer counts in 21.3uS increments (1024/48Mhz)
void SpinDelayUs(int us)
{
	int ticks = (48*us) >> 10;

	// Borrow a PWM unit for my real-time clock
	AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(0);
	// 48 MHz / 1024 gives 46.875 kHz
	AT91C_BASE_PWMC_CH0->PWMC_CMR = PWM_CH_MODE_PRESCALER(10);
	AT91C_BASE_PWMC_CH0->PWMC_CDTYR = 0;
	AT91C_BASE_PWMC_CH0->PWMC_CPRDR = 0xffff;

	uint16_t start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

	for(;;) {
		uint16_t now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;
		if (now == (uint16_t)(start + ticks))
			return;

		WDT_HIT();
	}
}

void SpinDelay(int ms)
{
  // convert to uS and call microsecond delay function
	SpinDelayUs(ms*1000);
}

/* Similar to FpgaGatherVersion this formats stored version information
 * into a string representation. It takes a pointer to the struct version_information,
 * verifies the magic properties, then stores a formatted string, prefixed by
 * prefix in dst.
 */
void FormatVersionInformation(char *dst, int len, const char *prefix, void *version_information)
{
	struct version_information *v = (struct version_information*)version_information;
	dst[0] = 0;
	strncat(dst, prefix, len);
	if(v->magic != VERSION_INFORMATION_MAGIC) {
		strncat(dst, "Missing/Invalid version information", len);
		return;
	}
	if(v->versionversion != 1) {
		strncat(dst, "Version information not understood", len);
		return;
	}
	if(!v->present) {
		strncat(dst, "Version information not available", len);
		return;
	}

	strncat(dst, v->svnversion, len);
	if(v->clean == 0) {
		strncat(dst, "-unclean", len);
	} else if(v->clean == 2) {
		strncat(dst, "-suspect", len);
	}

	strncat(dst, " ", len);
	strncat(dst, v->buildtime, len);
}

//  -------------------------------------------------------------------------
//  timer lib
//  -------------------------------------------------------------------------
//  test procedure:
//
//	ti = GetTickCount();
//	SpinDelay(1000);
//	ti = GetTickCount() - ti;
//	Dbprintf("timer(1s): %d t=%d", ti, GetTickCount());

void StartTickCount()
{
//  must be 0x40, but on my cpu - included divider is optimal
//  0x20 - 1 ms / bit 
//  0x40 - 2 ms / bit

	AT91C_BASE_RTTC->RTTC_RTMR = AT91C_RTTC_RTTRST + 0x001D; // was 0x003B
}

/*
* Get the current count.
*/
uint32_t RAMFUNC GetTickCount(){
	return AT91C_BASE_RTTC->RTTC_RTVR;// was * 2;
}

//  -------------------------------------------------------------------------
//  microseconds timer 
//  -------------------------------------------------------------------------
void StartCountUS()
{
	AT91C_BASE_PMC->PMC_PCER |= (0x1 << 12) | (0x1 << 13) | (0x1 << 14);
//	AT91C_BASE_TCB->TCB_BMR = AT91C_TCB_TC1XC1S_TIOA0;
	AT91C_BASE_TCB->TCB_BMR = AT91C_TCB_TC0XC0S_NONE | AT91C_TCB_TC1XC1S_TIOA0 | AT91C_TCB_TC2XC2S_NONE;

	// fast clock
	AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS; // timer disable
	AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK | // MCK(48MHz)/32 -- tick=1.5mks
														AT91C_TC_WAVE | AT91C_TC_WAVESEL_UP_AUTO | AT91C_TC_ACPA_CLEAR |
														AT91C_TC_ACPC_SET | AT91C_TC_ASWTRG_SET;
	AT91C_BASE_TC0->TC_RA = 1;
	AT91C_BASE_TC0->TC_RC = 0xBFFF + 1; // 0xC000
	
	AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKDIS; // timer disable  
	AT91C_BASE_TC1->TC_CMR = AT91C_TC_CLKS_XC1; // from timer 0

	AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN;
	AT91C_BASE_TC1->TC_CCR = AT91C_TC_CLKEN;
	AT91C_BASE_TCB->TCB_BCR = 1;
}

uint32_t RAMFUNC GetCountUS(){
	return (AT91C_BASE_TC1->TC_CV * 0x8000) + ((AT91C_BASE_TC0->TC_CV / 15) * 10);
}

static uint32_t GlobalUsCounter = 0;

uint32_t RAMFUNC GetDeltaCountUS(){
	uint32_t g_cnt = GetCountUS();
	uint32_t g_res = g_cnt - GlobalUsCounter;
	GlobalUsCounter = g_cnt;
	return g_res;
}


