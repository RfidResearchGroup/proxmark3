//-----------------------------------------------------------------------------
// Utility functions used in many places, not specific to any piece of code.
// Jonathan Westhues, Sept 2005
//-----------------------------------------------------------------------------
#include <proxmark3.h>
#include "apps.h"

void *memcpy(void *dest, const void *src, int len)
{
	BYTE *d = dest;
	const BYTE *s = src;
	while((len--) > 0) {
		*d = *s;
		d++;
		s++;
	}
	return dest;
}

void *memset(void *dest, int c, int len)
{
	BYTE *d = dest;
	while((len--) > 0) {
		*d = c;
		d++;
	}
	return dest;
}

int memcmp(const void *av, const void *bv, int len)
{
	const BYTE *a = av;
	const BYTE *b = bv;

	while((len--) > 0) {
		if(*a != *b) {
			return *a - *b;
		}
		a++;
		b++;
	}
	return 0;
}

int strlen(char *str)
{
	int l = 0;
	while(*str) {
		l++;
		str++;
	}
	return l;
}

char* strncat(char *dest, const char *src, unsigned int n)
{
	unsigned int dest_len = strlen(dest);
	unsigned int i;
	
	for (i = 0 ; i < n && src[i] != '\0' ; i++)
		dest[dest_len + i] = src[i];
	dest[dest_len + i] = '\0';
	
	return dest;
}

void num_to_bytes(uint64_t n, size_t len, byte_t* dest)
{
	while (len--) {
		dest[len] = (byte_t) n;
		n >>= 8;
	}
}

uint64_t bytes_to_num(byte_t* src, size_t len)
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

	WORD start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

	int letoff = 0;
	for(;;)
	{
		WORD now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

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
				if (now == (WORD)(start + ticks))
					return BUTTON_HOLD;
		}

		// We already let off, did we click again?
		else
			// Sweet, double click!
			if (BUTTON_PRESS())
				return BUTTON_DOUBLE_CLICK;

			// Have we ran out of time to double click?
			else
				if (now == (WORD)(start + ticks))
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

	WORD start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

	for(;;)
	{
		WORD now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

		// As soon as our button let go, we didn't hold long enough
		if (!BUTTON_PRESS())
			return BUTTON_SINGLE_CLICK;

		// Have we waited the full second?
		else
			if (now == (WORD)(start + ticks))
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

	WORD start = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;

	for(;;) {
		WORD now = AT91C_BASE_PWMC_CH0->PWMC_CCNTR;
		if (now == (WORD)(start + ticks))
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
