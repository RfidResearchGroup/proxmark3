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
	PWM_ENABLE = PWM_CHANNEL(0);
	// 48 MHz / 1024 gives 46.875 kHz
	PWM_CH_MODE(0) = PWM_CH_MODE_PRESCALER(10);
	PWM_CH_DUTY_CYCLE(0) = 0;
	PWM_CH_PERIOD(0) = 0xffff;
	
	WORD start = (WORD)PWM_CH_COUNTER(0);
	
	int letoff = 0;
	for(;;)
	{
		WORD now = (WORD)PWM_CH_COUNTER(0);
		
		// We haven't let off the button yet
		if (!letoff)
		{
			// We just let it off!
			if (!BUTTON_PRESS())
			{
				letoff = 1;

				// reset our timer for 500ms
				start = (WORD)PWM_CH_COUNTER(0);
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
	PWM_ENABLE = PWM_CHANNEL(0);
	// 48 MHz / 1024 gives 46.875 kHz
	PWM_CH_MODE(0) = PWM_CH_MODE_PRESCALER(10);
	PWM_CH_DUTY_CYCLE(0) = 0;
	PWM_CH_PERIOD(0) = 0xffff;
	
	WORD start = (WORD)PWM_CH_COUNTER(0);
	
	for(;;)
	{
		WORD now = (WORD)PWM_CH_COUNTER(0);
		
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

void SpinDelayUs(int us)
{
	int ticks = (48*us) >> 10;
	
	// Borrow a PWM unit for my real-time clock
	PWM_ENABLE = PWM_CHANNEL(0);
	// 48 MHz / 1024 gives 46.875 kHz
	PWM_CH_MODE(0) = PWM_CH_MODE_PRESCALER(10);
	PWM_CH_DUTY_CYCLE(0) = 0;
	PWM_CH_PERIOD(0) = 0xffff;
	
	WORD start = (WORD)PWM_CH_COUNTER(0);
	
	for(;;) {
		WORD now = (WORD)PWM_CH_COUNTER(0);
		if(now == (WORD)(start + ticks)) {
			return;
		}
		WDT_HIT();
	}
}

void SpinDelay(int ms)
{
	int ticks = (48000*ms) >> 10;

	// Borrow a PWM unit for my real-time clock
	PWM_ENABLE = PWM_CHANNEL(0);
	// 48 MHz / 1024 gives 46.875 kHz
	PWM_CH_MODE(0) = PWM_CH_MODE_PRESCALER(10);
	PWM_CH_DUTY_CYCLE(0) = 0;
	PWM_CH_PERIOD(0) = 0xffff;

	WORD start = (WORD)PWM_CH_COUNTER(0);

	for(;;)
	{
		WORD now = (WORD)PWM_CH_COUNTER(0);
		if (now == (WORD)(start + ticks))
			return;

		WDT_HIT();
	}
}
