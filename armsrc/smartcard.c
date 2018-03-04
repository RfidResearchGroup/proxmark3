#include "smartcard.h"

/*
PA5 	SIM I/O
PA7		SIM CLOCK
PA10	SIM RESET

Both RX / TX is connected to PA5

*/

void SmartCardSetup(void) {
	// PA5	-> 
	// PA7 	-> 
	// PA10 -> 
}

void SmartCardStop(void) {
	StopTicks();
	Dbprintf("SmartCardStop");
	LED_A_OFF();
}

bool SmartCardInit(void) {
	
	StartTicks();

	LED_A_ON();	
	SmartCardSetup();

	Dbprintf("SmartCardInit");
	return true;
}

