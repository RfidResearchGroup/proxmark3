/**************************************************************************************************
 *
 *  @project        Proxmark 3
 *  @file           smartcard.c
 *  @author         Chris Nocker <nocker02@gmail.com>
 *  @created        03/04/2018
 *  @brief          Implements communication with a smart card.
 *
 *************************************************************************************************/
#include "smartcard.h"

//#define SMART_CARD_DEBUG_ENABLED
#ifndef SMART_CARD_DEBUG_ENABLED

#endif  // SMART_CARD_DEBUG_ENABLED

// -- Defines ---------------------------------------------------------------------------------- //
#define SMART_CARD_RST_PIN					AT91C_PIO_PA1
#define SMART_CARD_IO_PIN					AT91C_PIO_PA5
#define SMART_CARD_CLK_PIN					AT91C_PIO_PA7
#define SMART_CARD_RST_LO 					AT91C_BASE_PIOA->PIO_CODR |= SMART_CARD_RST_PIN
#define SMART_CARD_RST_HI					AT91C_BASE_PIOA->PIO_SODR |= SMART_CARD_RST_PIN
#define SMART_CARD_RST_STATE				AT91C_BASE_PIOA->PIO_ODSR & SMART_CARD_RST_PIN
#define SMART_CARD_IO_LO 					AT91C_BASE_PIOA->PIO_CODR |= SMART_CARD_IO_PIN
#define SMART_CARD_IO_HI 					AT91C_BASE_PIOA->PIO_SODR |= SMART_CARD_IO_PIN
#define SMART_CARD_IO_STATE					AT91C_BASE_PIOA->PIO_ODSR & SMART_CARD_IO_PIN
#define SMART_CARD_CLK_LO 					AT91C_BASE_PIOA->PIO_CODR |= SMART_CARD_CLK_PIN
#define SMART_CARD_CLK_HI 					AT91C_BASE_PIOA->PIO_SODR |= SMART_CARD_CLK_PIN
#define SMART_CARD_CLK_STATE				AT91C_BASE_PIOA->PIO_ODSR & SMART_CARD_CLK_PIN
#define SMART_CARD_IO_OUPUT_MODE			AT91C_BASE_PIOA->PIO_OER = SMART_CARD_IO_PIN
#define SMART_CARD_IO_RECEPTION_MODE		AT91C_BASE_PIOA->PIO_ODR = SMART_CARD_IO_PIN
#define SMART_CARD_RECEIVE_BUFFER_SIZE		(10)
#define SMART_CARD_TRANSMIT_BUFFER_SIZE		(10)

#define SMART_CARD_CLOCK					AT91C_BASE_PWMC_CH1


// true = the distance between a and b is greater than c
#define RANGE(a,b,c)						((MAX(a,b))-(MIN(a,b))>(c))

// -- Private Variables ------------------------------------------------------------------------ //

static bool triggerDeactivation;
static bool communicationsEstablished;
static uint16_t receiveBuffer[SMART_CARD_RECEIVE_BUFFER_SIZE];	// Raw received bytes that need their parity checked before using them
static uint8_t receiveGetPtr;
static uint8_t receivePutPtr;
static uint8_t transmitBuffer[SMART_CARD_TRANSMIT_BUFFER_SIZE];
static uint8_t transmitGetPtr;
static uint8_t transmitPutPtr;
static bool generateClk;
static bool receptionMode;
static bool transmitMode;

/**
 *  @brief          Get a transmit byte
 *  @description    Get a byte from the transmit buffer
 *  @param          receivedByte			Pointer to return the byte from the buffer to the caller
 *  @return         bool                    true  = A byte was removed from the buffer and returned to the caller
 *                                          false = No byte available
 */
static bool SMART_CARD_GetTransmitByte( uint8_t * receivedByte ) {
	bool result = false;
	uint8_t tempGetPtr = transmitGetPtr;

	// Move the temp put pointer to the next index
	if ( ++tempGetPtr >= SMART_CARD_RECEIVE_BUFFER_SIZE ) {
		tempGetPtr = 0;
	}

	// If the get pointer does not match the put pointer then there is data to be taken from the buffer
	if ( transmitGetPtr != transmitPutPtr )	{
		*receivedByte = transmitBuffer[transmitGetPtr];
		transmitGetPtr = tempGetPtr;
		result = true;
	}

	return result;
}

/**
 *  @brief          Put transmit byte
 *  @description    Store a byte in the transmit buffer
 *  @param          transmitByte			The byte to try and put in the buffer
 *  @return         bool                    true  = Operation was performed successfully
 *                                          false = No room in buffer :-(
 */
static bool SMART_CARD_PutTransmitByte( uint8_t transmitByte ) {
	bool result = false;
	uint8_t tempPutPtr = transmitPutPtr;

	// Move the temp put pointer to the next index
	if ( ++tempPutPtr >= SMART_CARD_RECEIVE_BUFFER_SIZE ) {
		tempPutPtr = 0;
	}

	// If the new put pointer does not match the get pointer then it is safe to save this byte
	if ( tempPutPtr != transmitGetPtr ) {
		transmitBuffer[transmitPutPtr] = transmitByte;
		transmitPutPtr = tempPutPtr;
		result = true;
	}

	return result;
}

/**
 *  @brief          Get received byte
 *  @description    Get a byte from the receive buffer
 *  @param          receivedByte			Pointer to return the byte from the buffer to the caller
 *  @return         bool                    true  = A byte was removed from the buffer and returned to the caller
 *                                          false = No byte available
 */
static bool SMART_CARD_GetRecievedByte( uint16_t * receivedByte ) {
	bool result = false;
	uint8_t tempGetPtr = receiveGetPtr;

	// Move the temp put pointer to the next index
	if ( ++tempGetPtr >= SMART_CARD_RECEIVE_BUFFER_SIZE ) {
		tempGetPtr = 0;
	}

	// If the get pointer does not match the put pointer then there is data to be taken from the buffer
	if ( receiveGetPtr != receivePutPtr ) {
		*receivedByte = receiveBuffer[receiveGetPtr];
		receiveGetPtr = tempGetPtr;
		result = true;
	}

	return result;
}

/**
 *  @brief          Put received byte
 *  @description    Store a verified, received byte in the receive buffer
 *  @param          receivedByte			The byte to try and put in the buffer
 *  @return         bool                    true  = Operation was performed successfully
 *                                          false = No room in buffer :-(
 */
static bool SMART_CARD_PutRecievedByte( uint16_t receivedByte ) {
	bool result = false;
	uint8_t tempPutPtr = receivePutPtr;

	// Move the temp put pointer to the next index
	if ( ++tempPutPtr >= SMART_CARD_RECEIVE_BUFFER_SIZE ) {
		tempPutPtr = 0;
	}

	// If the new put pointer does not match the get pointer then it is safe to save this byte
	if ( tempPutPtr != receiveGetPtr ) {
		receiveBuffer[receivePutPtr] = receivedByte;
		receivePutPtr = tempPutPtr;
		result = true;
	}

	return result;
}

/**
 *  @brief          Calculate byte parity
 *  @description    Calculate the parity of a byte
 *  @param          dataByte				Byte to calculate the parity of
 *  @return         bool                    true  = Parity of the byte is high
 *                                          false = Parity of the byte is low
 */
static bool SMART_CARD_CalculateByteParity( uint8_t dataByte ) {
	bool result;
	uint8_t i, parity;

	// Accumulate the parity
	for ( i = 0, parity = 0; i < 8; i++ ) {
		if ( dataByte & ( 1 << i ) ) {
			parity++;
		}
	}

	// The high (1) bits of the byte plus the parity bit must be even for the byte to be considered as good
	result = ( parity % 2 ) ? true : false;

	return result;
}

/**
 *  @brief          Verify received byte parity
 *  @description    Calculate the parity of a received sampled byte and compare it to the parity in the received sampled byte
 *  @param          receivedSampledByte		Byte to verify the parity of
 *  @return         bool                    true  = Parity of the received byte is good
 *                                          false = Parity of the received byte is bad (reject)
 */
static bool SMART_CARD_VerifyReceivedByteParity( uint16_t receivedSampledByte ) {
	bool result;
	uint8_t dataByte = (uint8_t)(receivedSampledByte >> 1 );

	// Check if the calculated parity is the same as the parity in the received sampled byte
	if ( SMART_CARD_CalculateByteParity( dataByte ) == ( receivedSampledByte & 1 ) )
		result = true;
	else
		result = false;

	return result;
}

/**
 *  @brief          Maintain the smart card connection
 *  @description    Send and receive commands
 *  @param          void
 *  @return         bool                    true  = Operation was performed successfully
 *                                          false = An error occurred
 */
static bool SMART_CARD_MaintainConnection( void ) {
	// TODO: This functions implementation is not yet complete

	bool result = true;
	uint16_t rxByte;
	uint8_t verifiedRxByte;

	// See if there has been a new byte sampled
	if ( SMART_CARD_GetRecievedByte( &rxByte ) ) {
		// Check that the parity is correct
		if ( SMART_CARD_VerifyReceivedByteParity( rxByte ) ) {
			verifiedRxByte = rxByte >> 1;

			// TODO: Dummy code that is to remove compiler warnings during development
			if ( verifiedRxByte ) {
				SMART_CARD_PutTransmitByte( verifiedRxByte );
			}
		}
	}

	return result;
}

/**
 *  @brief          Disable the clock
 *  @description
 *  @param          void
 *  @return         void
 */
static void SMART_CARD_DisableClock( void ) {
	// Disable TC2
	//AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKDIS;
	AT91C_BASE_PWMC->PWMC_DIS = PWM_CHANNEL(1);
	generateClk = false;
}

/**
 *  @brief          Enable the clock
 *  @description
 *  @param          void
 *  @return         void
 */
static void SMART_CARD_EnableClock( void )  {
	// Enable and reset TC2
	//AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKEN | AT91C_TC_SWTRG;
	AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(1);
	generateClk = true;
}

/**
 *  @brief          Perform deactivation
 *  @description    Control the signals to the smart card to perform a deactivation operation
 *  @param          void
 *  @return         bool                    true  = Operation was performed successfully
 *                                          false = An error occurred
 */
static void SMART_CARD_PerformDeactivation( void ) {
	/*
	 * 1. Reset L
	 * 2. CLK L
	 * 3. I/O L
	 * 4. VCC L (NOTE: This may require a circuit change!!!)
	 */
	SMART_CARD_RST_LO;
	SMART_CARD_IO_LO;
	SMART_CARD_DisableClock();
}

/**
 *  @brief          Negotiate parameters
 *  @description
 *  @param          void
 *  @return         bool                    true  = Operation was performed successfully
 *                                          false = An error occurred
 */
//static bool SMART_CARD_NegotiateProtocolParameters( void ) {
// TODO: This functions implementation is not yet complete
//	bool result = false;
//
//	// Check if the card is in a specific mode
//	if ( 0xFF )
//	{
//		// Have to use this mode
//	}
//	else
//	{
//		// Negotiate
//	}
//
//	return result;
//}


/**
 *  @brief          Class selection
 *  @description    Class selection
 *  @param          void
 *  @return         bool                    true  = Operation was performed successfully
 *                                          false = An error occurred
 */
static bool SMART_CARD_ClassSelection( uint8_t class, uint8_t * answer, uint8_t length ) {
	bool result = false;

	// Check that an answer was received
	if ( answer[0] ) {
		// Check that the answer was valid
		if ( answer[1] ) {
			// See if the card indicated a class
			if ( answer[2] ) {
				// Check that we are happy with the class (i.e. this is the 3V one that we supplied)
				if ( answer[2] == 2 ) {
					result = true;
				} else {
					// We cannot work with this class
					triggerDeactivation = true;
				}
			} else {
				// Card did not indicate class, just accept this answer				
				result = true;
			}
		} else {
			// Error handling
		}
	} else {
		// Card did not answer
		triggerDeactivation = true;
	}
	return result;
}


/**
 *  @brief          Process the reset answer
 *  @description
 *  @param          answer
 *  @return         bool                    true  = Operation was performed successfully
 *                                          false = An error occurred
 */
static bool SMART_CARD_ProcessResetAnswer( uint8_t* answer, uint8_t length ) {
	// TODO: This functions implementation is not yet complete
	bool result = false;
	uint8_t class;

	for ( class = 0; class < 3; class++ ) {
		// We can only do one class as we cannot adjust the VCC voltage
		if ( SMART_CARD_ClassSelection( class, answer, length ) ) {
			result = true;
			break;
		} else {
			if ( triggerDeactivation ) {
				triggerDeactivation = false;
				SMART_CARD_PerformDeactivation();
			}
		}
	}

	return result;
}


/**
 *  @brief          Perform warm reset
 *  @description    Can be performed at any time (not sure we'll use this one???)
 *  @param          void
 *  @return         bool                    true  = Operation was performed successfully
 *                                          false = An error occurred
 */
//static bool SMART_CARD_PerformWarmReset( void ) {
// TODO: This functions implementation is not yet complete
//	bool result = false;
//	/*
//	 * 1. the interface device initiates a warm reset (at time Tc) by putting RST to state L for at least 400 clock cycles (delay te) while VCC remains powered and CLK provided
//	 * 2. The card shall set I/O to state H within 200 clock cycles (delay td) after state L is applied to RST
//	 * 3. RST is put to state H
//	 * 4. The answer on I/O shall begin between 400 and 40 000 clock cycles (delay tf) after the rising edge of the signal on RST
//	 * 5. If the answer does not begin within 40 000 clock cycles with RST at state H, the interface device shall perform a deactivation
//	 */
//
//	return result;
//}

/**
 *  @brief          Perform cold reset
 *  @description	We are outputting the CLK to the smart card.  Wait for the initial reset answer
 *  @param          void
 *  @return         bool                    true  = Operation was performed successfully
 *                                          false = An error occurred
 */
static bool SMART_CARD_PerformColdReset( void ) {
	// TODO: This functions implementation is not yet complete
	bool result = false;
	/*
	 * 1. The card shall set I/O to state H within 200 clock cycles
	 *       The cold reset results from maintaining RST at state L for at least 400 clock cycles (delay tb) after the clock signal is applied to CLK
	 * 2. The interface device shall ignore the state on I/O while RST is at state L
	 * 3. RST is put to state H
	 * 4. The answer on I/O shall begin between 400 and 40 000 clock cycles (delay tc) after the rising edge of the signal on RST
	 * 5. If the answer does not begin within 40 000 clock cycles with RST at state H, the interface device shall perform a deactivation
	 */

	return result;
}

/**
 *  @brief          Activate the smart card interface
 *  @description	Control the interface signals to perform an activation on the smart card
 *  @param          void
 *  @return         void
 */
static void SMART_CARD_ActivateInterface( void ) {
	/*
	 * 1. RST shall be put to state L
	 * 2. VCC shall be powered
	 * 3. I/O in the interface device shall be put in reception mode
	 * 4. CLK shall be provided with a clock signal (1MHz to 5MHz)
	 */
	SMART_CARD_RST_LO;
	SMART_CARD_IO_RECEPTION_MODE;
	SMART_CARD_EnableClock();
}

/**
 *  @brief          Establish communications
 *  @description	Activate the smart card, perform a cold reset & process the reset answer
 *  @param          void
 *  @return         bool                    true  = Operation was performed successfully and communications have been established
 *                                          false = An error occurred
 */
static bool SMART_CARD_EstablishCommunications( void ) {
	// TODO: This functions implementation is not yet complete
	bool result = false;
	uint8_t answer[100];

	// Activate the interface
	SMART_CARD_ActivateInterface();

	// Perform a cold reset
	result = SMART_CARD_PerformColdReset();

	// Process the "answer" if it was received
	if ( result ) {
		result = SMART_CARD_ProcessResetAnswer( answer, 100 );

		// Check if the "answer" was acceptable
		if ( !result ) {
			// Delay for 20ms
			WaitMS( 20 );
		}
	}
	
	return result;
}

/**
 *  @brief          Configure timer
 *  @description	Configure the timer to generate an interrupt every 500ns.  This is 2MHz.  From this we will
 *  				generate the 1MHz clock signal and sample the I/O line every 2 interrupt triggers
 *  @param          void
 *  @return         void
 */
static void SMART_CARD_ConfigureClock( void ) {
	/*
	AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_TC2);  			// Enable Clock TC2

	AT91C_BASE_TCB->TCB_BMR &= AT91C_TCB_TC2XC2S;				// Clear the external clock selection
	AT91C_BASE_TCB->TCB_BMR |= AT91C_TCB_TC2XC2S_NONE;			// XC2 Clock = None

	// Configure TC2 to count up to RC, then reset and generate an interrupt
	AT91C_BASE_TC2->TC_CCR = AT91C_TC_CLKDIS;					// Disable TC2
	AT91C_BASE_TC2->TC_CMR =  AT91C_TC_CLKS_TIMER_DIV1_CLOCK	// TC2 Clock = MCK(48MHz)/2 = 24MHz
							| AT91C_TC_CPCTRG; 					// Capture Mode, reset the TC2 counter when RC is reached
	AT91C_BASE_TC2->TC_RC = 12; 								// RC Compare value = 24MHz / 2MHz = 12
	AT91C_BASE_TC2->TC_IER = AT91C_TC_CPCS;						// Generate an interrupt when the RC value is reached
	
	*/

	// enable PWM Clock
	AT91C_BASE_PMC->PMC_PCER |= (1 << AT91C_ID_PWMC);
	
	// Enable channel1 as SMART CARD real-time clock
	AT91C_BASE_PWMC->PWMC_ENA = PWM_CHANNEL(1);
	
	// 48 MHz / 16 gives 3MHz
	SMART_CARD_CLOCK->PWMC_CMR = PWM_CH_MODE_PRESCALER(3);	// Channel Mode Register
	SMART_CARD_CLOCK->PWMC_CDTYR = 0;						// Channel Duty Cycle Register
	SMART_CARD_CLOCK->PWMC_CPRDR = 0xffff;					// Channel Period Register
	
	AT91C_BASE_PWMC->PWMC_IER = 1 << 1;
	// AT91C_BASE_PWMC->PWMC_IDR;  // disable interrupt
}


// -- Public Functions ------------------------------------------------------------------------- //

/**
 *  @brief          CLK interrupt handler
 *
 *  @description    Implements a bit banged CLK signal to the smart card.  Also outputs data on the I/O line on rising
 *  				CLK edges when transmiting and samples the I/O line on falling CLK edges when receiving
 *  @param          void
 *  @return         void
 */
void SMART_CARD_ClockInterruptHandler( void ) {
	static uint8_t clkCount;
	static uint8_t previousSampleRxClkCount;
	static uint8_t previousSampleTxClkCount;
	static uint16_t sampledRxData;								// The bits of the Rx byte are accumulated here
	static uint8_t sampleBitIndex;								// Used during both Tx and Rx as the comms are half duplex
	static uint8_t transmitByte;
	bool sampleBit = SMART_CARD_IO_STATE;						// Read the state of the I/O signal in case we are going to use it

	// Clear the interrupt
	// TODO: This functions implementation is not yet complete... just need to handle the interrupt

	// Check if we are meant to be generating the CLK signal
	if ( generateClk )
	{
		// On the even clock counts we will toggle the CLK signal
		if ( clkCount++ % 2 )
		{
			// Read the current state of the CLK signal, if it is High then set it Low and if it is Low set it High
			if ( SMART_CARD_CLK_STATE )
			{
				// Generate a falling edge
				SMART_CARD_CLK_LO;

				// ******************************************************************* //
				// On the falling edge of the CLK signal we sample from the I/O signal //
				// ******************************************************************* //

				// See if we are receiving
				if ( receptionMode )
				{
					// See if we are already looking for the start of a new byte OR
					// It has been a while since we last captured a byte (this provides resynchronising)
					if ( ( sampleBitIndex == 0 ) || ( RANGE( clkCount, previousSampleRxClkCount, 5 ) ) )
					{
						sampleBitIndex = 0;
						previousSampleRxClkCount = clkCount;

						// The start bit must be low
						if ( sampleBit == 0 )
						{
							// Set the bit index to indicate that we've detected a start bit
							sampleBitIndex = 1;

							// Initialise the sample data byte where the received bits will be put
							sampledRxData = 0;
						}
					}
					// Otherwise see if we are in the process of collecting bits of a sample byte
					else if ( ( sampleBitIndex ) && ( sampleBitIndex <= 10 ) )
					{
						// Shift the bits of the sampled byte up by 1 to make room for this new bit
						sampledRxData = sampledRxData << 1;

						// Or in the new sample bit
						sampledRxData |= sampleBit << sampleBitIndex;

						// Check if we've received the start bit, 8 bits of the byte and the parity bit
						if ( sampleBitIndex == 10 )
						{
							// Transfer the sampled data into the receive buffer so that it can be processed
							if ( !SMART_CARD_PutRecievedByte( sampledRxData ) )
							{
								// An error has occured as there was no space to save this byte!
							}
						}

						// Increment index and wait for next bit
						sampleBitIndex++;

						// Update the Rx CLK count so we know how long to wait
						previousSampleRxClkCount = clkCount;
					}
				}
			}
			// CLK is Low so set it High
			else
			{
				// Generate a rising edge
				SMART_CARD_CLK_HI;

				// ***************************************************************************************** //
				// On the rising edge of the CLK signal we output the next bit of the byte to the I/O signal //
				// ***************************************************************************************** //

				// See if we are transmitting
				if ( transmitMode )
				{
					// See if we are already looking for new byte to transmit OR
					// It has been a while since we last sent a byte (this allows for the "pause" time)
					if ( ( sampleBitIndex == 0 ) || ( RANGE( clkCount, previousSampleTxClkCount, 7 ) ) )
					{
						sampleBitIndex = 0;
						previousSampleTxClkCount = clkCount;

						// See if there is a byte to transmit
						if ( SMART_CARD_GetTransmitByte( &transmitByte ) )
						{
							// The start bit must be low
							SMART_CARD_IO_LO;

							// Set the bit index to indicate that we've started transmitting
							sampleBitIndex = 1;
						}
					}
					// We are in the process of collecting bits of a sample byte
					else if ( ( sampleBitIndex ) && ( sampleBitIndex <= 11 ) )
					{
						// Check if we've output the start bit and the 8 bits of the byte and the parity bit
						if ( sampleBitIndex == 11 )
						{
							// There is nothing left to output, set the I/O signal high during the "pause" time
							SMART_CARD_IO_HI;
						}
						// Check if we've output the start bit and the 8 bits of the byte
						else if ( sampleBitIndex == 10 )
						{
							// Calculate the parity bit and output it appropriately
							if ( SMART_CARD_CalculateByteParity( transmitByte ) )
							{
								SMART_CARD_IO_HI;
							}
							else
							{
								SMART_CARD_IO_LO;
							}
						}
						// Otherwise we are still outputting the bits of the byte
						else
						{
							// Set the state of the I/O signal according to the bits of the transmit byte
							if ( transmitByte & ( 1 << ( sampleBitIndex - 1 ) ) )
							{
								SMART_CARD_IO_HI;
							}
							else
							{
								SMART_CARD_IO_LO;
							}
						}

						// Increment index for when the next bit is output
						sampleBitIndex++;
					}
				}
			}
		}
	}
}


/**
 *  @brief          Service the smart card interface
 *  @description    Check if a transaction needs to occur
 *  @param          void
 *  @return         bool                    true  = The smart card was service successfully
 *                                          false = An error occurred
 */
void SMART_CARD_ServiceSmartCard( void ) {
	
	if ( !communicationsEstablished ) {
		// Attempt to establish communications if they are not currently working
		communicationsEstablished = SMART_CARD_EstablishCommunications();
	} else {		
		// Communications are working, processs any commands/responses
		
		// If a fatal error occurs we will need to re-establish communications
		communicationsEstablished = SMART_CARD_MaintainConnection();
	}
}

void SmartCard_setup(void) {
	// Enable the pins to be controlled
	AT91C_BASE_PIOA->PIO_PER = SMART_CARD_RST_PIN | SMART_CARD_CLK_PIN | SMART_CARD_IO_PIN;

	// Configure the pins to be outputs
	AT91C_BASE_PIOA->PIO_OER = SMART_CARD_RST_PIN | SMART_CARD_CLK_PIN | SMART_CARD_IO_PIN;

	// Configure the IO pin for multi-drive mode (is this right?)
	AT91C_BASE_PIOA->PIO_MDER = SMART_CARD_IO_PIN;
	AT91C_BASE_PIOA->PIO_PPUER = SMART_CARD_IO_PIN;

	// Configure a timer to generate an interrupt for the clock signal and sampling of the I/O line
	SMART_CARD_ConfigureClock();
}

void SmartCard_stop(void) {
	//StopTicks();
	if ( MF_DBGLEVEL > 3 )  Dbprintf("Smart Card Stop");
	LED_A_OFF();
}

bool SmartCard_init(void) {

	//StartTicks();
	
	//LED_A_ON();
	SmartCard_setup();
	
	if ( MF_DBGLEVEL > 3 ) Dbprintf("Smart Card Init OK");
	return true;
}

void SmartCard_print_status(void) {
	DbpString("Smart card module (ISO 7816)");

	if (!SmartCard_init()) {
		DbpString("  init....................FAIL");
		return;
	}
	DbpString("  init....................OK");
		
	SmartCard_stop();	
}