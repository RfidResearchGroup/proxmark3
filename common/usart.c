//-----------------------------------------------------------------------------
// Iceman, July 2018
// edists by - Anticat, August 2018
// 
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// The main USART code, for serial communications over FPC connector
//-----------------------------------------------------------------------------
#include "usart.h"
#include "string.h"

#define AT91_BAUD_RATE				115200

volatile AT91PS_USART pUS1	= AT91C_BASE_US1;
volatile AT91PS_PIO pPIOA	= AT91C_BASE_PIOA;
volatile AT91PS_PDC pPDC 	= AT91C_BASE_PDC_US1;

/*
void usart_close(void) {
    // Reset the USART mode
	pUS1->US_MR = 0;

    // Reset the baud rate divisor register
	pUS1->US_BRGR = 0;
	
    // Reset the Timeguard Register
    pUS1->US_TTGR = 0;

    // Disable all interrupts
    pUS1->US_IDR = 0xFFFFFFFF;

    // Abort the Peripheral Data Transfers
	pUS1->US_PTCR = AT91C_PDC_RXTDIS | AT91C_PDC_TXTDIS;

    // Disable receiver and transmitter and stop any activity immediately
    pUS1->US_CR = AT91C_US_TXDIS | AT91C_US_RXDIS | AT91C_US_RSTTX | AT91C_US_RSTRX;
}
*/

static uint8_t outbuf[sizeof(UsbCommand)];
//static uint8_t inbuf[sizeof(UsbCommand)];


/// Reads data from an USART peripheral
/// \param data  Pointer to the buffer where the received data will be stored.
/// \param len  Size of the data buffer (in bytes).
inline int usart_readbuffer(uint8_t *data, size_t len) {

	pUS1->US_PTSR = AT91C_PDC_TXTEN;	
	pUS1->US_PTCR = AT91C_PDC_TXTEN;
	
	// Check if the first PDC bank is free
    if (!(pUS1->US_RCR)) {
        pUS1->US_RPR = (uint32_t)data;
        pUS1->US_RCR = len;
        return 2;
    }
    // Check if the second PDC bank is free
    else if (!(pUS1->US_RNCR)) {
        pUS1->US_RNPR = (uint32_t)data;
        pUS1->US_RNCR = len;
        return 1;
    } else {
        return 0;
    }
	
	/*
	pPDC->PDC_PTSR = AT91C_PDC_RXTEN;	
	pPDC->PDC_PTCR = AT91C_PDC_RXTEN;
	
	//check if data is available
	if (pPDC->PDC_RCR != 0) return -1;

	memcpy(data, inbuf, len);

	//start next transfer
	pPDC->PDC_RNPR = (uint32_t)inbuf;
	pPDC->PDC_RNCR = sizeof(inbuf);

	return sizeof(inbuf);
	*/
}
/*
int16_t usart_writebuffer(uint8_t *data, size_t len) {

//	pUS1->US_PTSR = AT91C_PDC_TXTEN;
	pUS1->US_PTCR = AT91C_PDC_TXTEN;
	
	// if buffer is sent
	if (pUS1->US_TCR != 0) return -1;
	
	memcpy(outbuf, data, len);

	//start next transfer
	pUS1->US_TNPR = (uint32_t)outbuf;
	pUS1->US_TNCR = sizeof(outbuf);

	return sizeof(outbuf);
}
*/

// works.
// transfer to client
inline int16_t usart_writebuffer(uint8_t *data, size_t len) {

	pUS1->US_PTSR = AT91C_PDC_TXTEN;
	pUS1->US_PTCR = AT91C_PDC_TXTEN;
	
    // Check if the first PDC bank is free
    if (!(pUS1->US_TCR)) {
		
		memcpy(outbuf, data, len);
        
		pUS1->US_TPR = (uint32_t)outbuf;
        pUS1->US_TCR = sizeof(outbuf);
		return 2;
    }
    // Check if the second PDC bank is free
    else if (!(pUS1->US_TNCR)) {
		memcpy(outbuf, data, len);
		
        pUS1->US_TNPR = (uint32_t)outbuf;
        pUS1->US_TNCR = sizeof(outbuf);
		return 1;
    } else {
        return 0;
    }
}

void usart_init(void) {

	// disable & reset receiver / transmitter for configuration
	pUS1->US_CR = (AT91C_US_RSTRX | AT91C_US_RSTTX);
	
	//enable the USART1 Peripheral clock
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_US1);

	// disable PIO control of receive / transmit pins
	pPIOA->PIO_PDR |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1); 
	
	// enable peripheral mode A on receive / transmit pins
	pPIOA->PIO_ASR |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);

	// enable pull-up on receive / transmit pins (see 31.5.1 I/O Lines)
	pPIOA->PIO_PPUER |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);
	
    // set mode
    pUS1->US_MR = AT91C_US_USMODE_NORMAL |      // normal mode
               AT91C_US_CLKS_CLOCK |            // MCK (48MHz)
               AT91C_US_CHRL_8_BITS |           // 8 bits
               AT91C_US_PAR_NONE |              // parity: none
               AT91C_US_NBSTOP_1_BIT |          // 1 stop bit
               AT91C_US_CHMODE_NORMAL;          // channel mode: normal

	// set baudrate to 115200 
	pUS1->US_BRGR = (48UL*1000*1000) / (115200*16);
	
	// Write the Timeguard Register
	pUS1->US_TTGR = 0;
	pUS1->US_RTOR = 0;
	pUS1->US_FIDI = 0;
	pUS1->US_IF = 0;
	
	/*
	//Empty PDC
	pUS1->US_RNPR = (uint32_t)(char *)0;
	pUS1->US_RNCR = 0;
	pUS1->US_RPR = (uint32_t)(char *)0;
	pUS1->US_RCR = 0;

	pUS1->US_TNPR = (uint32_t)(char *)0;
	pUS1->US_TNCR = 0;	
	pUS1->US_TPR = (uint32_t)(char *)0;
	pUS1->US_TCR = 0;
	*/
	
	//pUS1->US_PTCR = (AT91C_PDC_RXTEN | AT91C_PDC_TXTEN);
	//pUS1->US_PTSR = (AT91C_PDC_RXTEN | AT91C_PDC_TXTEN);
	
	// re-enable receiver / transmitter
	pUS1->US_CR = (AT91C_US_RXEN | AT91C_US_TXEN);
	
}