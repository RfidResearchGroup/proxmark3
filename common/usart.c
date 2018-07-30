#include "usart.h"
#include "apps.h"

#define USART_INTERRUPT_LEVEL		7
#define AT91_BAUD_RATE				115200

volatile AT91PS_PDC pPDC 	= AT91C_BASE_PDC_US1;
volatile AT91PS_USART pUS1	= AT91C_BASE_US1;
volatile AT91PS_AIC pAIC 	= AT91C_BASE_AIC;
volatile AT91PS_PIO pPIOA	= AT91C_BASE_PIOA;

#define usart_rx_ready {(pUS1->US_CSR & AT91C_US_RXRDY)}
#define usart_tx_ready {(pUS1->US_CSR & AT91C_US_TXRDY)}

void usart_close(void) {
    // Reset the USART mode
	pUS1->US_MR = 0;

    // Reset the baud rate divisor register
	pUS1->US_BRGR = 0;
	
    // Reset the Timeguard Register
    pUS1->US_TTGR = 0;

    // Disable all interrupts
    pUS1->US_IDR = 0xFFFFFFFF;

    //* Abort the Peripheral Data Transfers
    //AT91F_PDC_Close((AT91PS_PDC) &(pUSART->US_RPR));

    // Disable receiver and transmitter and stop any activity immediately
    pUS1->US_CR = AT91C_US_TXDIS | AT91C_US_RXDIS | AT91C_US_RSTTX | AT91C_US_RSTRX;
}

/// Reads data from an USART peripheral, filling the provided buffer until it
/// becomes full. This function returns immediately with 1 if the buffer has
/// been queued for transmission; otherwise 0.
/// \param data  Pointer to the buffer where the received data will be stored.
/// \param len  Size of the data buffer (in bytes).
uint8_t usart_readbuffer(uint8_t *data, size_t len) {
	
	// Check if the first PDC bank is free
    if ((pUS1->US_RCR == 0) && (pUS1->US_RNCR == 0)) {

        pUS1->US_RPR = (uint32_t)data;
        pUS1->US_RCR = len;
        pUS1->US_PTCR = AT91C_PDC_RXTEN;
        return 1;
    }
    // Check if the second PDC bank is free
    else if (pUS1->US_RNCR == 0) {

        pUS1->US_RNPR = (uint32_t)data;
        pUS1->US_RNCR = len;
        return 1;
    } else {
        return 0;
    }
}

/// Reads and return a packet of data on the specified USART peripheral. This
/// function operates asynchronously, so it waits until some data has been
/// received.
/// \param timeout  Time out value (0 -> no timeout).
uint8_t usart_read(uint32_t timeout) {
    if (timeout == 0) {
        while ((pUS1->US_CSR & AT91C_US_RXRDY) == 0) {};
    }
    else {

        while ((pUS1->US_CSR & AT91C_US_RXRDY) == 0) {

            if (timeout == 0) {

                DbpString("USART_Read: Timed out.");
                return 0;
            }
            timeout--;
        }
    }
	uint8_t res = pUS1->US_RHR;
	Dbprintf("  usar got %02x", res);
    return res;
}

/// Sends one packet of data through the specified USART peripheral. This
/// function operates synchronously, so it only returns when the data has been
/// actually sent.
/// \param data  Data to send including 9nth bit and sync field if necessary (in
///              the same format as the US_THR register in the datasheet).
/// \param timeOut  Time out value (0 = no timeout).
void usart_write( uint8_t data, uint32_t timeout) {
	if ( timeout == 0) {

		while ((pUS1->US_CSR & AT91C_US_TXEMPTY) == 0) {};
		
    } else {
		while ((pUS1->US_CSR & AT91C_US_TXEMPTY) == 0) {

			if (timeout == 0) {
				DbpString("USART_Write: Timed out.");
				return;
			}
			timeout--;
		}
	}
	pUS1->US_THR = data;
}

uint8_t usart_writebuffer(uint8_t *data, size_t len, uint32_t timeout) {

    // Check if the first PDC bank is free
    if ((pUS1->US_TCR == 0) && (pUS1->US_TNCR == 0)) {

        pUS1->US_TPR = (uint32_t)data;
        pUS1->US_TCR = len;
        pUS1->US_PTCR = AT91C_PDC_TXTEN;
        return 1;
    }
    // Check if the second PDC bank is free
    else if (pUS1->US_TNCR == 0) {

        pUS1->US_TNPR = (uint32_t)data;
        pUS1->US_TNCR = len;
        return 1;
    }
    else {
        return 0;
    }
}

// interupt version
void Usart_c_irq_handler(void) {
	
	// get Usart status register
	uint32_t status = pUS1->US_CSR;
	
	if ( status & AT91C_US_RXRDY){
		// Get byte and send
		pUS1->US_THR = (pUS1->US_RHR & 0x1FF);
		LED_B_INV();
	}
		// tx
	if ( status & AT91C_US_TXRDY){
		LED_D_INV();
	}


	if ( status & AT91C_US_OVRE) {
		// clear US_RXRDY
		(void)(pUS1->US_RHR & 0x1FF);
		pUS1->US_THR = ('O' & 0x1FF);
	}

	// Check error
	if ( status & AT91C_US_PARE) {
		 pUS1->US_THR = ('P' & 0x1FF);
	}

	if ( status & AT91C_US_FRAME) {
 		 pUS1->US_THR = ('F' & 0x1FF);
	}

	if ( status & AT91C_US_TIMEOUT){
		pUS1->US_CR = AT91C_US_STTTO;
		pUS1->US_THR = ('T' & 0x1FF);
	}
	
	// Reset the status bit
	pUS1->US_CR = AT91C_US_RSTSTA;
}

__inline unsigned int AT91F_AIC_ConfigureIt (
	AT91PS_AIC pAIC,  // \arg pointer to the AIC registers
	unsigned int irq_id,     // \arg interrupt number to initialize
	unsigned int priority,   // \arg priority to give to the interrupt
	unsigned int src_type,   // \arg activation and sense of activation
	void (*newHandler) (void) ) // \arg address of the interrupt handler
{
	unsigned int oldHandler;
    unsigned int mask;

    oldHandler = pAIC->AIC_SVR[irq_id];

    mask = (0x1 << irq_id);
    // Disable the interrupt on the interrupt controller
    pAIC->AIC_IDCR = mask;
    // Save the interrupt handler routine pointer and the interrupt priority
    pAIC->AIC_SVR[irq_id] = (unsigned int) newHandler;
    // Store the Source Mode Register
    pAIC->AIC_SMR[irq_id] = (src_type | priority);
    // Clear the interrupt on the interrupt controller
    pAIC->AIC_ICCR = mask;

	return oldHandler;
}

void usart_init(void) {
	
	// disable & reset  receiver / transmitter
	pUS1->US_CR = AT91C_US_RSTRX | AT91C_US_RSTTX | AT91C_US_RXDIS | AT91C_US_TXDIS;
		
	//enable the USART 1 Peripheral clock
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_US1);
	
	// Configure PIO controllers to peripheral mode A
	pPIOA->PIO_ASR = (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);
	
	// Disable PIO control of the following pins, allows use by the SPI peripheral
	pPIOA->PIO_PDR = (AT91C_PA21_RXD1 | AT91C_PA22_TXD1); 

	// kill pull-ups
//	pPIOA->PIO_PPUDR = ~(AT91C_PA21_RXD1 | AT91C_PA22_TXD1); 
//	pPIOA->PIO_MDDR  = (AT91C_PA21_RXD1 | AT91C_PA22_TXD1); 
	
	//	Pull-up Enable
	pPIOA->PIO_PPUER |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);
	// MultiDriver Enable
	//pPIOA->PIO_MDER |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);
	
	// Enable the pins to be controlled
	pPIOA->PIO_PER |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);

	// Configure the pins to be outputs
	pPIOA->PIO_OER |= (AT91C_PA21_RXD1 | AT91C_PA22_TXD1);

	//enable PIO in input mode
	//pPIOA->PIO_ODR  = AT91C_PA21_RXD1;
	
    // set mode
    pUS1->US_MR = AT91C_US_USMODE_NORMAL |      // normal mode
               AT91C_US_CLKS_CLOCK |            // MCK
               AT91C_US_CHRL_8_BITS |           // 8 bits
               AT91C_US_PAR_NONE |              // parity: none
               AT91C_US_NBSTOP_1_BIT |          // 1 stop bit
               AT91C_US_CHMODE_NORMAL;          // channel mode: normal

    // baud rate
    // CD = MCK / (16 * baud)
    // MCK = 24027428  (pm3 runs on 24MHZ clock PMC_PCKR[0] ) 

	
    // baudrate 115200
	//  16*115200 = 1843200
	//   24027428 / 1843200 ==   13  --< CD

	// baudrate 460800
	// 16*460800 = 7372800	
	// 24027428 /  7372800 == 3	
	pUS1->US_BRGR = 24*1024*1024/(115200*16);	// OVER=0 16
	
	// Write the Timeguard Register
	pUS1->US_TTGR = 0;

	pUS1->US_RTOR = 0;
	pUS1->US_FIDI = 0;
	pUS1->US_IF = 0;

    // Enable USART IT error and RXRDY
	// Write to the IER register
//	pUS1->US_IER = (AT91C_US_TIMEOUT | AT91C_US_FRAME | AT91C_US_OVRE | AT91C_US_RXRDY);
	
    // open Usart 1 interrupt
/*
	AT91F_AIC_ConfigureIt(
		pAIC,
		AT91C_ID_US1,
		USART_INTERRUPT_LEVEL,
		AT91C_AIC_SRCTYPE_INT_HIGH_LEVEL,
		Usart_c_irq_handler
	);
*/
	
	// enable interupt
//	pAIC->AIC_IECR = (1 << AT91C_ID_US1);
	
	// trigger interrup software
//	pAIC->AIC_ISCR = (1 << AT91C_ID_US1) ;

    // enable RX + TX
	pUS1->US_CR = AT91C_US_RXEN | AT91C_US_TXEN;

}