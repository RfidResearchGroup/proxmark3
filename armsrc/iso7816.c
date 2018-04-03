#include "iso7816.h"

/* here: use NCPS2 @ PA10: */
#define SPI_CSR_NUM      2          		// Chip Select register[] 0,1,2,3  (at91samv512 has 4)

/* PCS_0 for NPCS0, PCS_1 for NPCS1 ... */
#define PCS_0  ((0<<0)|(1<<1)|(1<<2)|(1<<3)) // 0xE - 1110
#define PCS_1  ((1<<0)|(0<<1)|(1<<2)|(1<<3)) // 0xD - 1101
#define PCS_2  ((1<<0)|(1<<1)|(0<<2)|(1<<3)) // 0xB - 1011
#define PCS_3  ((1<<0)|(1<<1)|(1<<2)|(0<<3)) // 0x7 - 0111

// TODO
#if (SPI_CSR_NUM == 0)
#define SPI_MR_PCS       PCS_0
#elif (SPI_CSR_NUM == 1)
#define SPI_MR_PCS       PCS_1
#elif (SPI_CSR_NUM == 2)
#define SPI_MR_PCS       PCS_2
#elif (SPI_CSR_NUM == 3)
#define SPI_MR_PCS       PCS_3
#else
#error "SPI_CSR_NUM invalid"
// not realy - when using an external address decoder...
// but this code takes over the complete SPI-interace anyway
#endif


void ISO7816_setup(void) {
	// PA1 -> SIM RST
	// PA5 -> SIM I/O
	// PA7 -> SIM CLK	

	// Disable PIO control of the following pins, allows use by the SPI peripheral
	AT91C_BASE_PIOA->PIO_PDR = GPIO_NCS0 | GPIO_MISO | GPIO_MOSI | GPIO_SPCK | GPIO_NCS2;

	//	Pull-up Enable
	AT91C_BASE_PIOA->PIO_PPUER = GPIO_NCS0 | GPIO_MISO | GPIO_MOSI | GPIO_SPCK | GPIO_NCS2;

	// Peripheral A
	AT91C_BASE_PIOA->PIO_ASR = GPIO_NCS0 | GPIO_MISO | GPIO_MOSI | GPIO_SPCK;

	// Peripheral B
	AT91C_BASE_PIOA->PIO_BSR |= GPIO_NCS2;

	//enable the SPI Peripheral clock
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_SPI);

	// Enable SPI
	AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIEN;

	//	NPCS2 Mode 0
	AT91C_BASE_SPI->SPI_MR =
		( 0 << 24)	|		// Delay between chip selects (take default: 6 MCK periods)
		(0xB << 16)	|		// Peripheral Chip Select (selects SPI_NCS2 or PA10)
		( 0 << 7)	|		// Local Loopback Disabled
		( 1 << 4)	|		// Mode Fault Detection disabled
		( 0 << 2)	|		// Chip selects connected directly to peripheral
		( 0 << 1) 	|		// Fixed Peripheral Select
		( 1 << 0);			// Master Mode

	//	8 bit
	AT91C_BASE_SPI->SPI_CSR[2] =
		( 0 << 24)	|		// Delay between Consecutive Transfers (32 MCK periods)
		( 0 << 16)	|		// Delay Before SPCK (1 MCK period)
		( 6 << 8)	|		// Serial Clock Baud Rate (baudrate = MCK/6 = 24Mhz/6 = 4M baud
		( 0 << 4)	|		// Bits per Transfer (8 bits)
		( 1 << 3)	|		// Chip Select inactive after transfer
		( 1 << 1)	|		// Clock Phase data captured on leading edge, changes on following edge
		( 0 << 0);			// Clock Polarity inactive state is logic 0

	//	read first, empty buffer
	if (AT91C_BASE_SPI->SPI_RDR == 0) {};
}

void ISO7816_stop(void) {
	//* Reset all the Chip Select register
    AT91C_BASE_SPI->SPI_CSR[0] = 0;
    AT91C_BASE_SPI->SPI_CSR[1] = 0;
    AT91C_BASE_SPI->SPI_CSR[2] = 0;
    AT91C_BASE_SPI->SPI_CSR[3] = 0;

    // Reset the SPI mode
    AT91C_BASE_SPI->SPI_MR = 0;

    // Disable all interrupts
    AT91C_BASE_SPI->SPI_IDR = 0xFFFFFFFF;
	
	// SPI disable
	AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIDIS;

	if ( MF_DBGLEVEL > 3 ) Dbprintf("ISO7816 Stop");
	
	StopTicks();
}

//	send one byte over SPI
uint16_t ISO7816_sendbyte(uint32_t data) {	
	uint16_t incoming = 0;

	WDT_HIT();

	// wait until SPI is ready for transfer
	while ((AT91C_BASE_SPI->SPI_SR & AT91C_SPI_TXEMPTY) == 0) {};

	// send the data
	AT91C_BASE_SPI->SPI_TDR = data;

	// wait recive transfer is complete
	while ((AT91C_BASE_SPI->SPI_SR & AT91C_SPI_RDRF) == 0)
		WDT_HIT();

	// reading incoming data
	incoming = ((AT91C_BASE_SPI->SPI_RDR) & 0xFFFF);

	return incoming;
}

//	initialize
bool ISO7816_init(void) {
	ISO7816_setup();

	StartTicks();
	
	//	StopTicks();
//		return false;
	
	if ( MF_DBGLEVEL > 3 ) Dbprintf("ISO7816 OK");
	return true;
}

void ISO7816_test(void) {

	if (!ISO7816_init()) return;
	
	ISO7816_stop();
}

void Iso7816_print_status(void) {
	DbpString("Contact module (iso7816)");

	if (!ISO7816_init()) {
		DbpString("  init....................FAIL");
		return;
	}
	DbpString("  init....................OK");
		
	ISO7816_stop();	
}