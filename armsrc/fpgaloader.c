//-----------------------------------------------------------------------------
// Jonathan Westhues, April 2006
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to load the FPGA image, and then to configure the FPGA's major
// mode once it is configured.
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"

//-----------------------------------------------------------------------------
// Set up the Serial Peripheral Interface as master
// Used to write the FPGA config word
// May also be used to write to other SPI attached devices like an LCD
//-----------------------------------------------------------------------------
void SetupSpi(int mode)
{
	// PA10 -> SPI_NCS2 chip select (LCD)
	// PA11 -> SPI_NCS0 chip select (FPGA)
	// PA12 -> SPI_MISO Master-In Slave-Out
	// PA13 -> SPI_MOSI Master-Out Slave-In
	// PA14 -> SPI_SPCK Serial Clock

	// Disable PIO control of the following pins, allows use by the SPI peripheral
	AT91C_BASE_PIOA->PIO_PDR =
		GPIO_NCS0	|
		GPIO_NCS2 	|
		GPIO_MISO	|
		GPIO_MOSI	|
		GPIO_SPCK;

	AT91C_BASE_PIOA->PIO_ASR =
		GPIO_NCS0	|
		GPIO_MISO	|
		GPIO_MOSI	|
		GPIO_SPCK;

	AT91C_BASE_PIOA->PIO_BSR = GPIO_NCS2;

	//enable the SPI Peripheral clock
	AT91C_BASE_PMC->PMC_PCER = (1<<AT91C_ID_SPI);
	// Enable SPI
	AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIEN;

	switch (mode) {
		case SPI_FPGA_MODE:
			AT91C_BASE_SPI->SPI_MR =
				( 0 << 24)	|	// Delay between chip selects (take default: 6 MCK periods)
				(14 << 16)	|	// Peripheral Chip Select (selects FPGA SPI_NCS0 or PA11)
				( 0 << 7)	|	// Local Loopback Disabled
				( 1 << 4)	|	// Mode Fault Detection disabled
				( 0 << 2)	|	// Chip selects connected directly to peripheral
				( 0 << 1) 	|	// Fixed Peripheral Select
				( 1 << 0);		// Master Mode
			AT91C_BASE_SPI->SPI_CSR[0] =
				( 1 << 24)	|	// Delay between Consecutive Transfers (32 MCK periods)
				( 1 << 16)	|	// Delay Before SPCK (1 MCK period)
				( 6 << 8)	|	// Serial Clock Baud Rate (baudrate = MCK/6 = 24Mhz/6 = 4M baud
				( 8 << 4)	|	// Bits per Transfer (16 bits)
				( 0 << 3)	|	// Chip Select inactive after transfer
				( 1 << 1)	|	// Clock Phase data captured on leading edge, changes on following edge
				( 0 << 0);		// Clock Polarity inactive state is logic 0
			break;
		case SPI_LCD_MODE:
			AT91C_BASE_SPI->SPI_MR =
				( 0 << 24)	|	// Delay between chip selects (take default: 6 MCK periods)
				(11 << 16)	|	// Peripheral Chip Select (selects LCD SPI_NCS2 or PA10)
				( 0 << 7)	|	// Local Loopback Disabled
				( 1 << 4)	|	// Mode Fault Detection disabled
				( 0 << 2)	|	// Chip selects connected directly to peripheral
				( 0 << 1) 	|	// Fixed Peripheral Select
				( 1 << 0);		// Master Mode
			AT91C_BASE_SPI->SPI_CSR[2] =
				( 1 << 24)	|	// Delay between Consecutive Transfers (32 MCK periods)
				( 1 << 16)	|	// Delay Before SPCK (1 MCK period)
				( 6 << 8)	|	// Serial Clock Baud Rate (baudrate = MCK/6 = 24Mhz/6 = 4M baud
				( 1 << 4)	|	// Bits per Transfer (9 bits)
				( 0 << 3)	|	// Chip Select inactive after transfer
				( 1 << 1)	|	// Clock Phase data captured on leading edge, changes on following edge
				( 0 << 0);		// Clock Polarity inactive state is logic 0
			break;
		default:				// Disable SPI
			AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIDIS;
			break;
	}
}

//-----------------------------------------------------------------------------
// Set up the synchronous serial port, with the one set of options that we
// always use when we are talking to the FPGA. Both RX and TX are enabled.
//-----------------------------------------------------------------------------
void FpgaSetupSsc(void)
{
	// First configure the GPIOs, and get ourselves a clock.
	AT91C_BASE_PIOA->PIO_ASR =
		GPIO_SSC_FRAME	|
		GPIO_SSC_DIN	|
		GPIO_SSC_DOUT	|
		GPIO_SSC_CLK;
	AT91C_BASE_PIOA->PIO_PDR = GPIO_SSC_DOUT;

	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_SSC);

	// Now set up the SSC proper, starting from a known state.
	AT91C_BASE_SSC->SSC_CR = AT91C_SSC_SWRST;

	// RX clock comes from TX clock, RX starts when TX starts, data changes
	// on RX clock rising edge, sampled on falling edge
	AT91C_BASE_SSC->SSC_RCMR = SSC_CLOCK_MODE_SELECT(1) | SSC_CLOCK_MODE_START(1);

	// 8 bits per transfer, no loopback, MSB first, 1 transfer per sync
	// pulse, no output sync, start on positive-going edge of sync
	AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) |
		AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);

	// clock comes from TK pin, no clock output, outputs change on falling
	// edge of TK, start on rising edge of TF
	AT91C_BASE_SSC->SSC_TCMR = SSC_CLOCK_MODE_SELECT(2) |
		SSC_CLOCK_MODE_START(5);

	// tx framing is the same as the rx framing
	AT91C_BASE_SSC->SSC_TFMR = AT91C_BASE_SSC->SSC_RFMR;

	AT91C_BASE_SSC->SSC_CR = AT91C_SSC_RXEN | AT91C_SSC_TXEN;
}

//-----------------------------------------------------------------------------
// Set up DMA to receive samples from the FPGA. We will use the PDC, with
// a single buffer as a circular buffer (so that we just chain back to
// ourselves, not to another buffer). The stuff to manipulate those buffers
// is in apps.h, because it should be inlined, for speed.
//-----------------------------------------------------------------------------
bool FpgaSetupSscDma(uint8_t *buf, int len)
{
	if (buf == NULL) {
        return false;
    }

	AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;
	AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) buf;
	AT91C_BASE_PDC_SSC->PDC_RCR = len;
	AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) buf;
	AT91C_BASE_PDC_SSC->PDC_RNCR = len;
	AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTEN;
    
    return true;
}

static void DownloadFPGA_byte(unsigned char w)
{
#define SEND_BIT(x) { if(w & (1<<x) ) HIGH(GPIO_FPGA_DIN); else LOW(GPIO_FPGA_DIN); HIGH(GPIO_FPGA_CCLK); LOW(GPIO_FPGA_CCLK); }
	SEND_BIT(7);
	SEND_BIT(6);
	SEND_BIT(5);
	SEND_BIT(4);
	SEND_BIT(3);
	SEND_BIT(2);
	SEND_BIT(1);
	SEND_BIT(0);
}

// Download the fpga image starting at FpgaImage and with length FpgaImageLen bytes
// If bytereversal is set: reverse the byte order in each 4-byte word
static void DownloadFPGA(const char *FpgaImage, int FpgaImageLen, int bytereversal)
{
	int i=0;

	AT91C_BASE_PIOA->PIO_OER = GPIO_FPGA_ON;
	AT91C_BASE_PIOA->PIO_PER = GPIO_FPGA_ON;
	HIGH(GPIO_FPGA_ON);		// ensure everything is powered on

	SpinDelay(50);

	LED_D_ON();

	// These pins are inputs
    AT91C_BASE_PIOA->PIO_ODR =
    	GPIO_FPGA_NINIT |
    	GPIO_FPGA_DONE;
	// PIO controls the following pins
    AT91C_BASE_PIOA->PIO_PER =
    	GPIO_FPGA_NINIT |
    	GPIO_FPGA_DONE;
	// Enable pull-ups
	AT91C_BASE_PIOA->PIO_PPUER =
		GPIO_FPGA_NINIT |
		GPIO_FPGA_DONE;

	// setup initial logic state
	HIGH(GPIO_FPGA_NPROGRAM);
	LOW(GPIO_FPGA_CCLK);
	LOW(GPIO_FPGA_DIN);
	// These pins are outputs
	AT91C_BASE_PIOA->PIO_OER =
		GPIO_FPGA_NPROGRAM	|
		GPIO_FPGA_CCLK		|
		GPIO_FPGA_DIN;

	// enter FPGA configuration mode
	LOW(GPIO_FPGA_NPROGRAM);
	SpinDelay(50);
	HIGH(GPIO_FPGA_NPROGRAM);

	i=100000;
	// wait for FPGA ready to accept data signal
	while ((i) && ( !(AT91C_BASE_PIOA->PIO_PDSR & GPIO_FPGA_NINIT ) ) ) {
		i--;
	}

	// crude error indicator, leave both red LEDs on and return
	if (i==0){
		LED_C_ON();
		LED_D_ON();
		return;
	}

	if(bytereversal) {
		/* This is only supported for uint32_t aligned images */
		if( ((int)FpgaImage % sizeof(uint32_t)) == 0 ) {
			i=0;
			while(FpgaImageLen-->0)
				DownloadFPGA_byte(FpgaImage[(i++)^0x3]);
			/* Explanation of the magic in the above line:
			 * i^0x3 inverts the lower two bits of the integer i, counting backwards
			 * for each 4 byte increment. The generated sequence of (i++)^3 is
			 * 3 2 1 0 7 6 5 4 11 10 9 8 15 14 13 12 etc. pp.
			 */
		}
	} else {
		while(FpgaImageLen-->0)
			DownloadFPGA_byte(*FpgaImage++);
	}

	// continue to clock FPGA until ready signal goes high
	i=100000;
	while ( (i--) && ( !(AT91C_BASE_PIOA->PIO_PDSR & GPIO_FPGA_DONE ) ) ) {
		HIGH(GPIO_FPGA_CCLK);
		LOW(GPIO_FPGA_CCLK);
	}
	// crude error indicator, leave both red LEDs on and return
	if (i==0){
		LED_C_ON();
		LED_D_ON();
		return;
	}
	LED_D_OFF();
}

static char *bitparse_headers_start;
static char *bitparse_bitstream_end;
static int bitparse_initialized;
/* Simple Xilinx .bit parser. The file starts with the fixed opaque byte sequence
 * 00 09 0f f0 0f f0 0f f0 0f f0 00 00 01
 * After that the format is 1 byte section type (ASCII character), 2 byte length
 * (big endian), <length> bytes content. Except for section 'e' which has 4 bytes
 * length.
 */
static const char _bitparse_fixed_header[] = {0x00, 0x09, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x0f, 0xf0, 0x00, 0x00, 0x01};
static int bitparse_init(void * start_address, void *end_address)
{
	bitparse_initialized = 0;

	if(memcmp(_bitparse_fixed_header, start_address, sizeof(_bitparse_fixed_header)) != 0) {
		return 0; /* Not matched */
	} else {
		bitparse_headers_start= ((char*)start_address) + sizeof(_bitparse_fixed_header);
		bitparse_bitstream_end= (char*)end_address;
		bitparse_initialized = 1;
		return 1;
	}
}

int bitparse_find_section(char section_name, char **section_start, unsigned int *section_length)
{
	char *pos = bitparse_headers_start;
	int result = 0;

	if(!bitparse_initialized) return 0;

	while(pos < bitparse_bitstream_end) {
		char current_name = *pos++;
		unsigned int current_length = 0;
		if(current_name < 'a' || current_name > 'e') {
			/* Strange section name, abort */
			break;
		}
		current_length = 0;
		switch(current_name) {
		case 'e':
			/* Four byte length field */
			current_length += (*pos++) << 24;
			current_length += (*pos++) << 16;
		default: /* Fall through, two byte length field */
			current_length += (*pos++) << 8;
			current_length += (*pos++) << 0;
		}

		if(current_name != 'e' && current_length > 255) {
			/* Maybe a parse error */
			break;
		}

		if(current_name == section_name) {
			/* Found it */
			*section_start = pos;
			*section_length = current_length;
			result = 1;
			break;
		}

		pos += current_length; /* Skip section */
	}

	return result;
}

//-----------------------------------------------------------------------------
// Find out which FPGA image format is stored in flash, then call DownloadFPGA
// with the right parameters to download the image
//-----------------------------------------------------------------------------
extern char _binary_fpga_bit_start, _binary_fpga_bit_end;
void FpgaDownloadAndGo(void)
{
	/* Check for the new flash image format: Should have the .bit file at &_binary_fpga_bit_start
	 */
	if(bitparse_init(&_binary_fpga_bit_start, &_binary_fpga_bit_end)) {
		/* Successfully initialized the .bit parser. Find the 'e' section and
		 * send its contents to the FPGA.
		 */
		char *bitstream_start;
		unsigned int bitstream_length;
		if(bitparse_find_section('e', &bitstream_start, &bitstream_length)) {
			DownloadFPGA(bitstream_start, bitstream_length, 0);

			return; /* All done */
		}
	}

	/* Fallback for the old flash image format: Check for the magic marker 0xFFFFFFFF
	 * 0xAA995566 at address 0x102000. This is raw bitstream with a size of 336,768 bits
	 * = 10,524 uint32_t, stored as uint32_t e.g. little-endian in memory, but each DWORD
	 * is still to be transmitted in MSBit first order. Set the invert flag to indicate
	 * that the DownloadFPGA function should invert every 4 byte sequence when doing
	 * the bytewise download.
	 */
	if( *(uint32_t*)0x102000 == 0xFFFFFFFF && *(uint32_t*)0x102004 == 0xAA995566 )
		DownloadFPGA((char*)0x102000, 10524*4, 1);
}

void FpgaGatherVersion(char *dst, int len)
{
	char *fpga_info;
	unsigned int fpga_info_len;
	dst[0] = 0;
	if(!bitparse_find_section('e', &fpga_info, &fpga_info_len)) {
		strncat(dst, "FPGA image: legacy image without version information", len-1);
	} else {
		strncat(dst, "FPGA image built", len-1);
		/* USB packets only have 48 bytes data payload, so be terse */
#if 0
		if(bitparse_find_section('a', &fpga_info, &fpga_info_len) && fpga_info[fpga_info_len-1] == 0 ) {
			strncat(dst, " from ", len-1);
			strncat(dst, fpga_info, len-1);
		}
		if(bitparse_find_section('b', &fpga_info, &fpga_info_len) && fpga_info[fpga_info_len-1] == 0 ) {
			strncat(dst, " for ", len-1);
			strncat(dst, fpga_info, len-1);
		}
#endif
		if(bitparse_find_section('c', &fpga_info, &fpga_info_len) && fpga_info[fpga_info_len-1] == 0 ) {
			strncat(dst, " on ", len-1);
			strncat(dst, fpga_info, len-1);
		}
		if(bitparse_find_section('d', &fpga_info, &fpga_info_len) && fpga_info[fpga_info_len-1] == 0 ) {
			strncat(dst, " at ", len-1);
			strncat(dst, fpga_info, len-1);
		}
	}
}

//-----------------------------------------------------------------------------
// Send a 16 bit command/data pair to the FPGA.
// The bit format is:  C3 C2 C1 C0 D11 D10 D9 D8 D7 D6 D5 D4 D3 D2 D1 D0
// where C is the 4 bit command and D is the 12 bit data
//-----------------------------------------------------------------------------
void FpgaSendCommand(uint16_t cmd, uint16_t v)
{
	SetupSpi(SPI_FPGA_MODE);
	while ((AT91C_BASE_SPI->SPI_SR & AT91C_SPI_TXEMPTY) == 0);		// wait for the transfer to complete
	AT91C_BASE_SPI->SPI_TDR = AT91C_SPI_LASTXFER | cmd | v;		// send the data
}
//-----------------------------------------------------------------------------
// Write the FPGA setup word (that determines what mode the logic is in, read
// vs. clone vs. etc.). This is now a special case of FpgaSendCommand() to
// avoid changing this function's occurence everywhere in the source code.
//-----------------------------------------------------------------------------
void FpgaWriteConfWord(uint8_t v)
{
	FpgaSendCommand(FPGA_CMD_SET_CONFREG, v);
}

//-----------------------------------------------------------------------------
// Set up the CMOS switches that mux the ADC: four switches, independently
// closable, but should only close one at a time. Not an FPGA thing, but
// the samples from the ADC always flow through the FPGA.
//-----------------------------------------------------------------------------
void SetAdcMuxFor(uint32_t whichGpio)
{
	AT91C_BASE_PIOA->PIO_OER =
		GPIO_MUXSEL_HIPKD |
		GPIO_MUXSEL_LOPKD |
		GPIO_MUXSEL_LORAW |
		GPIO_MUXSEL_HIRAW;

	AT91C_BASE_PIOA->PIO_PER =
		GPIO_MUXSEL_HIPKD |
		GPIO_MUXSEL_LOPKD |
		GPIO_MUXSEL_LORAW |
		GPIO_MUXSEL_HIRAW;

	LOW(GPIO_MUXSEL_HIPKD);
	LOW(GPIO_MUXSEL_HIRAW);
	LOW(GPIO_MUXSEL_LORAW);
	LOW(GPIO_MUXSEL_LOPKD);

	HIGH(whichGpio);
}
