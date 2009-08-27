//-----------------------------------------------------------------------------
// Routines to load the FPGA image, and then to configure the FPGA's major
// mode once it is configured.
//
// Jonathan Westhues, April 2006
//-----------------------------------------------------------------------------
#include <proxmark3.h>
#include "apps.h"

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
	PIO_DISABLE			 =	(1 << GPIO_NCS0)	|
							(1 << GPIO_NCS2) 	|
							(1 << GPIO_MISO)	|
							(1 << GPIO_MOSI)	|
							(1 << GPIO_SPCK);

	PIO_PERIPHERAL_A_SEL =	(1 << GPIO_NCS0)	|
							(1 << GPIO_MISO)	|
							(1 << GPIO_MOSI)	|
							(1 << GPIO_SPCK);

	PIO_PERIPHERAL_B_SEL =	(1 << GPIO_NCS2);

	//enable the SPI Peripheral clock
	PMC_PERIPHERAL_CLK_ENABLE = (1<<PERIPH_SPI);
	// Enable SPI
	SPI_CONTROL = SPI_CONTROL_ENABLE;

	switch (mode) {
		case SPI_FPGA_MODE:
			SPI_MODE =
				( 0 << 24)	|	// Delay between chip selects (take default: 6 MCK periods)
				(14 << 16)	|	// Peripheral Chip Select (selects FPGA SPI_NCS0 or PA11)
				( 0 << 7)	|	// Local Loopback Disabled
				( 1 << 4)	|	// Mode Fault Detection disabled
				( 0 << 2)	|	// Chip selects connected directly to peripheral
				( 0 << 1) 	|	// Fixed Peripheral Select
				( 1 << 0);		// Master Mode
			SPI_FOR_CHIPSEL_0 =
				( 1 << 24)	|	// Delay between Consecutive Transfers (32 MCK periods)
				( 1 << 16)	|	// Delay Before SPCK (1 MCK period)
				( 6 << 8)	|	// Serial Clock Baud Rate (baudrate = MCK/6 = 24Mhz/6 = 4M baud
				( 8 << 4)	|	// Bits per Transfer (16 bits)
				( 0 << 3)	|	// Chip Select inactive after transfer
				( 1 << 1)	|	// Clock Phase data captured on leading edge, changes on following edge
				( 0 << 0);		// Clock Polarity inactive state is logic 0
			break;
		case SPI_LCD_MODE:
			SPI_MODE =
				( 0 << 24)	|	// Delay between chip selects (take default: 6 MCK periods)
				(11 << 16)	|	// Peripheral Chip Select (selects LCD SPI_NCS2 or PA10)
				( 0 << 7)	|	// Local Loopback Disabled
				( 1 << 4)	|	// Mode Fault Detection disabled
				( 0 << 2)	|	// Chip selects connected directly to peripheral
				( 0 << 1) 	|	// Fixed Peripheral Select
				( 1 << 0);		// Master Mode
			SPI_FOR_CHIPSEL_2 =
				( 1 << 24)	|	// Delay between Consecutive Transfers (32 MCK periods)
				( 1 << 16)	|	// Delay Before SPCK (1 MCK period)
				( 6 << 8)	|	// Serial Clock Baud Rate (baudrate = MCK/6 = 24Mhz/6 = 4M baud
				( 1 << 4)	|	// Bits per Transfer (9 bits)
				( 0 << 3)	|	// Chip Select inactive after transfer
				( 1 << 1)	|	// Clock Phase data captured on leading edge, changes on following edge
				( 0 << 0);		// Clock Polarity inactive state is logic 0
			break;
		default:				// Disable SPI
			SPI_CONTROL = SPI_CONTROL_DISABLE;
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
	PIO_PERIPHERAL_A_SEL =	(1 << GPIO_SSC_FRAME)	|
							(1 << GPIO_SSC_DIN)		|
							(1 << GPIO_SSC_DOUT)	|
							(1 << GPIO_SSC_CLK);
	PIO_DISABLE = (1 << GPIO_SSC_DOUT);

	PMC_PERIPHERAL_CLK_ENABLE = (1 << PERIPH_SSC);

	// Now set up the SSC proper, starting from a known state.
	SSC_CONTROL = SSC_CONTROL_RESET;

	// RX clock comes from TX clock, RX starts when TX starts, data changes
	// on RX clock rising edge, sampled on falling edge
	SSC_RECEIVE_CLOCK_MODE = SSC_CLOCK_MODE_SELECT(1) | SSC_CLOCK_MODE_START(1);

	// 8 bits per transfer, no loopback, MSB first, 1 transfer per sync
	// pulse, no output sync, start on positive-going edge of sync
	SSC_RECEIVE_FRAME_MODE = SSC_FRAME_MODE_BITS_IN_WORD(8) |
		SSC_FRAME_MODE_MSB_FIRST | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);

	// clock comes from TK pin, no clock output, outputs change on falling
	// edge of TK, start on rising edge of TF
	SSC_TRANSMIT_CLOCK_MODE = SSC_CLOCK_MODE_SELECT(2) |
		SSC_CLOCK_MODE_START(5);

	// tx framing is the same as the rx framing
	SSC_TRANSMIT_FRAME_MODE = SSC_RECEIVE_FRAME_MODE;

	SSC_CONTROL = SSC_CONTROL_RX_ENABLE | SSC_CONTROL_TX_ENABLE;
}

//-----------------------------------------------------------------------------
// Set up DMA to receive samples from the FPGA. We will use the PDC, with
// a single buffer as a circular buffer (so that we just chain back to
// ourselves, not to another buffer). The stuff to manipulate those buffers
// is in apps.h, because it should be inlined, for speed.
//-----------------------------------------------------------------------------
void FpgaSetupSscDma(BYTE *buf, int len)
{
	PDC_RX_POINTER(SSC_BASE) = (DWORD)buf;
	PDC_RX_COUNTER(SSC_BASE) = len;
	PDC_RX_NEXT_POINTER(SSC_BASE) = (DWORD)buf;
	PDC_RX_NEXT_COUNTER(SSC_BASE) = len;
	PDC_CONTROL(SSC_BASE) = PDC_RX_ENABLE;
}

// Download the fpga image starting at FpgaImage and with length FpgaImageLen DWORDs (e.g. 4 bytes)
// If bytereversal is set: reverse the byte order in each 4-byte word
static void DownloadFPGA(const DWORD *FpgaImage, DWORD FpgaImageLen, int bytereversal)
{
	int i, j;

	PIO_OUTPUT_ENABLE = (1 << GPIO_FPGA_ON);
	PIO_ENABLE = (1 << GPIO_FPGA_ON);
	PIO_OUTPUT_DATA_SET = (1 << GPIO_FPGA_ON);

	SpinDelay(50);

	LED_D_ON();

	HIGH(GPIO_FPGA_NPROGRAM);
	LOW(GPIO_FPGA_CCLK);
	LOW(GPIO_FPGA_DIN);
	PIO_OUTPUT_ENABLE = (1 << GPIO_FPGA_NPROGRAM)	|
						(1 << GPIO_FPGA_CCLK)		|
						(1 << GPIO_FPGA_DIN);
	SpinDelay(1);

	LOW(GPIO_FPGA_NPROGRAM);
	SpinDelay(50);
	HIGH(GPIO_FPGA_NPROGRAM);

	for(i = 0; i < FpgaImageLen; i++) {
		DWORD v = FpgaImage[i];
		unsigned char w;
		for(j = 0; j < 4; j++) {
			if(!bytereversal) 
				w = v >>(j*8);
			else
				w = v >>((3-j)*8);
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

int bitparse_find_section(char section_name, void **section_start, unsigned int *section_length)
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
		void *bitstream_start;
		unsigned int bitstream_length;
		if(bitparse_find_section('e', &bitstream_start, &bitstream_length)) {
			DownloadFPGA((DWORD *)bitstream_start, bitstream_length/4, 0);
			
			return; /* All done */
		}
	}
	
	/* Fallback for the old flash image format: Check for the magic marker 0xFFFFFFFF
	 * 0xAA995566 at address 0x2000. This is raw bitstream with a size of 336,768 bits 
	 * = 10,524 DWORDs, stored as DWORDS e.g. little-endian in memory, but each DWORD
	 * is still to be transmitted in MSBit first order. Set the invert flag to indicate
	 * that the DownloadFPGA function should invert every 4 byte sequence when doing
	 * the bytewise download.
	 */
	if( *(DWORD*)0x2000 == 0xFFFFFFFF && *(DWORD*)0x2004 == 0xAA995566 )
		DownloadFPGA((DWORD *)0x2000, 10524, 1);
}

//-----------------------------------------------------------------------------
// Send a 16 bit command/data pair to the FPGA.
// The bit format is:  C3 C2 C1 C0 D11 D10 D9 D8 D7 D6 D5 D4 D3 D2 D1 D0
// where C is the 4 bit command and D is the 12 bit data
//-----------------------------------------------------------------------------
void FpgaSendCommand(WORD cmd, WORD v)
{
	SetupSpi(SPI_FPGA_MODE);
	while ((SPI_STATUS & SPI_STATUS_TX_EMPTY) == 0);		// wait for the transfer to complete
	SPI_TX_DATA = SPI_CONTROL_LAST_TRANSFER | cmd | v;		// send the data
}
//-----------------------------------------------------------------------------
// Write the FPGA setup word (that determines what mode the logic is in, read
// vs. clone vs. etc.). This is now a special case of FpgaSendCommand() to
// avoid changing this function's occurence everywhere in the source code.
//-----------------------------------------------------------------------------
void FpgaWriteConfWord(BYTE v)
{
	FpgaSendCommand(FPGA_CMD_SET_CONFREG, v);
}

//-----------------------------------------------------------------------------
// Set up the CMOS switches that mux the ADC: four switches, independently
// closable, but should only close one at a time. Not an FPGA thing, but
// the samples from the ADC always flow through the FPGA.
//-----------------------------------------------------------------------------
void SetAdcMuxFor(int whichGpio)
{
	PIO_OUTPUT_ENABLE = (1 << GPIO_MUXSEL_HIPKD) |
						(1 << GPIO_MUXSEL_LOPKD) |
						(1 << GPIO_MUXSEL_LORAW) |
						(1 << GPIO_MUXSEL_HIRAW);

	PIO_ENABLE		=	(1 << GPIO_MUXSEL_HIPKD) |
						(1 << GPIO_MUXSEL_LOPKD) |
						(1 << GPIO_MUXSEL_LORAW) |
						(1 << GPIO_MUXSEL_HIRAW);

	LOW(GPIO_MUXSEL_HIPKD);
	LOW(GPIO_MUXSEL_HIRAW);
	LOW(GPIO_MUXSEL_LORAW);
	LOW(GPIO_MUXSEL_LOPKD);

	HIGH(whichGpio);
}
