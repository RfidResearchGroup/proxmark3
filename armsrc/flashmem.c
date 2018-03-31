#include "flashmem.h"

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


/*
	读取指令，可以从一个位置开始持续的读，最多能将整块芯片读取完
	页写指令，每次写入为1-256字节，但是不能跨越256字节边界
	擦除指令，擦除指令后必须将CS拉高，否则不会执行
*/

void FlashSetup(void) {
	// PA1	-> SPI_NCS3 chip select (MEM)
	// PA10 -> SPI_NCS2 chip select (LCD)
	// PA11 -> SPI_NCS0 chip select (FPGA)
	// PA12 -> SPI_MISO Master-In Slave-Out
	// PA13 -> SPI_MOSI Master-Out Slave-In
	// PA14 -> SPI_SPCK Serial Clock

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

void FlashStop(void) {
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

	if ( MF_DBGLEVEL > 3 ) Dbprintf("FlashStop");
	
	StopTicks();
}

//	send one byte over SPI
uint16_t FlashSendByte(uint32_t data) {	
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

//	send last byte over SPI
uint16_t FlashSendLastByte(uint32_t data) {
	return FlashSendByte(data | AT91C_SPI_LASTXFER);
}

//	read state register 1
uint8_t Flash_ReadStat1(void) {
	FlashSendByte(READSTAT1);
	uint8_t stat1 = FlashSendLastByte(0xFF);
	if ( MF_DBGLEVEL > 3 )  Dbprintf("stat1 [%02x]", stat1);
	return stat1;
}

// read state register 2
uint8_t Flash_ReadStat2(void) {
	FlashSendByte(READSTAT2);
	uint8_t stat2 = FlashSendLastByte(0xFF);
	if ( MF_DBGLEVEL > 3 ) Dbprintf("stat2 [%02x]", stat2);
	return stat2;
}

// determine whether FLASHMEM is busy
bool Flash_CheckBusy(uint16_t times){
	bool ret = (Flash_ReadStat1() & BUSY);

	if (!ret || !times || !(times--))
		return ret;

	while (times) {
		WDT_HIT();
		WaitMS(1);
		ret = (Flash_ReadStat1() & BUSY);
		if (!ret)
			break;
		times--;
	}
	return ret;
}

// read ID out
uint8_t Flash_ReadID(void) {

	if (Flash_CheckBusy(1000)) return 0;

	// Manufacture ID / device ID
	FlashSendByte(ID);
	FlashSendByte(0x00);
	FlashSendByte(0x00);
	FlashSendByte(0x00);

    uint8_t man_id = FlashSendByte(0xFF);
	uint8_t dev_id = FlashSendLastByte(0xFF);
	
	if ( MF_DBGLEVEL > 3 ) Dbprintf("Flash ReadID  |  Man ID %02x | Device ID %02x", man_id, dev_id);
	
	if ( (man_id == WINBOND_MANID ) && (dev_id == WINBOND_DEVID) )
		return dev_id;

	return 0;
}

// read unique id for chip.
void Flash_UniqueID(uint8_t *uid) {

	if (Flash_CheckBusy(1000)) return;

	// reading unique serial number
	FlashSendByte(UNIQUE_ID);
	FlashSendByte(0x00);
	FlashSendByte(0x00);
	FlashSendByte(0x00);
	FlashSendByte(0x00);

    uid[3] = FlashSendByte(0xFF);
	uid[2] = FlashSendByte(0xFF);
	uid[1] = FlashSendByte(0xFF);
	uid[0] = FlashSendLastByte(0xFF);
}

uint8_t Flash_ReadData(uint32_t address, uint8_t *out, uint16_t len) {
	// length should never be zero
	if (!len || Flash_CheckBusy(1000)) return 0;

	FlashSendByte(READDATA);
	FlashSendByte((address >> 16) & 0xFF);
	FlashSendByte((address >> 8) & 0xFF);
	FlashSendByte((address >> 0) & 0xFF);

	uint16_t i = 0;
	for (; i < (len - 1); i++)
		out[i] = FlashSendByte(0xFF);

	out[i] = FlashSendLastByte(0xFF);
	return len;	
}

//	Write data 
uint8_t Flash_WriteData(uint32_t address, uint8_t *in, uint16_t len) {
	// length should never be zero
	if (!len || Flash_CheckBusy(1000)) return 0;

	//	不能跨越 256 字节边界
	if (((address & 255) + len) > 256) return 0;

	FlashSendByte(PAGEPROG);
	FlashSendByte((address >> 16) & 0xFF);
	FlashSendByte((address >> 8) & 0xFF);
	FlashSendByte((address >> 0) & 0xFF);

	uint16_t i = 0;
	for (; i < (len - 1); i++)
		FlashSendByte(in[i]);

	FlashSendLastByte(in[i]);
	return len;	
}

//	enable the flash write
void Flash_WriteEnable() {
	FlashSendLastByte(WRITEENABLE);
	if ( MF_DBGLEVEL > 3 ) Dbprintf("Flash Write enabled");	
}

//	erase 4K at one time
bool Flash_Erase4k(uint32_t address) {
	if (address & (4096 - 1)) {
		if ( MF_DBGLEVEL > 1 ) Dbprintf("Flash_Erase4k : Address is not align at 4096");
		return false;
	}

	FlashSendByte(SECTORERASE);
	FlashSendByte((address >> 16) & 0xFF);
	FlashSendByte((address >> 8) & 0xFF);
	FlashSendLastByte((address >> 0) & 0xFF);
	return true;
}

//	erase 32K at one time
bool Flash_Erase32k(uint32_t address) {
	if (address & (32*1024 - 1)) {
		if ( MF_DBGLEVEL > 1 ) Dbprintf("Flash_Erase4k : Address is not align at 4096");
		return false;
	}
	FlashSendByte(BLOCK32ERASE);
	FlashSendByte((address >> 16) & 0xFF);
	FlashSendByte((address >> 8) & 0xFF);
	FlashSendLastByte((address >> 0) & 0xFF);
	return true;
}

//	erase 64k at one time
bool Flash_Erase64k(uint32_t address) {

	if (address & (64*1024 - 1)) {
		if ( MF_DBGLEVEL > 1 ) Dbprintf("Flash_Erase4k : Address is not align at 4096");
		return false;
	}
	FlashSendByte(BLOCK64ERASE);
	FlashSendByte((address >> 16) & 0xFF);
	FlashSendByte((address >> 8) & 0xFF);
	FlashSendLastByte((address >> 0) & 0xFF);
	return true;
}

//	Erase chip
void Flash_EraseChip(void) {
	FlashSendLastByte(CHIPERASE);
}

//	initialize
bool FlashInit(void) {
	FlashSetup();

	StartTicks();
	
	if (Flash_CheckBusy(1000)) {
		StopTicks();
		return false;
	}

	if ( MF_DBGLEVEL > 3 ) Dbprintf("FlashInit OK");
	return true;
}

void EXFLASH_TEST(void) {
	uint8_t	 data[256] = { 0x00, 0x01, 0x02 };
	uint8_t	 data2[256] = { 0x00};

	if (!FlashInit()) return;
	
	Flash_ReadStat1();
	
	Dbprintf("Flash test write:  012 to 0x00 0x01 0x02");
	Flash_WriteEnable();
	Flash_Erase4k(0x00);
	if (Flash_CheckBusy(1000)) {
		Dbprintf("Flash_Erase4k CheckBusy Error.");
		return;
	}
	
	Flash_ReadData(0, data2, 256);
	Flash_WriteEnable();
	Flash_WriteData(0x12, data, sizeof(data));		//	this will never run, cuz out of 256byte boundary
	Flash_WriteData(0x12, data, 3);

	if (Flash_CheckBusy(1000)) {
		Dbprintf("Flash_WriteDate CheckBusy Error.");
		return;
	}

	Flash_ReadData(0, data2, 256);
	FlashStop();
}


void Flashmem_print_status(void) {
	DbpString("Flash memory");

	if (!FlashInit()) {
		DbpString("  init....................FAIL");
		return;
	}
	DbpString("  init....................OK");
	
	uint8_t dev_id = Flash_ReadID();
	switch (dev_id) {
		case 0x11 :
			DbpString("  Memory size.............2 mbits / 256kb");
			break;
		case 0x10 :
			DbpString("  Memory size..... .......1 mbits / 128kb");
			break;
		case 0x05 :
			DbpString("  Memory size.............512 kbits / 64kb");
			break;
		default :
			DbpString("  Device ID............... -->  Unknown  <--");
			break;
	}
	
	uint8_t uid[4] = {0,0,0,0};
	Flash_UniqueID(uid);	
	Dbprintf("  Unique ID...............0x%02x%02x%02x%02x %", uid[3], uid[2], uid[1], uid[0]);	
	
	FlashStop();	
}