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
bool Flash_CheckBusy(uint16_t times) {
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

	if (Flash_CheckBusy(100)) return 0;

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

	if (Flash_CheckBusy(100)) return;

	// reading unique serial number
	FlashSendByte(UNIQUE_ID);
	FlashSendByte(0xFF);
	FlashSendByte(0xFF);
	FlashSendByte(0xFF);
	FlashSendByte(0xFF);

	uid[7] = FlashSendByte(0xFF);
	uid[6] = FlashSendByte(0xFF);
	uid[5] = FlashSendByte(0xFF);
	uid[4] = FlashSendByte(0xFF);
    uid[3] = FlashSendByte(0xFF);
	uid[2] = FlashSendByte(0xFF);
	uid[1] = FlashSendByte(0xFF);
	uid[0] = FlashSendLastByte(0xFF);
}

uint16_t Flash_ReadData(uint32_t address, uint8_t *out, uint16_t len) {
	
	if (!FlashInit()) return 0;
	
	Flash_ReadStat1();
	
	// length should never be zero
	if (!len || Flash_CheckBusy(100)) return 0;

	FlashSendByte(READDATA);
	FlashSendByte((address >> 16) & 0xFF);
	FlashSendByte((address >> 8) & 0xFF);
	FlashSendByte((address >> 0) & 0xFF);

	uint16_t i = 0;
	for (; i < (len - 1); i++)
		out[i] = FlashSendByte(0xFF);

	out[i] = FlashSendLastByte(0xFF);
	
	FlashStop();	
	return len;	
}

// Write data can only program one page. A page has 256 bytes. 
// if len > 256, it might wrap around and overwrite pos 0.
uint16_t Flash_WriteData(uint32_t address, uint8_t *in, uint16_t len) {

	// length should never be zero
	if (!len)
		return 0;
	
	//	Max 256 bytes write
	if (((address & 0xFF) + len) > 256) {
		Dbprintf("Flash_WriteData 256 fail [ 0x%02x ] [ %u ]", (address & 0xFF)+len, len );
		return 0;
	}
	
	// out-of-range
	if ( (( address >> 16 ) & 0xFF ) > MAX_BLOCKS) {
		Dbprintf("Flash_WriteData,  block out-of-range");
		return 0;
	}

	if (!FlashInit()) {
		Dbprintf("Flash_WriteData init fail");
		return 0;
	}
	
	Flash_ReadStat1();

	Flash_WriteEnable();
	
	FlashSendByte(PAGEPROG);
	FlashSendByte((address >> 16) & 0xFF);
	FlashSendByte((address >> 8) & 0xFF);
	FlashSendByte((address >> 0) & 0xFF);

	uint16_t i = 0;
	for (; i < (len - 1); i++)
		FlashSendByte(in[i]);

	FlashSendLastByte(in[i]);

	FlashStop();
	return len;	
}

bool Flash_WipeMemoryPage(uint8_t page) {
	if (!FlashInit()) {
		Dbprintf("Flash_WriteData init fail");
		return false;
	}
	Flash_ReadStat1();
	
	// Each block is 64Kb. One block erase takes 1s ( 1000ms )
	Flash_WriteEnable(); Flash_Erase64k(page); Flash_CheckBusy(1000);	

	FlashStop();
	return true;	
}
// Wipes flash memory completely, fills with 0xFF
bool Flash_WipeMemory() {
	if (!FlashInit()) {
		Dbprintf("Flash_WriteData init fail");
		return false;
	}
	Flash_ReadStat1();
	
	// Each block is 64Kb.  Four blocks
	// one block erase takes 1s ( 1000ms )
	Flash_WriteEnable(); Flash_Erase64k(0); Flash_CheckBusy(1000);	
	Flash_WriteEnable(); Flash_Erase64k(1); Flash_CheckBusy(1000);
	Flash_WriteEnable(); Flash_Erase64k(2); Flash_CheckBusy(1000);
	Flash_WriteEnable(); Flash_Erase64k(3); Flash_CheckBusy(1000);
	
	FlashStop();
	return true;
}

//	enable the flash write
void Flash_WriteEnable() {
	FlashSendLastByte(WRITEENABLE);	
	if ( MF_DBGLEVEL > 3 ) Dbprintf("Flash Write enabled");	
}

//	erase 4K at one time
// execution time: 0.8ms / 800us
bool Flash_Erase4k(uint8_t block, uint8_t sector) {

	if (block > MAX_BLOCKS  || sector > MAX_SECTORS) return false;

	FlashSendByte(SECTORERASE);
	FlashSendByte(block);
	FlashSendByte(sector << 4);
	FlashSendLastByte(00);
	return true;
}

/*
//	erase 32K at one time
// execution time: 0,3s / 300ms
bool Flash_Erase32k(uint32_t address) {
	if (address & (32*1024 - 1)) {
		if ( MF_DBGLEVEL > 1 ) Dbprintf("Flash_Erase32k : Address is not align at 4096");
		return false;
	}
	FlashSendByte(BLOCK32ERASE);
	FlashSendByte((address >> 16) & 0xFF);
	FlashSendByte((address >> 8) & 0xFF);
	FlashSendLastByte((address >> 0) & 0xFF);
	return true;
}
*/

// erase 64k at one time
// since a block is 64kb,  and there is four blocks.
// we only need block number,  as MSB
// execution time: 1s  / 1000ms
// 0x00 00 00  -- 0x 00 FF FF  == block 0
// 0x01 00 00  -- 0x 01 FF FF  == block 1
// 0x02 00 00  -- 0x 02 FF FF  == block 2
// 0x03 00 00  -- 0x 03 FF FF  == block 3
bool Flash_Erase64k(uint8_t block) {
	
	if (block > MAX_BLOCKS) return false;
	
	FlashSendByte(BLOCK64ERASE);
	FlashSendByte(block);
	FlashSendByte(0x00);
	FlashSendLastByte(0x00);
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
	
	if (Flash_CheckBusy(100)) {
		StopTicks();
		return false;
	}

	if ( MF_DBGLEVEL > 3 ) Dbprintf("FlashInit OK");
	return true;
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
	
	uint8_t uid[8] = {0,0,0,0,0,0,0,0};
	Flash_UniqueID(uid);	
	Dbprintf("  Unique ID...............0x%02x%02x%02x%02x%02x%02x%02x%02x",
			uid[7], uid[6], uid[5], uid[4], 
			uid[3], uid[2], uid[1], uid[0]
	);
	
	FlashStop();
}