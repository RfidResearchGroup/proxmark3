#include "flashmem.h"

#define address_length 3

/* here: use NCPS2 @ PA10: */
#define SPI_CSR_NUM      2          		// Chip Select register[] 0,1,2,3  (at91samv512 has 4)

/* PCS_0 for NPCS0, PCS_1 for NPCS1 ... */
#define PCS_0  ((0<<0)|(1<<1)|(1<<2)|(1<<3)) // 0xE - 1110
#define PCS_1  ((1<<0)|(0<<1)|(1<<2)|(1<<3)) // 0xD - 1101
#define PCS_2  ((1<<0)|(1<<1)|(0<<2)|(1<<3)) // 0xB - 1011
#define PCS_3  ((1<<0)|(1<<1)|(1<<2)|(0<<3)) // 0x7 - 0111

/* TODO: ## */
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


//	初始化Flash
void FlashSetup()
{
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
	if (AT91C_BASE_SPI->SPI_RDR == 0)
		;

}

//	end up SPI
void FlashStop(void)
{
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

	Dbprintf("FlashStop");
}

//	发送一个字节 send one byte 
uint16_t FlashSendByte(uint32_t data)
{	
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

//	send last one byte
uint16_t FlashSendLastByte(uint32_t data) {
	return FlashSendByte(data | AT91C_SPI_LASTXFER);
}

//	Read state register 1
uint8_t Flash_ReadStat1(void) {
	FlashSendByte(READSTAT1);
	uint8_t stat1 = FlashSendLastByte(0xFF);
	Dbprintf("stat1 [%02x]", stat1);
	return stat1;
}

// Read state register 2
uint8_t Flash_ReadStat2(void) {
	FlashSendByte(READSTAT2);
	uint8_t stat2 = FlashSendLastByte(0xFF);
	Dbprintf("stat2 [%02x]", stat2);
	return stat2;
}

// Determine whether FLASHMEM is busy
bool Flash_CheckBusy(uint16_t times){
	bool bRet = (Flash_ReadStat1() & BUSY);

	if (!bRet || !times || !(times--))
		return bRet;

	while (times)
	{
		WDT_HIT();
		SpinDelayUs(1000);		//	wait 1ms
		bRet = (Flash_ReadStat1() & BUSY);
		if (!bRet)
			break;
		times--;
	}
	return bRet;
}

// read ID out
uint8_t Flash_ReadID(void) {

	if (Flash_CheckBusy(1000))
		return 0;

	// Manufacture ID / device ID
	uint8_t t0 = FlashSendByte(ID);
	uint8_t t1 = FlashSendByte(0x00);
	uint8_t t2 = FlashSendByte(0x00);
	uint8_t t3 = FlashSendByte(0x00);

    uint8_t man_id = FlashSendByte(0xFF);
	uint8_t dev_id = FlashSendLastByte(0xFF);
	
	Dbprintf(" [%02x] %02x %02x %02x | %02x  %02x", t0,t1,t2,t3, man_id, dev_id);

	//WINBOND_MANID
	if ( man_id == WINBOND_MANID ) {
		Dbprintf("Correct read of Manucaturer ID [%02x] == %02x", man_id, WINBOND_MANID);
	}

	if (man_id != WINBOND_MANID)
		dev_id = 0;

	return dev_id;
}

//	读取数据					address				buffer		length
uint8_t Flash_ReadDate(uint32_t Address, uint8_t *Buffer, uint16_t len)
{
	// length should never be zero
	if (!len || Flash_CheckBusy(1000))
		return 0;

	FlashSendByte(READDATA);
	FlashSendByte((Address >> 16) & 0xFF);
	FlashSendByte((Address >> 8) & 0xFF);
	FlashSendByte((Address >> 0) & 0xFF);

	uint16_t i = 0;
	for (; i < (len - 1); i++)
		Buffer[i] = FlashSendByte(0xFF);

	Buffer[i] = FlashSendLastByte(0xFF);
	return len;	
}

//	写入数据			地址	address  	缓冲区	buffer		长度length
uint8_t Flash_WriteDate(uint32_t Address, uint8_t *Buffer, uint16_t len)
{
	// length should never be zero
	if (!len || Flash_CheckBusy(1000))
		return 0;

	//	不能跨越 256 字节边界
	if (((Address & 255) + len) > 256)
		return 0;

	FlashSendByte(PAGEPROG);
	FlashSendByte((Address >> 16) & 0xFF);
	FlashSendByte((Address >> 8) & 0xFF);
	FlashSendByte((Address >> 0) & 0xFF);

	uint16_t i = 0;
	for (; i < (len - 1); i++)
		FlashSendByte(Buffer[i]);

	FlashSendLastByte(Buffer[i]);
	return len;	
}


//	enable the flash write
void Flash_WriteEnable()
{
	FlashSendLastByte(WRITEENABLE);
	Dbprintf("Flash WriteEnabled");	
}

//	erase 4K at one time
bool Flash_Erase4k(uint32_t Address)
{
	if (Address & (4096 - 1))
	{
		Dbprintf("Flash_Erase4k : Address is not align at 4096");
		return false;
	}

	FlashSendByte(SECTORERASE);
	FlashSendByte((Address >> 16) & 0xFF);
	FlashSendByte((Address >> 8) & 0xFF);
	FlashSendLastByte((Address >> 0) & 0xFF);
	return true;
}

//	erase 32K at one time
bool Flash_Erase32k(uint32_t Address)
{
	if (Address & (32*1024 - 1))
	{
		Dbprintf("Flash_Erase4k : Address is not align at 4096");
		return false;
	}
	FlashSendByte(BLOCK32ERASE);
	FlashSendByte((Address >> 16) & 0xFF);
	FlashSendByte((Address >> 8) & 0xFF);
	FlashSendLastByte((Address >> 0) & 0xFF);
	return true;
}

//	erase 64k at one time
bool Flash_Erase64k(uint32_t Address)
{
	if (Address & (64*1024 - 1))
	{
		Dbprintf("Flash_Erase4k : Address is not align at 4096");
		return false;
	}
	FlashSendByte(BLOCK64ERASE);
	FlashSendByte((Address >> 16) & 0xFF);
	FlashSendByte((Address >> 8) & 0xFF);
	FlashSendLastByte((Address >> 0) & 0xFF);
	return true;
}

//	erase all
void Flash_EraseChip(void)
{
	FlashSendLastByte(CHIPERASE);
}


//	initialize
bool FlashInit(void)	
{
	FlashSetup();

	if (Flash_CheckBusy(1000))
		return false;

	Dbprintf("FlashInit");
	return true;
}

void EXFLASH_TEST(void)
{
	uint8_t		Data[256] = { 0x00, 0x01, 0x02 };
	uint8_t		Data2[256] = { 0x00};
	uint32_t	FlashSize = 0;

	if (!FlashInit()) return;
	
	Flash_ReadStat1();
	
	switch (Flash_ReadID())
	{
	case 0x11:		//	W25X20CL
		FlashSize = 2048*1024;
		break;
	case 0x10:		//	W25X10CL
		FlashSize = 1024*1024;
		break;
	case 0x05:		//	W25X05CL
		FlashSize = 512*1024;
		break;
	}

	Dbprintf("Flash Size = %dk", FlashSize / 1024);

	if (FlashSize != 2048*1024)
		return;
	
	Dbprintf("Flash test write:  012 to 0x00 0x01 0x02");
	Flash_WriteEnable();
	Flash_Erase4k(0x00);
	if (Flash_CheckBusy(1000))
	{
		Dbprintf("Flash_Erase4k CheckBusy Error.");
		return;
	}
	Flash_ReadDate(0, Data2, 256);
	Flash_WriteEnable();
	Flash_WriteDate(0x12, Data, sizeof(Data));		//	this will never run, cuz out of 256byte boundary
	Flash_WriteDate(0x12, Data, 3);
	if (Flash_CheckBusy(1000))
	{
		Dbprintf("Flash_WriteDate CheckBusy Error.");
		return;
	}

	Flash_ReadDate(0, Data2, 256);

	FlashStop();
}

