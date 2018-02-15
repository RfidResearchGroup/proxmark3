#include "flashmem.h"
#include "proxmark3.h"
#include "apps.h"

#define address_length 3

extern void Dbprintf(const char *fmt, ...);

static void FlashInit() {
	SetupSpi(SPI_MEM_MODE);
	NCS_3_LOW;
	Dbprintf("FlashInit");
}
static void FlashStop(){
	NCS_3_HIGH;
	Dbprintf("FlashStop");
}
static void FlashSend(uint16_t data) {

	Dbprintf("FlashSend");
	
	// 9th bit set for data, clear for command
	while ((AT91C_BASE_SPI->SPI_SR & AT91C_SPI_TXEMPTY) == 0);	// wait for the transfer to complete
	// For clarity's sake we pass data with 9th bit clear and commands with 9th
	// bit set since they're implemented as defines, se we need to invert bit
	AT91C_BASE_SPI->SPI_TDR = data ^ 0x100;	// Send the data/command
}
static uint8_t FlashWriteRead(uint8_t data){
	FlashSend(READDATA);
	FlashSend(data);
	uint8_t ret = MISO_VALUE;
	return ret;
}
static void FlashWrite_Enable(){
	FlashWriteRead(WRITEENABLE);
	Dbprintf("Flash WriteEnabled");	
}
static uint8_t FlashRead(uint8_t *address, uint16_t len) {
	FlashSend(READDATA);
	for (uint16_t i = 0; i < len; i++) {
		FlashWriteRead(address[i]);
	}  
	uint8_t	tmp = FlashWriteRead(0XFF);
	return tmp;	
}
void EXFLASH_TEST(void) {
	uint8_t a[3] = {0x00,0x00,0x00};
	//uint8_t b[3] = {0x00,0x01,0x02};	
	uint8_t d = 0;

	FlashInit();

	FlashWrite_Enable();
	
	//Dbprintf("write 012 to 0x00 0x01 0x02");	 
	//EXFLASH_Program(a, b, sizeof(b));

	d = FlashRead(a, sizeof(a));
	Dbprintf("%02x | %02x %02x %02x", d, a[0], a[1], a[2]);

	FlashStop();
	cmd_send(CMD_ACK, 1, 0, 0, 0,0);
}

//  IO  spi write or read
uint8_t EXFLASH_spi_write_read(uint8_t wData) {	
	uint8_t tmp = 0;
	SCK_LOW;
	NCS_3_LOW;

	for (uint8_t i = 0; i < 8; i++) {
		SCK_LOW;
		SpinDelayUs(2);

		if (wData & 0x80) {
			MOSI_HIGH;
		} else {
			MOSI_LOW;
			SpinDelayUs(2);
		}
		wData <<= 1;
		SCK_HIGH;
		tmp <<= 1;
		tmp |= MISO_VALUE;
	}
	SCK_LOW;
	return tmp;
}

uint8_t EXFLASH_readStat1(void) {
	uint8_t stat1 = 3;
	EXFLASH_spi_write_read(READSTAT1);
	stat1 = EXFLASH_spi_write_read(0xFF);
	NCS_3_HIGH;
	return stat1;
}

uint8_t EXFLASH_readStat2(void) {
	uint8_t stat2;
	EXFLASH_spi_write_read(READSTAT2);
	stat2 = EXFLASH_spi_write_read(0xFF);
	NCS_3_HIGH;
	return stat2;
}

bool EXFLASH_NOTBUSY(void) {
	uint8_t state, count = 0;
	do {
		state = EXFLASH_readStat1();
		if (count > 100) {
			return false;
		}
		count++;
	} while (state & BUSY);
	return true;
}

void EXFLASH_Write_Enable(void) {
	EXFLASH_spi_write_read(WRITEENABLE);
	NCS_3_HIGH;
}

uint8_t EXFLASH_Read(uint8_t *address, uint16_t len) {
	if (!EXFLASH_NOTBUSY())
		return false;

	EXFLASH_spi_write_read(READDATA);

	uint8_t tmp;
	for (uint16_t i=0; i < len; i++) {
		EXFLASH_spi_write_read(address[i]);
	}  
	tmp = EXFLASH_spi_write_read(0XFF);
	NCS_3_HIGH;
	return tmp;
}

uint8_t EXFLASH_Program(uint8_t  address[], uint8_t *array, uint8_t len) {
	uint8_t state1, count = 0, i;
	EXFLASH_Write_Enable();

	do {
		state1 = EXFLASH_readStat1();
		if (count > 100) {
			return false;
		}
		count++;
	} while ((state1 & WRTEN) != WRTEN);

	EXFLASH_spi_write_read(PAGEPROG);

	for (i=0; i<address_length; i++) {
		EXFLASH_spi_write_read(address[i]);
	}  

	for (i=0; i<len; i++) {
		EXFLASH_spi_write_read(array[i]);
	}  

	NCS_3_HIGH;
	return true;
}

uint8_t EXFLASH_ReadID(void) {

	if (!EXFLASH_NOTBUSY())
		return true;

    uint8_t ManID;   // DevID	
	EXFLASH_spi_write_read(MANID);
    EXFLASH_spi_write_read(0x00);
    EXFLASH_spi_write_read(0x00); 
    EXFLASH_spi_write_read(0x00);
	ManID = EXFLASH_spi_write_read(0xff);
//	DevID = EXFLASH_spi_write_read(0xff);

	NCS_3_HIGH;
	return ManID;
}

bool EXFLASH_Erase(void) {
	uint8_t state1, count = 0;

	EXFLASH_Write_Enable();

	do {
		state1 = EXFLASH_readStat1();
		if (count > 100) {
			return false;
		}
		count++;
	} while ((state1 & WRTEN) != WRTEN);

	EXFLASH_spi_write_read(CHIPERASE);
	NCS_3_HIGH;
	return true;
}

bool EXFLASH_Reset(void) {
	LED_A_ON();
	SetupSpi(SPI_MEM_MODE);

	NCS_3_LOW;
		
	if (!EXFLASH_NOTBUSY()) {
		LED_A_OFF();
		Dbprintf("[!] init reset failed");
		return false;
	}
	
	EXFLASH_spi_write_read(ENABLE_RESET);
	NCS_3_HIGH;
	EXFLASH_spi_write_read(RESET);
	NCS_3_HIGH;
	SpinDelayUs(10);
	LED_A_OFF();
	return true;
}

void EXFLASH_Init(void) {
	EXFLASH_Reset();
}

/*
void EXFLASH_TEST(void) {
	 uint8_t a[3] = {0x00,0x00,0x00};
	 uint8_t b[3] = {0x00,0x01,0x02};
     uint8_t f[3] = {0x00,0x00,0x01};
     uint8_t e[3] = {0x00,0x00,0x02};
	 uint8_t d = 0;
 
	 //EXFLASH_Init();
    // c = EXFLASH_ReadID();
	
    //EXFLASH_Write_Enable();
	//EXFLASH_readStat1();
    Dbprintf("%s \r\n", "write 012 to 0x00 0x01 0x02");	 
   	Dbprintf("%s \r\n"," wait... ");

    EXFLASH_Program(a, b, sizeof(b));
      
	d = EXFLASH_Read(a, sizeof(a) );
    Dbprintf(" %d ", d);
   
    d = EXFLASH_Read(f, sizeof(f) );
    Dbprintf(" %d ", d);
	
	d = EXFLASH_Read(e, sizeof(e) );

	Dbprintf(" %d ", d);
    Dbprintf("%s \r\n","TEST done!");

	EXFLASH_Erase();
	cmd_send(CMD_ACK, 1, 0, 0, 0,0);
}
*/