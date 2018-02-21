#include "flashmem.h"

#define address_length 3

/* here: use NCPS2 @ PA10: */
#define NCPS_PDR_BIT     AT91C_PA10_NPCS2	// GPIO
#define NCPS_ASR_BIT     0					// SPI peripheral A
#define NCPS_BSR_BIT     AT91C_PA10_NPCS2	// SPI peripheral B
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
1.  variable chip select (PS=1)  ChipSelect number is written to TDR in EVERY transfer
2.  fixed chip select (PS=0), 

FIXED 		= you manage the CS lines
VARIABLE 	= SPI module manages the CS lines
*/

void FlashSetup(void) {
	// PA1	-> SPI_NCS3 chip select (MEM)
	// PA12 -> SPI_MISO Master-In Slave-Out
	// PA13 -> SPI_MOSI Master-Out Slave-In
	// PA14 -> SPI_SPCK Serial Clock

	// Kill all the pullups,
	//AT91C_BASE_PIOA->PIO_PPUDR = GPIO_NCS1 | GPIO_MOSI | GPIO_SPCK | GPIO_MISO;

	// These pins are outputs
	//AT91C_BASE_PIOA->PIO_OER = GPIO_NCS1 | GPIO_MOSI | GPIO_SPCK;

	// PIO controls the following pins
	//AT91C_BASE_PIOA->PIO_PER = GPIO_NCS1 | GPIO_MOSI | GPIO_SPCK | GPIO_MISO;

	// Disable PIO control of the following pins, hand over to SPI control
	AT91C_BASE_PIOA->PIO_PDR = GPIO_MISO | GPIO_MOSI | GPIO_SPCK | NCPS_PDR_BIT;
		
	// Peripheral A
	AT91C_BASE_PIOA->PIO_ASR = GPIO_MISO | GPIO_MOSI | GPIO_SPCK | NCPS_ASR_BIT;
	// Peripheral B
	AT91C_BASE_PIOA->PIO_BSR = GPIO_MISO | GPIO_MOSI | GPIO_SPCK | NCPS_BSR_BIT ;

	// set chip-select as output high (unselect card)
	AT91C_BASE_PIOA->PIO_PER  = NCPS_PDR_BIT; // enable GPIO of CS-pin
	AT91C_BASE_PIOA->PIO_SODR = NCPS_PDR_BIT; // set high
	AT91C_BASE_PIOA->PIO_OER  = NCPS_PDR_BIT; // output enable
	
	//enable the SPI Peripheral clock
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_SPI);

	// SPI Mode register
	/*
	AT91C_BASE_SPI->SPI_MR =
		(0 << 24)			|	// DLYBCS, Delay between chip selects (take default: 6 MCK periods)
		(0 << 7)			|	// LLB, Local Loopback Disabled
		AT91C_SPI_MODFDIS	|	// Mode Fault Detection disabled
		(0 << 2)			|	// PCSDEC, Chip selects connected directly to peripheral
		AT91C_SPI_PS_FIXED	|	// PS, Fixed Peripheral Select
		AT91C_SPI_MSTR;			// MSTR, Master Mode
		*/
	AT91C_BASE_SPI->SPI_MR = AT91C_SPI_MSTR  | AT91C_SPI_PS_FIXED | AT91C_SPI_MODFDIS;
		
	// PCS, Peripheral Chip Select
	AT91C_BASE_SPI->SPI_MR |= ( (SPI_MR_PCS << 16) & AT91C_SPI_PCS );

	// SPI Chip select register
/*
	AT91C_BASE_SPI->SPI_CSR[SPI_CSR_NUM] =
		(1 << 24)			|	// Delay between Consecutive Transfers (32 MCK periods)
		(1 << 16) 			|	// Delay Before SPCK (1 MCK period)
		(6 << 8) 			|	// Serial Clock Baud Rate (baudrate = MCK/6 = 24Mhz/6 = 4M baud
		AT91C_SPI_BITS_8	|	// Bits per Transfer (8 bits)
		(0 << 3) 			|	// CSAAT, Chip Select inactive after transfer
		AT91C_SPI_NCPHA		|	// NCPHA, Clock Phase data captured on leading edge, changes on following edge
		(0 << 0);				// CPOL, Clock Polarity inactive state is logic 0
*/
	AT91C_BASE_SPI->SPI_CSR[SPI_CSR_NUM] =  AT91C_SPI_NCPHA | AT91C_SPI_BITS_8 | (6 << 8);

	// Enable SPI
	AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIEN;
	
		/* Send 20 spi commands with card not selected */
	for (int i=0; i<21; i++)
		FlashSend(0xFF);

	/* enable automatic chip-select */
	// reset PIO-registers of CS-pin to default
	AT91C_BASE_PIOA->PIO_ODR  |= NCPS_PDR_BIT; // input
	AT91C_BASE_PIOA->PIO_CODR |= NCPS_PDR_BIT; // clear
	// disable PIO from controlling the CS pin (=hand over to SPI)
	AT91C_BASE_PIOA->PIO_PDR |= NCPS_PDR_BIT;
	// set pin-functions in PIO Controller (function NCPS for CS-pin)
	AT91C_BASE_PIOA->PIO_ASR |= NCPS_ASR_BIT;
	AT91C_BASE_PIOA->PIO_BSR |= NCPS_BSR_BIT;
}

void FlashStop(void) {
	//NCS_1_HIGH;
	StopTicks();
	Dbprintf("FlashStop");
	LED_A_OFF();
	
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
}

uint16_t FlashSend(uint16_t data) {	
	
	uint16_t incoming = 0;

	// wait until SPI is ready for transfer
	while ( !(AT91C_BASE_SPI->SPI_SR & AT91C_SPI_TXEMPTY)) {};

	// send the data
	AT91C_BASE_SPI->SPI_TDR = data;

	// wait recive transfer is complete
	while ( !(AT91C_BASE_SPI->SPI_SR & AT91C_SPI_RDRF)) {};
	
	// reading incoming data
	incoming = ((AT91C_BASE_SPI->SPI_RDR) & 0xFFFF);

	return incoming;
}
uint8_t Flash_ReadStat1(void) {
	uint8_t stat2 = FlashSend(READSTAT1);
	uint8_t stat1 = FlashSend(0xFF);
	Dbprintf("stat1 [%02x] %02x ", stat1, stat2);
//	NCS_1_HIGH;
	return stat1;
}
/*
static uint8_t Flash_ReadStat2(void) {
	FlashSend(READSTAT2);
	uint8_t stat2 = FlashSend(0xff);
	NCS_1_HIGH;
	return stat2;
}
*/

bool Flash_NOTBUSY(void) {
	WDT_HIT();
	uint8_t state, count = 0;
	do {
		state = Flash_ReadStat1();
		if (count > 100) {
			return false;
		}
		count++;
	} while (state & BUSY);
	return true;
}
/*
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
*/
/*
static uint8_t FlashRead(uint8_t *address, uint16_t len) {
	FlashSend(READDATA);
	for (uint16_t i = 0; i < len; i++) {
		FlashWriteRead(address[i]);
	}  
	uint8_t	tmp = FlashWriteRead(0XFF);
	return tmp;	
}
*/

uint8_t Flash_ReadID(void) {

//	if (!Flash_NOTBUSY())
//		return true;

	// Manufacture ID / device ID
	uint8_t t0 = FlashSend(ID);
	uint8_t t1 = FlashSend(0x00);
	uint8_t t2 = FlashSend(0x00);
	uint8_t t3 = FlashSend(0x00);

    uint8_t man_id = FlashSend(0xFF);
	uint8_t dev_id = 0; //	FlashSend(0xff);
	
	Dbprintf(" [%02x] %02x %02x %02x | %02x  %02x", t0,t1,t2,t3, man_id, dev_id);

	//WINBOND_MANID
	if ( man_id == WINBOND_MANID ) {
		Dbprintf("Correct read of Manucaturer ID [%02x] == %02x", man_id, WINBOND_MANID);
	}
	// if ( dev_id > 0) {
		// Dbprintf("Got a device ID [%02x] == %02x  ( 0x11 0x30 0x12", dev_id,  WINBOND_DEVID);
	// }

//	NCS_1_HIGH;
	return man_id;
}
bool FlashInit(void) {
	
	StartTicks();

	LED_A_ON();	
	FlashSetup();

	if (!Flash_NOTBUSY())
		return false;
	
//	FlashSend(ENABLE_RESET);
//	NCS_1_HIGH;
//	FlashSend(RESET);
//	NCS_1_HIGH;
//	WaitUS(10);

	Dbprintf("FlashInit");
	return true;
}

void EXFLASH_TEST(void) {
	//uint8_t a[3] = {0x00,0x00,0x00};
	//uint8_t b[3] = {0x00,0x01,0x02};
	//uint8_t d = 0;

	if (!FlashInit()) return;

	//FlashWrite_Enable();
	
	Flash_ReadID();
	
	//Dbprintf("Flash test write:  012 to 0x00 0x01 0x02");
	//EXFLASH_Program(a, b, sizeof(b));

	//d = FlashRead(a, sizeof(a));
	//Dbprintf("%02x | %02x %02x %02x", d, a[0], a[1], a[2]);

	FlashStop();
	cmd_send(CMD_ACK, 1, 0, 0, 0,0);
}
/*
//  IO  spi write or read
uint8_t EXFLASH_spi_write_read(uint8_t wData) {	
	uint8_t tmp = 0;
	SCK_LOW;
	LOW(GPIO_NCS2);

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


void EXFLASH_Write_Enable(void) {
	EXFLASH_spi_write_read(WRITEENABLE);
	 HIGH(GPIO_NCS2);
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
	 HIGH(GPIO_NCS2);
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

	 HIGH(GPIO_NCS2);
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

	 HIGH(GPIO_NCS2);
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
	 HIGH(GPIO_NCS2);
	return true;
}
*/
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