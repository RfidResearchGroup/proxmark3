#include "flashmem.h"
#include "proxmark3.h"
#include "apps.h"

#define address_length 3

extern void Dbprintf(const char *fmt, ...);

static void FlashSetup() {
	// PA1	-> SPI_NCS3 chip select (MEM)
	// PA12 -> SPI_MISO Master-In Slave-Out
	// PA13 -> SPI_MOSI Master-Out Slave-In
	// PA14 -> SPI_SPCK Serial Clock

	// Disable PIO control of the following pins, allows use by the SPI peripheral
	AT91C_BASE_PIOA->PIO_PDR =
		GPIO_NCS2 	|
		GPIO_MISO	|
		GPIO_MOSI	|
		GPIO_SPCK;

	// Peripheral A
	AT91C_BASE_PIOA->PIO_ASR =
		GPIO_NCS2	|
		GPIO_MISO	|
		GPIO_MOSI	|
		GPIO_SPCK;

	//enable the SPI Peripheral clock
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_SPI);

	// Enable SPI
	AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIEN;

	// SPI Mode register
	AT91C_BASE_SPI->SPI_MR =
		((0 << 24)& AT91C_SPI_DLYBCS)	|	// DLYBCS, Delay between chip selects (take default: 6 MCK periods)
		((1 << 16)& AT91C_SPI_PCS)		|	// PCS, Peripheral Chip Select (selects PA1)
		((0 << 7) & AT91C_SPI_LLB)		|	// Local Loopback Disabled
		((1 << 4) & AT91C_SPI_MODFDIS)	|	// Mode Fault Detection disabled
		((0 << 2) & AT91C_SPI_PCSDEC)	|	// Chip selects connected directly to peripheral
		((0 << 1) & AT91C_SPI_PS_FIXED) |	// PS, Fixed Peripheral Select
		((1 << 0) & AT91C_SPI_MSTR);		// MSTR, Master Mode
	
	// SPI Chip select register
	AT91C_BASE_SPI->SPI_CSR[0] =
		((1 << 24)& AT91C_SPI_DLYBCT)		|	// Delay between Consecutive Transfers (32 MCK periods)
		((1 << 16)& AT91C_SPI_DLYBS)		|	// Delay Before SPCK (1 MCK period)
		((6 << 8) & AT91C_SPI_SCBR)			|	// Serial Clock Baud Rate (baudrate = MCK/6 = 24Mhz/6 = 4M baud
		(AT91C_SPI_BITS_8 & AT91C_SPI_BITS) |	// Bits per Transfer (8 bits)
		((0 << 3) & AT91C_SPI_CSAAT)		|	// CSAAT, Chip Select inactive after transfer
		((1 << 1) & AT91C_SPI_NCPHA)		|	// NCPHA, Clock Phase data captured on leading edge, changes on following edge
		((0 << 0) & AT91C_SPI_CPOL);			// CPOL, Clock Polarity inactive state is logic 0
}

static void FlashInit() {
	StartTicks();
	LED_A_ON();	
	FlashSetup();
	NCS_2_LOW;
	WaitUS(100);
	Dbprintf("FlashInit");
}
static void FlashStop(){
	NCS_2_HIGH;
	StopTicks();
	Dbprintf("FlashStop");
	LED_A_OFF();
	
	//* Reset all the Chip Select register
    AT91C_BASE_SPI->SPI_CSR[0] = 0;
//    AT91C_BASE_SPI->SPI_CSR[1] = 0;
//    AT91C_BASE_SPI->SPI_CSR[2] = 0;
//    AT91C_BASE_SPI->SPI_CSR[3] = 0;

    // Reset the SPI mode
    AT91C_BASE_SPI->SPI_MR = 0;

    // Disable all interrupts
    AT91C_BASE_SPI->SPI_IDR = 0xFFFFFFFF;
	
	// SPI disable
	AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIDIS;
}

// The chip select lines used when sending data.
// These values are loaded into the SPI Transmit Data Register (TDR) when sending data.
/*
static const U32 SPI_TXRX_CS0 = BIT19 | BIT18 | BIT17        ;
static const U32 SPI_TXRX_CS1 = BIT19 | BIT18 |         BIT16;
static const U32 SPI_TXRX_CS2 = BIT19 |         BIT17 | BIT16;
static const U32 SPI_TXRX_CS3 =         BIT18 | BIT17 | BIT16;
*/
/*
Fixed = you manage the CS lines
Variable = SPI module manages the CS lines
const UINT32 PCS_CS2 = 0x00030000;
const UINT32 PCS_LASTTXFER = 0x01000000;
UINT32 temp;
temp = dataToSend;
temp |= PCS_CS2;
if(lastByte == true)
{
    temp |= PCS_LASTTXFER;
}
SPI_TDR = temp;
*/
// 1.  variable chip select (PS=1)  ChipSelect number is written to TDR in EVERY transfer
// 2.  fixed chip select (PS=0), 

static uint8_t FlashSend(uint16_t data) {	

	// wait for the transfer to complete
	while ((AT91C_BASE_SPI->SPI_SR & AT91C_SPI_TXEMPTY) == 0) {};

	// send data
	AT91C_BASE_SPI->SPI_TDR = data;
	
	// wait for the recieving data
	while (!(AT91C_BASE_SPI->SPI_SR & AT91C_SPI_RDRF)) {}; 
	
	//return MISO_VALUE;
	return  AT91C_BASE_SPI->SPI_RDR & 0xFF;
	
/*	
	
	SCK_LOW;
	NCS_2_LOW;

	for (uint8_t i = 0; i < 8; i++) {
		SCK_LOW;
		WaitUS(2);

		if (data & 0x80) {
			MOSI_HIGH;
		} else {
			MOSI_LOW;
			WaitUS(2);
		}
		data <<= 1;
		SCK_HIGH;
		tmp = tmp << 1 | MISO_VALUE;
	}
	SCK_LOW;
	return tmp;
	*/
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

	// Manufacture ID / device ID
	uint8_t t0 = FlashSend(ID);
    uint8_t t1 = FlashSend(0x00);
    uint8_t t2 = FlashSend(0x00);
    uint8_t t3 = FlashSend(0x00);

	uint8_t man_id = MISO_VALUE;
	uint8_t dev_id = MISO_VALUE;
	
	Dbprintf(" [%02x] %02x %02x %02x | %02x  %02x", t0,t1,t2,t3, man_id, dev_id);


	//WINBOND_MANID
	if ( man_id == WINBOND_MANID ) {
		Dbprintf("Correct read of Manucaturer ID [%02x] == %02x", man_id, WINBOND_MANID);
	}
	if ( dev_id > 0) {
		Dbprintf("Got a device ID [%02x] == %02x  ( 0x11 0x30 0x12", dev_id,  WINBOND_DEVID);
	}

	uint8_t foo[8];
	// Read unique ID number  UNIQUE_ID (0x4B)
	FlashSend(UNIQUE_ID);
    FlashSend(0x00);
    FlashSend(0x00);
    FlashSend(0x00);
	FlashSend(0x00);
	for (int i = 0; i< sizeof(foo); i++) {
		foo[i] = MISO_VALUE;
	}
	
	NCS_2_HIGH;
	return 0;
}

void EXFLASH_TEST(void) {
	//uint8_t a[3] = {0x00,0x00,0x00};
	//uint8_t b[3] = {0x00,0x01,0x02};
	//uint8_t d = 0;

	FlashInit();

	FlashWrite_Enable();
	
	Flash_ReadID();
	
	//Dbprintf("Flash test write:  012 to 0x00 0x01 0x02");
	//EXFLASH_Program(a, b, sizeof(b));

	//d = FlashRead(a, sizeof(a));
	//Dbprintf("%02x | %02x %02x %02x", d, a[0], a[1], a[2]);

	FlashStop();
	cmd_send(CMD_ACK, 1, 0, 0, 0,0);
}

//  IO  spi write or read
uint8_t EXFLASH_spi_write_read(uint8_t wData) {	
	uint8_t tmp = 0;
	SCK_LOW;
	NCS_2_LOW;

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
	NCS_2_HIGH;
	return stat1;
}

uint8_t EXFLASH_readStat2(void) {
	uint8_t stat2;
	EXFLASH_spi_write_read(READSTAT2);
	stat2 = EXFLASH_spi_write_read(0xFF);
	NCS_2_HIGH;
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
	NCS_2_HIGH;
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
	NCS_2_HIGH;
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

	NCS_2_HIGH;
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

	NCS_2_HIGH;
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
	NCS_2_HIGH;
	return true;
}

bool EXFLASH_Reset(void) {
	LED_A_ON();
	SetupSpi(SPI_MEM_MODE);

	NCS_2_LOW;
		
	if (!EXFLASH_NOTBUSY()) {
		LED_A_OFF();
		Dbprintf("[!] init reset failed");
		return false;
	}
	
	EXFLASH_spi_write_read(ENABLE_RESET);
	NCS_2_HIGH;
	EXFLASH_spi_write_read(RESET);
	NCS_2_HIGH;
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