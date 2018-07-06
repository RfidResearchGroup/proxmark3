//-----------------------------------------------------------------------------
// Willok, June 2018
// Edits by Iceman, July 2018
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// The main i2c code, for communications with smart card module
//-----------------------------------------------------------------------------
#include "i2c.h"

//	定义连接引脚
#define	GPIO_RST	AT91C_PIO_PA1
#define GPIO_SCL	AT91C_PIO_PA5
#define GPIO_SDA	AT91C_PIO_PA7

#define SCL_H		HIGH(GPIO_SCL)
#define SCL_L		LOW(GPIO_SCL)
#define SDA_H		HIGH(GPIO_SDA)
#define SDA_L		LOW(GPIO_SDA)

#define SCL_read	(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SCL)
#define SDA_read	(AT91C_BASE_PIOA->PIO_PDSR & GPIO_SDA)

#define I2C_ERROR  "I2C_WaitAck Error" 

volatile unsigned long c;

//	直接使用循环来延时，一个循环 6 条指令，48M， Delay=1 大概为 200kbps
//void I2CSpinDelayClk(uint16_t delay) ;
void __attribute__((optimize("O0"))) I2CSpinDelayClk(uint16_t delay) {
	for (c = delay * 2; c; c--) {};
}

/*
#define I2C_DELAY_1CLK 		I2CSpinDelayClk(1)
#define I2C_DELAY_2CLK		I2CSpinDelayClk(2)
#define I2C_DELAY_XCLK(x)	I2CSpinDelayClk((x))
*/																  
//	通讯延迟函数			ommunication delay function	
#define I2C_DELAY_1CLK 		I2C_DELAY_1()
#define I2C_DELAY_2CLK		I2C_DELAY_2()
#define I2C_DELAY_XCLK(x)	I2C_DELAY_X((x))
void I2C_DELAY_1(void) {	I2CSpinDelayClk(1);}
void I2C_DELAY_2(void) {	I2CSpinDelayClk(2);}
void I2C_DELAY_X(uint16_t delay) {	I2CSpinDelayClk(delay);}

void I2C_init(void) {
	// 配置复位引脚，关闭上拉，推挽输出，默认高
	// Configure reset pin, close up pull up, push-pull output, default high
	AT91C_BASE_PIOA->PIO_PPUDR = GPIO_RST;
	AT91C_BASE_PIOA->PIO_MDDR = GPIO_RST;
  
	// 配置 I2C 引脚，开启上拉，开漏输出
	// Configure I2C pin, open up, open leakage
	AT91C_BASE_PIOA->PIO_PPUER |= (GPIO_SCL | GPIO_SDA);	// 打开上拉  Open up the pull up
	AT91C_BASE_PIOA->PIO_MDER |= (GPIO_SCL | GPIO_SDA);

	// 默认三根线全部拉高
	// default three lines all pull up
	AT91C_BASE_PIOA->PIO_SODR |= (GPIO_SCL | GPIO_SDA | GPIO_RST);

	// 允许输出
	// allow output
	AT91C_BASE_PIOA->PIO_OER |= (GPIO_SCL | GPIO_SDA | GPIO_RST);
	AT91C_BASE_PIOA->PIO_PER |= (GPIO_SCL | GPIO_SDA | GPIO_RST);
}


// 设置复位状态
// set the reset state
void I2C_SetResetStatus(uint8_t LineRST, uint8_t LineSCK, uint8_t LineSDA) {
	if (LineRST)
		HIGH(GPIO_RST);
	else
		LOW(GPIO_RST);

	if (LineSCK)
		HIGH(GPIO_SCL);
	else
		LOW(GPIO_SCL);

	if (LineSDA)
		HIGH(GPIO_SDA);
	else
		LOW(GPIO_SDA);
}

// 复位进入主程序
// Reset the SIM_Adapter, then  enter the main program
// Note: the SIM_Adapter will not enter the main program after power up. Please run this function before use SIM_Adapter.
void I2C_Reset_EnterMainProgram(void) {
	I2C_SetResetStatus(0, 0, 0);		//	拉低复位线
	SpinDelay(30);
	I2C_SetResetStatus(1, 0, 0);		//	解除复位
	SpinDelay(30);
	I2C_SetResetStatus(1, 1, 1);		//	拉高数据线
	SpinDelay(10);
}

// 复位进入引导模式
// Reset the SIM_Adapter, then enter the bootloader program
// Reserve：For firmware update.
void I2C_Reset_EnterBootloader(void) {
	I2C_SetResetStatus(0, 1, 1);		//	拉低复位线
	SpinDelay(100);
	I2C_SetResetStatus(1, 1, 1);		//	解除复位
	SpinDelay(10);
}

//	等待时钟变高	
// Wait for the clock to go High.	
bool WaitSCL_H(void) {

	volatile uint16_t count = 50000;

	while (count--)	{
		if (SCL_read) {
			return true;
		}
		I2C_DELAY_1CLK;
	}
	return false;
}

bool I2C_Start(void) {
	
	I2C_DELAY_XCLK(4);
	SDA_H;
	I2C_DELAY_1CLK;
	SCL_H;
	
	if (!WaitSCL_H()) return false;

	I2C_DELAY_2CLK;
	
	if (!SCL_read) return false;
	if (!SDA_read) return false;

	SDA_L; I2C_DELAY_2CLK;
	return true;
}

// send i2c STOP
void I2C_Stop(void) {
	SCL_L; I2C_DELAY_2CLK;
	SDA_L; I2C_DELAY_2CLK;
	SCL_H; I2C_DELAY_2CLK;
	SDA_H;
	I2C_DELAY_2CLK;
	I2C_DELAY_2CLK;
	I2C_DELAY_2CLK;
	I2C_DELAY_2CLK;
}
// Send i2c ACK
void I2C_Ack(void) {
	SCL_L; I2C_DELAY_2CLK;
	SDA_L; I2C_DELAY_2CLK;
	SCL_H; I2C_DELAY_2CLK;
	SCL_L; I2C_DELAY_2CLK;
}

// Send i2c NACK
void I2C_NoAck(void) {
	SCL_L; I2C_DELAY_2CLK;
	SDA_H; I2C_DELAY_2CLK;
	SCL_H; I2C_DELAY_2CLK;
	SCL_L; I2C_DELAY_2CLK;
}

bool I2C_WaitAck(void) {
	SCL_L; I2C_DELAY_1CLK;
	SDA_H; I2C_DELAY_1CLK;
	SCL_H;
	if (!WaitSCL_H())
		return false;

	I2C_DELAY_2CLK;
	if (SDA_read) {
		SCL_L;
		return false;
	}
	SCL_L;
	return true;
}

void I2C_SendByte(uint8_t data)	{
	uint8_t i = 8;

	while (i--) {
		SCL_L; I2C_DELAY_1CLK;
		
		if (data & 0x80)
			SDA_H;
		else
			SDA_L;
		
		data <<= 1;
		I2C_DELAY_1CLK;

		SCL_H;
		if (!WaitSCL_H())
			return;

		I2C_DELAY_2CLK;
	}
	SCL_L;
}

uint8_t I2C_ReadByte(void) {
	uint8_t i = 8, b = 0;

	SDA_H;
	while (i--)	{
		b <<= 1;
		SCL_L; I2C_DELAY_2CLK;
		SCL_H;
		if (!WaitSCL_H())
			return 0;

		I2C_DELAY_2CLK;
		if (SDA_read)
			b |= 0x01;
	}
	SCL_L;
	return b;
}

// Sends one byte  ( command to be written, slavedevice address)
bool I2C_WriteCmd(uint8_t device_cmd, uint8_t device_address) {
	bool bBreak = true;
	do 	{
		if (!I2C_Start())
			return false;

		I2C_SendByte(device_address & 0xFE);
		if (!I2C_WaitAck())
			break;

		I2C_SendByte(device_cmd);
		if (!I2C_WaitAck())
			break;

		bBreak = false;
	} while (false);

	I2C_Stop();
	if (bBreak)	{
		if ( MF_DBGLEVEL > 3 ) DbpString(I2C_ERROR);
		return false;
	}
	return true;
}

// 写入1字节数据 （待写入数据，待写入地址，器件类型）
// Sends 1 byte data (Data to be written,command to be written , SlaveDevice address  ).
bool I2C_WriteByte(uint8_t data, uint8_t device_cmd, uint8_t device_address) {
	bool bBreak = true;
	do 	{
		if (!I2C_Start())
			return false;

		I2C_SendByte(device_address & 0xFE);
		if (!I2C_WaitAck())
			break;

		I2C_SendByte(device_cmd);
		if (!I2C_WaitAck())
			break;

		I2C_SendByte(data);
		if (!I2C_WaitAck())
			break;

		bBreak = false;
	} while (false);

	I2C_Stop();
	if (bBreak)	{
		if ( MF_DBGLEVEL > 3 ) DbpString(I2C_ERROR);
		return false;
	}
	return true;
}


//	写入1串数据（待写入数组地址，待写入长度，待写入地址，器件类型）	
//Sends a string of data (Array address, length, command to be written , SlaveDevice address  ).
// len = uint8 (max buffer to write 256bytes)
bool I2C_BufferWrite(uint8_t *data, uint8_t len, uint8_t device_cmd, uint8_t device_address) {
	bool bBreak = true;

	do {
		if (!I2C_Start())
			return false;

		I2C_SendByte(device_address & 0xFE);

		if (!I2C_WaitAck())
			break;

		I2C_SendByte(device_cmd);
		if (!I2C_WaitAck())
			break;

		while (len) {
			
			I2C_SendByte(*data);
			if (!I2C_WaitAck())
				break;

			len--;
			data++;		
		}

		if (len == 0)
			bBreak = false;
	} while (false);

	I2C_Stop();
	if (bBreak)	{
		if ( MF_DBGLEVEL > 3 ) DbpString(I2C_ERROR);
		return false;
	}
	return true;	
}

// 读出1串数据（存放读出数据，待读出长度，带读出地址，器件类型）
// read 1 strings of data (Data storage array, Readout length, command to be written , SlaveDevice address  ).
// len = uint8 (max buffer to read 256bytes)
uint8_t I2C_BufferRead(uint8_t *data, uint8_t len, uint8_t device_cmd, uint8_t device_address) {
	bool bBreak = true;
	uint8_t	readcount = 0;

	// sending
	do {
		if (!I2C_Start())
			return 0;

		// 0xB0 or 0xC0  i2c write
		I2C_SendByte(device_address & 0xFE);
		if (!I2C_WaitAck())
			break;

		I2C_SendByte(device_cmd);
		if (!I2C_WaitAck())
			break;

		// 0xB1 or 0xC1 read
		I2C_Start();
		
		I2C_SendByte(device_address | 1);
		if (!I2C_WaitAck())
			break;

		bBreak = false;
	} while (false);

	if (bBreak)	{
		I2C_Stop();
		if ( MF_DBGLEVEL > 3 ) DbpString(I2C_ERROR);
		return 0;
	}

	// reading
	while (len) {
		len--;
		*data = I2C_ReadByte();
		// 读取的第一个字节为后续长度	
		// The first byte read is the message length
		if (!readcount && (len > *data))
			len = *data;

		if (len == 0)
			I2C_NoAck();
		else
			I2C_Ack();

		data++;
		readcount++;
	}
	
	I2C_Stop();
	return readcount;
}

uint8_t I2C_ReadFW(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address) {
	//START, 0xB0, 0x00, 0x00, START, 0xB1, xx, yy, zz, ......, STOP	
	bool bBreak = true;
	uint8_t	readcount = 0;

	// sending
	do {
		if (!I2C_Start())
			return 0;

		// 0xB0 or 0xC0  i2c write
		I2C_SendByte(device_address & 0xFE);
		if (!I2C_WaitAck())
			break;

		// msb
		I2C_SendByte(msb);
		if (!I2C_WaitAck())
			break;

		// lsb
		I2C_SendByte(lsb);
		if (!I2C_WaitAck())
			break;
		
		// 0xB1 or 0xC1 read
		I2C_Start();
		I2C_SendByte(device_address | 1);
		if (!I2C_WaitAck())
			break;

		bBreak = false;
	} while (false);

	if (bBreak)	{
		I2C_Stop();
		if ( MF_DBGLEVEL > 3 ) DbpString(I2C_ERROR);
		return 0;
	}

	// reading
	while (len) {
		len--;
		*data = I2C_ReadByte();

		if (len == 0)
			I2C_NoAck();
		else
			I2C_Ack();

		data++;
		readcount++;
	}
	
	I2C_Stop();
	return readcount;
}

bool I2C_WriteFW(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address) {
	//START, 0xB0, 0x00, 0x00, xx, yy, zz, ......, STOP	
	bool bBreak = true;

	do {
		if (!I2C_Start())
			return false;

		// 0xB0
		I2C_SendByte(device_address & 0xFE);
		if (!I2C_WaitAck())
			break;
		
		// msb
		I2C_SendByte(msb);
		if (!I2C_WaitAck())
			break;

		// lsb
		I2C_SendByte(lsb);
		if (!I2C_WaitAck())
			break;

		while (len) {
			I2C_SendByte(*data);
			if (!I2C_WaitAck())
				break;

			len--;
			data++;		
		}

		if (len == 0)
			bBreak = false;
	} while (false);

	I2C_Stop();
	if (bBreak)	{
		if ( MF_DBGLEVEL > 3 ) DbpString(I2C_ERROR);
		return false;
	}
	return true;	
}

void I2C_print_status(void) {
	I2C_init();
	I2C_Reset_EnterMainProgram();
	uint8_t resp[4] = {0};
	uint8_t len = I2C_BufferRead(resp, 4, I2C_DEVICE_CMD_GETVERSION, I2C_DEVICE_ADDRESS_MAIN);
	DbpString("Smart card module (ISO 7816)");
	if ( len )
		Dbprintf("  FW version................v%x.%02x", resp[1], resp[2]);
	else
		DbpString("  FW version................FAILED");
}

#define WAIT_SCL_MAX_300
#define WAIT_UNTIL_SCL_GOES_HIGH	while (!SCL_read) { I2C_DELAY_1CLK;	}
bool WaitSCL_300(void){
	volatile uint16_t delay = 300;
	while ( SCL_read || delay ) {
		SpinDelay(1);
		delay--;
	}	
	return (delay == 0);
}

bool GetATR(smart_card_atr_t *card_ptr) {
	
	if ( card_ptr ) {
		card_ptr->atr_len = 0;
		memset(card_ptr->atr, 0, sizeof(card_ptr->atr));
	}
	
	// Send ATR
	// start [C0 01] stop
	I2C_WriteCmd(I2C_DEVICE_CMD_GENERATE_ATR, I2C_DEVICE_ADDRESS_MAIN);

	// variable delay here.
	if (!WaitSCL_300()) 
		return false;

	// 8051 speaks with smart card.
	WAIT_UNTIL_SCL_GOES_HIGH;

	// start [C0 03 start C1 len aa bb cc stop]
	uint8_t len = I2C_BufferRead(card_ptr->atr, sizeof(card_ptr->atr), I2C_DEVICE_CMD_READ, I2C_DEVICE_ADDRESS_MAIN);
	
	// remove length byte from the read bytes.
	if ( card_ptr )
		card_ptr->atr_len = len - 1;
	
	return true;
}

void SmartCardAtr(void) {

	smart_card_atr_t card;
	
	I2C_Reset_EnterMainProgram();
	
	bool isOK = GetATR( &card );
	if ( isOK )
		Dbhexdump(card.atr_len, card.atr, false);

	cmd_send(CMD_ACK, isOK, sizeof(smart_card_atr_t), 0, &card, sizeof(smart_card_atr_t));
}

void SmartCardRaw( uint64_t arg0, uint64_t arg1, uint8_t *data ) {
	#define  ISO7618_MAX_FRAME 255
	I2C_Reset_EnterMainProgram();

	uint8_t len = 0;
	uint8_t *resp =  BigBuf_malloc(ISO7618_MAX_FRAME);
	
	smart_card_atr_t card;

	bool isOK = GetATR( &card );
	if ( !isOK )
		goto out;
	
	// Send raw bytes
	// start [C0 02] A0 A4 00 00 02 stop
	// asBytes = A0 A4 00 00 02
	// arg0 = len 5
	I2C_BufferWrite(data, arg1, I2C_DEVICE_CMD_SEND, I2C_DEVICE_ADDRESS_MAIN);
	
	// read response
	// start [C0 03 start C1 len aa bb cc stop]
	len = I2C_BufferRead(resp, ISO7618_MAX_FRAME, I2C_DEVICE_CMD_READ, I2C_DEVICE_ADDRESS_MAIN);
	
out:	
	cmd_send(CMD_ACK, isOK, len, 0, resp, len);
}

void SmartCardUpgrade(uint64_t arg0) {
#define I2C_BLOCK_SIZE 128
// write.   Sector0,  with 11,22,33,44
// erase is 128bytes, and takes 50ms to execute
			
	I2C_Reset_EnterBootloader();	

	bool isOK = true;
	uint8_t res = 0;
	uint16_t length = arg0;
	uint16_t pos = 0;
	uint8_t *fwdata = BigBuf_get_addr();
	uint8_t *verfiydata = BigBuf_malloc(I2C_BLOCK_SIZE);
	
	while (length) {
		
		uint8_t msb = (pos >> 8) & 0xFF;
		uint8_t lsb = pos & 0xFF;
		
		Dbprintf("FW %02X %02X", msb, lsb);

		size_t size = MIN(I2C_BLOCK_SIZE, length);
		
		// write
		res = I2C_WriteFW(fwdata+pos, size, msb, lsb, I2C_DEVICE_ADDRESS_BOOT);
		if ( !res ) {
			Dbprintf("Writing failed");
			isOK = false;
			break;
		}
		
		// writing takes time.
		SpinDelay(50);

		// read
		res = I2C_ReadFW(verfiydata, size, msb, lsb, I2C_DEVICE_ADDRESS_BOOT);
		if ( res == 0) {
			Dbprintf("Reading back failed");
			isOK = false;					
			break;
		}
		
		// cmp
		if ( 0 != memcmp(fwdata+pos, verfiydata, size)) {
			Dbprintf("not equal data");
			isOK = false;					
			break;
		}
				
		length -= size;
		pos += size;
	}			
	cmd_send(CMD_ACK, isOK, pos, 0, 0, 0);
}

void SmartCardSetBaud(uint64_t arg0) {
	I2C_Reset_EnterMainProgram();	
	
	bool isOK = true;
	//uint16_t baud = arg0;
	// Send SET BAUD
	// start [C0 04] stop
	//I2C_WriteByte(0x00, I2C_DEVICE_CMD_SETBAUD, I2C_DEVICE_ADDRESS_MAIN);
	
	cmd_send(CMD_ACK, isOK, 0, 0, 0, 0);
}

void SmartCardSetClock(uint64_t arg0) {

	I2C_Reset_EnterMainProgram();	
	
	bool isOK = true;
	//uint16_t clockrate = arg0;
	// Send SIM CLC
	// start [C0 04] stop
	//I2C_WriteByte(0x00, I2C_DEVICE_CMD_SIM_CLC, I2C_DEVICE_ADDRESS_MAIN);
				
	cmd_send(CMD_ACK, isOK, 0, 0, 0, 0);
}