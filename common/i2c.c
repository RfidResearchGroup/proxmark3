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

#define GPIO_RST AT91C_PIO_PA1
#define GPIO_SCL AT91C_PIO_PA5
#define GPIO_SDA AT91C_PIO_PA7

#define SCL_H    HIGH(GPIO_SCL)
#define SCL_L    LOW(GPIO_SCL)
#define SDA_H    HIGH(GPIO_SDA)
#define SDA_L    LOW(GPIO_SDA)

#define SCL_read (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SCL)
#define SDA_read (AT91C_BASE_PIOA->PIO_PDSR & GPIO_SDA)

#define I2C_ERROR  "I2C_WaitAck Error"

volatile unsigned long c;

// Direct use the loop to delay. 6 instructions loop, Masterclock 48Mhz,
// delay=1 is about 200kbps
// timer.
// I2CSpinDelayClk(4) = 12.31us
// I2CSpinDelayClk(1) = 3.07us
void __attribute__((optimize("O0"))) I2CSpinDelayClk(uint16_t delay) {
    for (c = delay * 2; c; c--) {};
}

#define I2C_DELAY_1CLK    I2CSpinDelayClk(1)
#define I2C_DELAY_2CLK    I2CSpinDelayClk(2)
#define I2C_DELAY_XCLK(x) I2CSpinDelayClk((x))

#define  ISO7618_MAX_FRAME 255

// try i2c bus recovery at 100kHz = 5uS high, 5uS low
void I2C_recovery(void) {

    DbpString("Performing i2c bus recovery");

    // reset I2C
    SDA_H;
    SCL_H;

    //9nth cycle acts as NACK
    for (int i = 0; i < 10; i++)  {
        SCL_H;
        WaitUS(5);
        SCL_L;
        WaitUS(5);
    }

    //a STOP signal (SDA from low to high while CLK is high)
    SDA_L;
    WaitUS(5);
    SCL_H;
    WaitUS(2);
    SDA_H;
    WaitUS(2);

    bool isok = (SCL_read && SDA_read);
    if (!SDA_read)
        DbpString("I2C bus recovery  error: SDA still LOW");
    if (!SCL_read)
        DbpString("I2C bus recovery  error: SCL still LOW");
    if (isok)
        DbpString("I2C bus recovery complete");
}

void I2C_init(void) {
    // Configure reset pin, close up pull up, push-pull output, default high
    AT91C_BASE_PIOA->PIO_PPUDR = GPIO_RST;
    AT91C_BASE_PIOA->PIO_MDDR = GPIO_RST;

    // Configure I2C pin, open up, open leakage
    AT91C_BASE_PIOA->PIO_PPUER |= (GPIO_SCL | GPIO_SDA);
    AT91C_BASE_PIOA->PIO_MDER |= (GPIO_SCL | GPIO_SDA);

    // default three lines all pull up
    AT91C_BASE_PIOA->PIO_SODR |= (GPIO_SCL | GPIO_SDA | GPIO_RST);

    AT91C_BASE_PIOA->PIO_OER |= (GPIO_SCL | GPIO_SDA | GPIO_RST);
    AT91C_BASE_PIOA->PIO_PER |= (GPIO_SCL | GPIO_SDA | GPIO_RST);

    bool isok = (SCL_read && SDA_read);
    if (!isok)
        I2C_recovery();
}

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

// Reset the SIM_Adapter, then  enter the main program
// Note: the SIM_Adapter will not enter the main program after power up. Please run this function before use SIM_Adapter.
void I2C_Reset_EnterMainProgram(void) {
    StartTicks();
    I2C_init();
    I2C_SetResetStatus(0, 0, 0);
    WaitMS(30);
    I2C_SetResetStatus(1, 0, 0);
    WaitMS(30);
    I2C_SetResetStatus(1, 1, 1);
    WaitMS(10);
}

// Reset the SIM_Adapter, then enter the bootloader program
// Reserve for firmware update.
void I2C_Reset_EnterBootloader(void) {
    StartTicks();
    I2C_init();
    I2C_SetResetStatus(0, 1, 1);
    WaitMS(100);
    I2C_SetResetStatus(1, 1, 1);
    WaitMS(10);
}

// Wait for the clock to go High.
bool WaitSCL_H_delay(uint32_t delay) {
    while (delay--) {
        if (SCL_read) {
            return true;
        }
        I2C_DELAY_1CLK;
    }
    return false;
}

// 5000 * 3.07us = 15350us. 15.35ms
// 15000 * 3.07us = 46050us. 46.05ms
bool WaitSCL_H(void) {
    return WaitSCL_H_delay(15000);
}

bool WaitSCL_L_delay(uint32_t delay) {
    while (delay--) {
        if (!SCL_read) {
            return true;
        }
        I2C_DELAY_1CLK;
    }
    return false;
}
// 5000 * 3.07us = 15350us. 15.35ms
bool WaitSCL_L(void) {
    return WaitSCL_L_delay(15000);
}

// Wait max 1800ms or until SCL goes LOW.
// It timeout reading response from card
// Which ever comes first
bool WaitSCL_L_timeout(void) {
    volatile uint16_t delay = 1800;
    while (delay--) {
        // exit on SCL LOW
        if (!SCL_read)
            return true;

        WaitMS(1);
    }
    return (delay == 0);
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

    SDA_L;
    I2C_DELAY_2CLK;
    return true;
}

bool I2C_WaitForSim() {

    // wait for data from card
    if (!WaitSCL_L_timeout())
        return false;

    // 8051 speaks with smart card.
    // 1000*50*3.07 = 153.5ms
    // 1byte transfer == 1ms  with max frame being 256bytes
    if (!WaitSCL_H_delay(10 * 1000 * 50))
        return false;

    return true;
}

// send i2c STOP
void I2C_Stop(void) {
    SCL_L;
    I2C_DELAY_2CLK;
    SDA_L;
    I2C_DELAY_2CLK;
    SCL_H;
    I2C_DELAY_2CLK;
    if (!WaitSCL_H()) return;
    SDA_H;
    I2C_DELAY_XCLK(8);
}

// Send i2c ACK
void I2C_Ack(void) {
    SCL_L;
    I2C_DELAY_2CLK;
    SDA_L;
    I2C_DELAY_2CLK;
    SCL_H;
    I2C_DELAY_2CLK;
    if (!WaitSCL_H()) return;
    SCL_L;
    I2C_DELAY_2CLK;
}

// Send i2c NACK
void I2C_NoAck(void) {
    SCL_L;
    I2C_DELAY_2CLK;
    SDA_H;
    I2C_DELAY_2CLK;
    SCL_H;
    I2C_DELAY_2CLK;
    if (!WaitSCL_H()) return;
    SCL_L;
    I2C_DELAY_2CLK;
}

bool I2C_WaitAck(void) {
    SCL_L;
    I2C_DELAY_1CLK;
    SDA_H;
    I2C_DELAY_1CLK;
    SCL_H;
    if (!WaitSCL_H())
        return false;

    I2C_DELAY_2CLK;
    I2C_DELAY_2CLK;
    if (SDA_read) {
        SCL_L;
        return false;
    }
    SCL_L;
    return true;
}

void I2C_SendByte(uint8_t data) {
    uint8_t bits = 8;

    while (bits--) {
        SCL_L;

        I2C_DELAY_1CLK;

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

int16_t I2C_ReadByte(void) {
    uint8_t bits = 8, b = 0;

    SDA_H;
    while (bits--) {
        b <<= 1;
        SCL_L;
        if (!WaitSCL_L()) return -2;

        I2C_DELAY_1CLK;

        SCL_H;
        if (!WaitSCL_H()) return -1;

        I2C_DELAY_1CLK;
        if (SDA_read)
            b |= 0x01;
    }
    SCL_L;
    return b;
}

// Sends one byte  ( command to be written, SlaveDevice address)
bool I2C_WriteCmd(uint8_t device_cmd, uint8_t device_address) {
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

        bBreak = false;
    } while (false);

    I2C_Stop();
    if (bBreak) {
        if (DBGLEVEL > 3) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

// Sends 1 byte data (Data to be written, command to be written , SlaveDevice address  ).
bool I2C_WriteByte(uint8_t data, uint8_t device_cmd, uint8_t device_address) {
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

        I2C_SendByte(data);
        if (!I2C_WaitAck())
            break;

        bBreak = false;
    } while (false);

    I2C_Stop();
    if (bBreak) {
        if (DBGLEVEL > 3) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

//Sends array of data (Array, length, command to be written , SlaveDevice address  ).
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
    if (bBreak) {
        if (DBGLEVEL > 3) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

// read one array of data (Data array, Readout length, command to be written , SlaveDevice address  ).
// len = uint8 (max buffer to read 256bytes)
int16_t I2C_BufferRead(uint8_t *data, uint8_t len, uint8_t device_cmd, uint8_t device_address) {

    if (!data || len == 0)
        return 0;

    // extra wait  500us (514us measured)
    // 200us  (xx measured)
    WaitUS(600);
    bool bBreak = true;
    uint16_t readcount = 0;

    do {
        if (!I2C_Start())
            return 0;

        // 0xB0 / 0xC0  == i2c write
        I2C_SendByte(device_address & 0xFE);
        if (!I2C_WaitAck())
            break;

        I2C_SendByte(device_cmd);
        if (!I2C_WaitAck())
            break;

        // 0xB1 / 0xC1 == i2c read
        I2C_Start();
        I2C_SendByte(device_address | 1);
        if (!I2C_WaitAck())
            break;

        bBreak = false;
    } while (false);

    if (bBreak) {
        I2C_Stop();
        if (DBGLEVEL > 3) DbpString(I2C_ERROR);
        return 0;
    }

    while (len) {

        int16_t tmp = I2C_ReadByte();
        if (tmp < 0)
            return tmp;

        *data = (uint8_t)tmp & 0xFF;

        len--;
        // 读取的第一个字节为后续长度
        // The first byte in response is the message length
        if (!readcount && (len > *data)) {
            len = *data;
        } else {
            data++;
        }
        readcount++;

        // acknowledgements. After last byte send NACK.
        if (len == 0)
            I2C_NoAck();
        else
            I2C_Ack();
    }

    I2C_Stop();

    // return bytecount - first byte (which is length byte)
    return --readcount;
}

int16_t I2C_ReadFW(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address) {
    //START, 0xB0, 0x00, 0x00, START, 0xB1, xx, yy, zz, ......, STOP
    bool bBreak = true;
    uint8_t readcount = 0;

    // sending
    do {
        if (!I2C_Start())
            return 0;

        // 0xB0 / 0xC0  i2c write
        I2C_SendByte(device_address & 0xFE);
        if (!I2C_WaitAck())
            break;

        I2C_SendByte(msb);
        if (!I2C_WaitAck())
            break;

        I2C_SendByte(lsb);
        if (!I2C_WaitAck())
            break;

        // 0xB1 / 0xC1  i2c read
        I2C_Start();
        I2C_SendByte(device_address | 1);
        if (!I2C_WaitAck())
            break;

        bBreak = false;
    } while (false);

    if (bBreak) {
        I2C_Stop();
        if (DBGLEVEL > 3) DbpString(I2C_ERROR);
        return 0;
    }

    // reading
    while (len) {

        int16_t tmp = I2C_ReadByte();
        if (tmp < 0)
            return tmp;

        *data = (uint8_t)tmp & 0xFF;

        data++;
        readcount++;
        len--;

        // acknowledgements. After last byte send NACK.
        if (len == 0)
            I2C_NoAck();
        else
            I2C_Ack();
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

        // 0xB0  == i2c write
        I2C_SendByte(device_address & 0xFE);
        if (!I2C_WaitAck())
            break;

        I2C_SendByte(msb);
        if (!I2C_WaitAck())
            break;

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
    if (bBreak) {
        if (DBGLEVEL > 3) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

void I2C_print_status(void) {
    DbpString(_BLUE_("Smart card module (ISO 7816)"));
    uint8_t maj, min;
    if (I2C_get_version(&maj, &min) == PM3_SUCCESS)
        Dbprintf("  version................." _YELLOW_("v%x.%02d"), maj, min);
    else
        DbpString("  version................." _RED_("FAILED"));
}

int I2C_get_version(uint8_t *maj, uint8_t *min) {
    uint8_t resp[] = {0, 0, 0, 0};
    I2C_Reset_EnterMainProgram();
    uint8_t len = I2C_BufferRead(resp, sizeof(resp), I2C_DEVICE_CMD_GETVERSION, I2C_DEVICE_ADDRESS_MAIN);
    if (len > 0) {
        *maj = resp[0];
        *min = resp[1];
        return PM3_SUCCESS;
    } else {
        return PM3_EDEVNOTSUPP;
    }
}

// Will read response from smart card module,  retries 3 times to get the data.
bool sc_rx_bytes(uint8_t *dest, uint8_t *destlen) {

    uint8_t i = 3;
    int16_t len = 0;
    while (i--) {

        I2C_WaitForSim();

        len = I2C_BufferRead(dest, *destlen, I2C_DEVICE_CMD_READ, I2C_DEVICE_ADDRESS_MAIN);

        if (len > 1) {
            break;
        } else if (len == 1) {
            continue;
        } else if (len <= 0) {
            return false;
        }
    }

    // after three
    if (len <= 1)
        return false;

    *destlen = (uint8_t)len & 0xFF;
    return true;
}

bool GetATR(smart_card_atr_t *card_ptr) {

    if (!card_ptr)
        return false;

    card_ptr->atr_len = 0;
    memset(card_ptr->atr, 0, sizeof(card_ptr->atr));


    // Send ATR
    // start [C0 01] stop start C1 len aa bb cc stop]
    I2C_WriteCmd(I2C_DEVICE_CMD_GENERATE_ATR, I2C_DEVICE_ADDRESS_MAIN);

    //wait for sim card to answer.
    // 1byte = 1ms ,  max frame 256bytes.  SHould wait 256ms atleast just in case.
    if (!I2C_WaitForSim())
        return false;

    // read bytes from module
    uint8_t len = sizeof(card_ptr->atr);
    if (!sc_rx_bytes(card_ptr->atr, &len))
        return false;

    uint8_t pos_td = 1;
    if ((card_ptr->atr[1] & 0x10) == 0x10) pos_td++;
    if ((card_ptr->atr[1] & 0x20) == 0x20) pos_td++;
    if ((card_ptr->atr[1] & 0x40) == 0x40) pos_td++;

    // T0 indicate presence T=0 vs T=1.  T=1 has checksum TCK
    if ((card_ptr->atr[1] & 0x80) == 0x80) {

        pos_td++;

        // 1 == T1 ,  presence of checksum TCK
        if ((card_ptr->atr[pos_td] & 0x01) == 0x01) {

            uint8_t chksum = 0;
            // xor property.  will be zero when xored with chksum.
            for (uint8_t i = 1; i < len; ++i)
                chksum ^= card_ptr->atr[i];

            if (chksum) {
                if (DBGLEVEL > 2) DbpString("Wrong ATR checksum");
            }
        }
    }

    card_ptr->atr_len = len;
    LogTrace(card_ptr->atr, card_ptr->atr_len, 0, 0, NULL, false);
    return true;
}

void SmartCardAtr(void) {
    smart_card_atr_t card;
    LED_D_ON();
    clear_trace();
    set_tracing(true);
    I2C_Reset_EnterMainProgram();
    bool isOK = GetATR(&card);
    reply_old(CMD_ACK, isOK, sizeof(smart_card_atr_t), 0, &card, sizeof(smart_card_atr_t));
    set_tracing(false);
    LEDsoff();
}

void SmartCardRaw(uint64_t arg0, uint64_t arg1, uint8_t *data) {

    LED_D_ON();

    uint8_t len = 0;
    uint8_t *resp = BigBuf_malloc(ISO7618_MAX_FRAME);
    smartcard_command_t flags = arg0;

    if ((flags & SC_CONNECT))
        clear_trace();

    set_tracing(true);

    if ((flags & SC_CONNECT)) {

        I2C_Reset_EnterMainProgram();

        if ((flags & SC_SELECT)) {
            smart_card_atr_t card;
            bool gotATR = GetATR(&card);
            //reply_old(CMD_ACK, gotATR, sizeof(smart_card_atr_t), 0, &card, sizeof(smart_card_atr_t));
            if (!gotATR)
                goto OUT;
        }
    }

    if ((flags & SC_RAW) || (flags & SC_RAW_T0)) {

        LogTrace(data, arg1, 0, 0, NULL, true);

        // Send raw bytes
        // asBytes = A0 A4 00 00 02
        // arg1 = len 5
        bool res = I2C_BufferWrite(data, arg1, ((flags & SC_RAW_T0) ? I2C_DEVICE_CMD_SEND_T0 : I2C_DEVICE_CMD_SEND), I2C_DEVICE_ADDRESS_MAIN);
        if (!res && DBGLEVEL > 3) DbpString(I2C_ERROR);

        // read bytes from module
        len = ISO7618_MAX_FRAME;
        res = sc_rx_bytes(resp, &len);
        if (res) {
            LogTrace(resp, len, 0, 0, NULL, false);
        } else {
            len = 0;
        }
    }
OUT:
    reply_old(CMD_ACK, len, 0, 0, resp, len);
    BigBuf_free();
    set_tracing(false);
    LEDsoff();
}

void SmartCardUpgrade(uint64_t arg0) {

    LED_C_ON();

#define I2C_BLOCK_SIZE 128
    // write.   Sector0,  with 11,22,33,44
    // erase is 128bytes, and takes 50ms to execute

    I2C_Reset_EnterBootloader();

    bool isOK = true;
    uint16_t length = arg0, pos = 0;
    uint8_t *fwdata = BigBuf_get_addr();
    uint8_t *verfiydata = BigBuf_malloc(I2C_BLOCK_SIZE);

    while (length) {

        uint8_t msb = (pos >> 8) & 0xFF;
        uint8_t lsb = pos & 0xFF;

        Dbprintf("FW %02X%02X", msb, lsb);

        size_t size = MIN(I2C_BLOCK_SIZE, length);

        // write
        int16_t res = I2C_WriteFW(fwdata + pos, size, msb, lsb, I2C_DEVICE_ADDRESS_BOOT);
        if (!res) {
            DbpString("Writing failed");
            isOK = false;
            break;
        }

        // writing takes time.
        WaitMS(50);

        // read
        res = I2C_ReadFW(verfiydata, size, msb, lsb, I2C_DEVICE_ADDRESS_BOOT);
        if (res <= 0) {
            DbpString("Reading back failed");
            isOK = false;
            break;
        }

        // cmp
        if (0 != memcmp(fwdata + pos, verfiydata, size)) {
            DbpString("not equal data");
            isOK = false;
            break;
        }

        length -= size;
        pos += size;
    }
    reply_old(CMD_ACK, isOK, pos, 0, 0, 0);
    LED_C_OFF();
    BigBuf_free();
}

void SmartCardSetBaud(uint64_t arg0) {
}

void SmartCardSetClock(uint64_t arg0) {
    LED_D_ON();
    set_tracing(true);
    I2C_Reset_EnterMainProgram();

    // Send SIM CLC
    // start [C0 05 xx] stop
    I2C_WriteByte(arg0, I2C_DEVICE_CMD_SIM_CLC, I2C_DEVICE_ADDRESS_MAIN);

    reply_old(CMD_ACK, 1, 0, 0, 0, 0);
    set_tracing(false);
    LEDsoff();
}
