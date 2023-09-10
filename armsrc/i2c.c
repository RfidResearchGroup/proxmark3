//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// The main i2c code, for communications with smart card module
//-----------------------------------------------------------------------------
#include "i2c.h"

#include "proxmark3_arm.h"
#include "cmd.h"
#include "BigBuf.h"
#include "ticks.h"
#include "dbprint.h"
#include "util.h"
#include "string.h"

#define GPIO_RST AT91C_PIO_PA1
#define GPIO_SCL AT91C_PIO_PA5
#define GPIO_SDA AT91C_PIO_PA7

#define SCL_H    HIGH(GPIO_SCL)
#define SCL_L    LOW(GPIO_SCL)
#define SDA_H    HIGH(GPIO_SDA)
#define SDA_L    LOW(GPIO_SDA)

#define SCL_read ((AT91C_BASE_PIOA->PIO_PDSR & GPIO_SCL) == GPIO_SCL)
#define SDA_read ((AT91C_BASE_PIOA->PIO_PDSR & GPIO_SDA) == GPIO_SDA)

#define I2C_ERROR  "I2C_WaitAck Error"

// Direct use the loop to delay. 6 instructions loop, Masterclock 48MHz,
// delay=1 is about 200kbps
// timer.
// I2CSpinDelayClk(4) = 12.31us
// I2CSpinDelayClk(1) = 3.07us
static volatile uint32_t c;
static void __attribute__((optimize("O0"))) I2CSpinDelayClk(uint16_t delay) {
    for (c = delay * 2; c; c--) {};
}

#define I2C_DELAY_1CLK    I2CSpinDelayClk(1)
#define I2C_DELAY_2CLK    I2CSpinDelayClk(2)
#define I2C_DELAY_XCLK(x) I2CSpinDelayClk((x))

// The SIM module v4 supports up to 384 bytes for the length.
#define  ISO7816_MAX_FRAME 270

// try i2c bus recovery at 100kHz = 5us high, 5us low
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

void I2C_init(bool has_ticks) {
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

    if (has_ticks) {
        WaitMS(2);
    }

    bool isok = (SCL_read && SDA_read);
    if (isok == false)
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
    I2C_init(true);
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
    I2C_init(true);
    I2C_SetResetStatus(0, 1, 1);
    WaitMS(100);
    I2C_SetResetStatus(1, 1, 1);
    WaitMS(10);
}

// Wait for the clock to go High.
static bool WaitSCL_H_delay(uint32_t delay) {
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
static bool WaitSCL_H(void) {
    return WaitSCL_H_delay(5000);
}

static bool WaitSCL_L_delay(uint32_t delay) {
    while (delay--) {
        if (!SCL_read) {
            return true;
        }
        I2C_DELAY_1CLK;
    }
    return false;
}

// 5000 * 3.07us = 15350us. 15.35ms
// 15000 * 3.07us = 46050us. 46.05ms
static bool WaitSCL_L(void) {
    return WaitSCL_L_delay(5000);
}

// Wait max 1800ms or until SCL goes LOW.
// It timeout reading response from card
// Which ever comes first
static bool WaitSCL_L_timeout(void) {
    volatile uint32_t delay = 200;
    while (delay--) {
        // exit on SCL LOW
        if (SCL_read == false)
            return true;

        WaitMS(1);
    }
    return (delay == 0);
}

static bool I2C_Start(void) {

    I2C_DELAY_2CLK;
    I2C_DELAY_2CLK;
    SDA_H;
    I2C_DELAY_1CLK;
    SCL_H;
    if (!WaitSCL_H())
        return false;

    I2C_DELAY_2CLK;

    if (!SCL_read)
        return false;
    if (!SDA_read)
        return false;

    SDA_L;
    I2C_DELAY_2CLK;
    return true;
}

static bool I2C_WaitForSim(void) {

    // wait for data from card
    if (!WaitSCL_L_timeout())
        return false;

    // 8051 speaks with smart card.
    // 1000*50*3.07 = 153.5ms
    // 1000*110*3.07 = 337.7ms
    // 1byte transfer == 1ms with max frame being 256bytes
    return WaitSCL_H_delay(1000 * 110);
}

// send i2c STOP
static void I2C_Stop(void) {
    SCL_L;
    I2C_DELAY_2CLK;
    SDA_L;
    I2C_DELAY_2CLK;
    SCL_H;
    I2C_DELAY_2CLK;
    if (!WaitSCL_H()) return;
    SDA_H;
    I2C_DELAY_2CLK;
    I2C_DELAY_2CLK;
    I2C_DELAY_2CLK;
    I2C_DELAY_2CLK;
}

// Send i2c ACK
static void I2C_Ack(void) {
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
static void I2C_NoAck(void) {
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

static bool I2C_WaitAck(void) {
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

static void I2C_SendByte(uint8_t data) {
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

static int16_t I2C_ReadByte(void) {
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
        if (g_dbglevel > 3) DbpString(I2C_ERROR);
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
        if (g_dbglevel > 3) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

//Sends array of data (Array, length, command to be written , SlaveDevice address  ).
// len = uint16 because we need to write up to 256 bytes
bool I2C_BufferWrite(const uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address) {
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
        if (g_dbglevel > 3) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

// read one array of data (Data array, Readout length, command to be written , SlaveDevice address  ).
// len = uint16 because we need to read up to 256bytes
int16_t I2C_BufferRead(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address) {

    if (!data || len == 0)
        return 0;

    // extra wait  500us (514us measured)
    // 200us  (xx measured)
    WaitUS(600);

    bool bBreak = true;
    uint16_t readcount = 0;
    uint16_t recv_len = 0;

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
        if (g_dbglevel > 3) DbpString(I2C_ERROR);
        return 0;
    }

    while (len) {

        int16_t tmp = I2C_ReadByte();
        if (tmp < 0)
            return tmp;

        *data = (uint8_t)tmp & 0xFF;

        len--;

        // Starting firmware v4 the length is encoded on the first two bytes.
        // This only applies if command is I2C_DEVICE_CMD_READ.
        if (device_cmd == I2C_DEVICE_CMD_READ) {
            switch (readcount) {
                case 0:
                    // Length (MSB)
                    recv_len = (*data) << 8;
                    break;
                case 1:
                    // Length (LSB)
                    recv_len += *data;
                    // Adjust len if needed
                    if (len > recv_len) {
                        len = recv_len;
                    }
                    break;
                default:
                    // Data byte received
                    data++;
                    break;
            }
        } else {
            // Length is encoded on 1 byte
            if ((readcount == 0) && (len > *data)) {
                len = *data;
            } else {
                data++;
            }
        }
        readcount++;

        // acknowledgements. After last byte send NACK.
        if (len == 0)
            I2C_NoAck();
        else
            I2C_Ack();
    }

    I2C_Stop();

    // return bytecount - bytes encoding length
    return readcount - (device_cmd == I2C_DEVICE_CMD_READ ? 2 : 1);
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
        if (g_dbglevel > 3) DbpString(I2C_ERROR);
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

bool I2C_WriteFW(const uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address) {
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
        if (g_dbglevel > 3) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

void I2C_print_status(void) {
    DbpString(_CYAN_("Smart card module (ISO 7816)"));
    uint8_t maj, min;
    if (I2C_get_version(&maj, &min) == PM3_SUCCESS) {
        Dbprintf("  version................. " _YELLOW_("v%x.%02d"), maj, min);
        if (maj < 4) {
            DbpString("    " _RED_("Outdated firmware.") " Please upgrade to v4.x or above.");
        }
    } else {
        DbpString("  version................. " _RED_("FAILED"));
    }
}

int I2C_get_version(uint8_t *maj, uint8_t *min) {
    uint8_t resp[] = {0, 0, 0, 0};
    I2C_Reset_EnterMainProgram();
    uint8_t len = I2C_BufferRead(resp, sizeof(resp), I2C_DEVICE_CMD_GETVERSION, I2C_DEVICE_ADDRESS_MAIN);
    if (len > 0) {
        *maj = resp[0];
        *min = resp[1];
        return PM3_SUCCESS;
    }
    return PM3_EDEVNOTSUPP;
}

// Will read response from smart card module,  retries 3 times to get the data.
bool sc_rx_bytes(uint8_t *dest, uint16_t *destlen) {

    uint8_t i = 5;
    int16_t len = 0;
    while (i--) {

        I2C_WaitForSim();

        len = I2C_BufferRead(dest, *destlen, I2C_DEVICE_CMD_READ, I2C_DEVICE_ADDRESS_MAIN);

        LED_C_ON();

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

    *destlen = len;
    return true;
}

bool GetATR(smart_card_atr_t *card_ptr, bool verbose) {

    if (card_ptr == NULL)
        return false;

    card_ptr->atr_len = 0;
    memset(card_ptr->atr, 0, sizeof(card_ptr->atr));

    // Send ATR
    // start [C0 01] stop start C1 len aa bb cc stop]
    I2C_WriteCmd(I2C_DEVICE_CMD_GENERATE_ATR, I2C_DEVICE_ADDRESS_MAIN);

    //wait for sim card to answer.
    // 1byte = 1ms ,  max frame 256bytes.  Should wait 256ms atleast just in case.
    if (I2C_WaitForSim() == false)
        return false;

    // read bytes from module
    uint16_t len = sizeof(card_ptr->atr);
    if (sc_rx_bytes(card_ptr->atr, &len) == false)
        return false;

    if (len > sizeof(card_ptr->atr)) {
        len = sizeof(card_ptr->atr);
    }

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
            for (uint16_t i = 1; i < len; ++i)
                chksum ^= card_ptr->atr[i];

            if (chksum) {
                if (g_dbglevel > 2) DbpString("Wrong ATR checksum");
            }
        }
    }

    card_ptr->atr_len = (uint8_t)(len & 0xff);
    if (verbose) {
        LogTrace(card_ptr->atr, card_ptr->atr_len, 0, 0, NULL, false);
    }

    return true;
}

void SmartCardAtr(void) {
    LED_D_ON();
    set_tracing(true);
    I2C_Reset_EnterMainProgram();
    smart_card_atr_t card;
    if (GetATR(&card, true)) {
        reply_ng(CMD_SMART_ATR, PM3_SUCCESS, (uint8_t *)&card, sizeof(smart_card_atr_t));
    } else {
        reply_ng(CMD_SMART_ATR, PM3_ETIMEOUT, NULL, 0);
    }
    set_tracing(false);
    LEDsoff();
//    StopTicks();
}

void SmartCardRaw(const smart_card_raw_t *p) {
    LED_D_ON();

    uint16_t len = 0;
    uint8_t *resp = BigBuf_malloc(ISO7816_MAX_FRAME);
    // check if alloacted...
    smartcard_command_t flags = p->flags;

    if ((flags & SC_CLEARLOG) == SC_CLEARLOG)
        clear_trace();

    if ((flags & SC_LOG) == SC_LOG)
        set_tracing(true);
    else
        set_tracing(false);

    if ((flags & SC_CONNECT) == SC_CONNECT) {

        I2C_Reset_EnterMainProgram();

        if ((flags & SC_SELECT) == SC_SELECT) {
            smart_card_atr_t card;
            bool gotATR = GetATR(&card, true);
            //reply_old(CMD_ACK, gotATR, sizeof(smart_card_atr_t), 0, &card, sizeof(smart_card_atr_t));
            if (gotATR == false) {
                reply_ng(CMD_SMART_RAW, PM3_ESOFT, NULL, 0);
                goto OUT;
            }
        }
    }

    if ((flags & SC_RAW) || (flags & SC_RAW_T0)) {

        LogTrace(p->data, p->len, 0, 0, NULL, true);

        bool res = I2C_BufferWrite(
                       p->data,
                       p->len,
                       ((flags & SC_RAW_T0) ? I2C_DEVICE_CMD_SEND_T0 : I2C_DEVICE_CMD_SEND),
                       I2C_DEVICE_ADDRESS_MAIN
                   );
        if (res == false && g_dbglevel > 3) {
            DbpString(I2C_ERROR);
            reply_ng(CMD_SMART_RAW, PM3_ESOFT, NULL, 0);
            goto OUT;
        }

        // read bytes from module
        len = ISO7816_MAX_FRAME;
        res = sc_rx_bytes(resp, &len);
        if (res) {
            LogTrace(resp, len, 0, 0, NULL, false);
        } else {
            len = 0;
        }
    }

    reply_ng(CMD_SMART_RAW, PM3_SUCCESS, resp, len);

OUT:
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

    reply_ng(CMD_SMART_UPGRADE, (isOK) ? PM3_SUCCESS : PM3_ESOFT, NULL, 0);
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
    reply_ng(CMD_SMART_SETCLOCK, PM3_SUCCESS, NULL, 0);
    set_tracing(false);
    LEDsoff();
}
