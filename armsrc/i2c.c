// //-----------------------------------------------------------------------------
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
#include "ticks_apis.h"
#include "dbprint.h"
#include "util.h"
#include "string.h"

#define SCL_H    Gpio_I2C_SCL_High()
#define SCL_L    Gpio_I2C_SCL_Low()
#define SDA_H    Gpio_I2C_SDA_High()
#define SDA_L    Gpio_I2C_SDA_Low()
#define RST_H    Gpio_I2C_RST_High()
#define RST_L    Gpio_I2C_RST_Low()

#define SCL_read Gpio_I2C_SCL_Read()
#define SDA_read Gpio_I2C_SDA_Read()

#define I2C_ERROR  "I2C_WaitAck Error"

// Bus timing lives in i2c.h alongside the timeouts derived from it, so the two
// cannot drift apart.
#define I2C_DELAY_1CLK    SpinDelayUsPrecision(I2C_DELAY_1CLK_US)
#define I2C_DELAY_2CLK    SpinDelayUsPrecision(I2C_DELAY_2CLK_US)

#define SC_PROTO_T0     (1 << 0)
#define SC_PROTO_T1     (1 << 1)

// Protocols the last ATR offered, as a bit mask of (1 << T).  Zero means we do
// not know - no ATR has been read since the module was last reset.
static uint8_t s_card_protocols = 0;

// Whether the protocol choice has already been reported this session.  These
// messages are worth seeing once; sc_raw_device_cmd() runs per APDU, and an
// EMV AID sweep is 150 of them.
static bool s_proto_announced = false;

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
    gpio_sw_i2c_rst_setup();

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
        RST_H;
    else
        RST_L;

    if (LineSCK)
        SCL_H;
    else
        SCL_L;

    if (LineSDA)
        SDA_H;
    else
        SDA_L;
}

// Reset the SIM_Adapter, then  enter the main program
// Note: the SIM_Adapter will not enter the main program after power up. Please run this function before use SIM_Adapter.
void I2C_Reset_EnterMainProgram(void) {
    // whatever we knew about the card is no longer trustworthy
    s_card_protocols = 0;
    s_proto_announced = false;
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

static bool WaitSCL_H(void) {
    return WaitSCL_H_delay(I2C_ITERS_FOR_MS(I2C_STRETCH_TIMEOUT_MS));
}

static bool WaitSCL_L_delay(uint32_t delay) {
    while (delay--) {
        if (SCL_read == false) {
            return true;
        }
        I2C_DELAY_1CLK;
    }
    return false;
}

static bool WaitSCL_L(void) {
    return WaitSCL_L_delay(I2C_ITERS_FOR_MS(I2C_STRETCH_TIMEOUT_MS));
}

// How long to allow the SIM module to *start* an operation, i.e. to pull SCL
// low after it has taken a command.
//
// This used to be 1200 ms, which is three orders of magnitude more than the
// module needs - its interrupt hands the command to the main loop and SCL goes
// low within microseconds of the STOP.  The only thing that long allowance ever
// bought was dead time: every caller that arrives when the module has *already*
// finished (SCL back high, and it is never going to go low again) sat here for
// the full 1200 ms before doing the read.  sc_rx_bytes() does exactly that on
// every call that follows a completed operation, which is why an ordinary
// `smart info` took about one and a half seconds.
//
// The result is ignored by sc_rx_bytes() anyway - reaching the end of this
// simply means the module is idle and the data is ready to read.
#define SIM_START_TIMEOUT_MS  50

static bool WaitSCL_L_timeout(void) {
    volatile uint32_t delay = SIM_START_TIMEOUT_MS;
    while (delay--) {
        // exit on SCL LOW
        if (SCL_read == false)
            return true;

        WaitMS(1);
    }
    return false;
}

static bool I2C_Start(void) {

    I2C_DELAY_2CLK;
    I2C_DELAY_2CLK;
    SDA_H;
    I2C_DELAY_1CLK;
    SCL_H;
    if (WaitSCL_H() == false) {
        return false;
    }

    I2C_DELAY_2CLK;

    if (SCL_read == false) {
        return false;
    }

    if (SDA_read == false) {
        return false;
    }

    SDA_L;
    I2C_DELAY_2CLK;
    return true;
}

static bool I2C_WaitForSim(uint32_t wait) {

    // wait for data from card
    if (WaitSCL_L_timeout() == false) {
        return false;
    }

    // wait is an iteration count; build it with I2C_ITERS_FOR_MS().
    return WaitSCL_H_delay(wait);
}

// send i2c STOP
static void I2C_Stop(void) {
    SCL_L;
    I2C_DELAY_2CLK;
    SDA_L;
    I2C_DELAY_2CLK;
    SCL_H;
    I2C_DELAY_2CLK;

    if (WaitSCL_H() == false) {
        return;
    }

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

    if (WaitSCL_H() == false) {
        return;
    }

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

    if (WaitSCL_H() == false) {
        return;
    }

    SCL_L;
    I2C_DELAY_2CLK;
}

static bool I2C_WaitAck(void) {
    SCL_L;
    I2C_DELAY_1CLK;
    SDA_H;
    I2C_DELAY_1CLK;
    SCL_H;

    if (WaitSCL_H() == false) {
        return false;
    }

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
        if (WaitSCL_H() == false) {
            return;
        }

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
        if (WaitSCL_L() == false) {
            return -2;
        }

        I2C_DELAY_1CLK;
        SCL_H;
        if (WaitSCL_H() == false) {
            return -1;
        }

        I2C_DELAY_1CLK;
        if (SDA_read) {
            b |= 0x01;
        }
    }
    SCL_L;
    return b;
}

// Sends one byte  (command to be written, SlaveDevice address)
bool I2C_WriteCmd(uint8_t device_cmd, uint8_t device_address) {
    bool _break = true;
    do {
        if (I2C_Start() == false) {
            return false;
        }

        I2C_SendByte(device_address & 0xFE);
        if (I2C_WaitAck() == false) {
            break;
        }

        I2C_SendByte(device_cmd);
        if (I2C_WaitAck() == false) {
            break;
        }

        _break = false;
    } while (false);

    I2C_Stop();

    if (_break) {

        if (g_dbglevel > DBG_DEBUG) DbpString(I2C_ERROR);

        return false;
    }
    return true;
}

// Sends 1 byte data (data to be written, command to be written , SlaveDevice address)
bool I2C_WriteByte(uint8_t data, uint8_t device_cmd, uint8_t device_address) {
    bool _break = true;
    do {
        if (I2C_Start() == false) {
            return false;
        }

        I2C_SendByte(device_address & 0xFE);
        if (I2C_WaitAck() == false) {
            break;
        }

        I2C_SendByte(device_cmd);
        if (I2C_WaitAck() == false) {
            break;
        }

        I2C_SendByte(data);
        if (I2C_WaitAck() == false) {
            break;
        }

        _break = false;
    } while (false);

    I2C_Stop();
    if (_break) {
        if (g_dbglevel > DBG_DEBUG) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

// Sends array of data (array, length, command to be written , SlaveDevice address)
// len = uint16 because we need to write up to 256 bytes
bool I2C_BufferWrite(const uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address) {
    bool _break = true;
    do {
        if (I2C_Start() == false) {
            return false;
        }

        I2C_SendByte(device_address & 0xFE);
        if (I2C_WaitAck() == false) {
            break;
        }

        I2C_SendByte(device_cmd);
        if (I2C_WaitAck() == false) {
            break;
        }

        while (len) {

            I2C_SendByte(*data);
            if (I2C_WaitAck() == false)
                break;

            len--;
            data++;
        }

        if (len == 0) {
            _break = false;
        }

    } while (false);

    I2C_Stop();
    if (_break) {
        if (g_dbglevel > DBG_DEBUG) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

// read one array of data (Data array, Readout length, command to be written , SlaveDevice address  ).
// len = uint16 because we need to read up to 256bytes
int16_t I2C_BufferRead(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address) {

    // sanity check - need at least 2 bytes for the SIM-module length header
    // (the response format prepends a 2-byte BE length); fewer cannot be parsed.
    if (data == NULL || len < 2) {
        return 0;
    }

    // extra wait  500us (514us measured)
    // 200us  (xx measured)
    WaitUS(600);

    bool _break = true;

    do {
        if (I2C_Start() == false) {
            return 0;
        }

        // 0xB0 / 0xC0  == i2c write
        I2C_SendByte(device_address & 0xFE);
        if (I2C_WaitAck() == false) {
            break;
        }

        I2C_SendByte(device_cmd);
        if (I2C_WaitAck() == false) {
            break;
        }

        // 0xB1 / 0xC1 == i2c read
        I2C_Start();
        I2C_SendByte(device_address | 1);
        if (I2C_WaitAck() == false) {
            break;
        }

        _break = false;
    } while (false);

    if (_break) {
        I2C_Stop();
        if (g_dbglevel > DBG_DEBUG) DbpString(I2C_ERROR);
        return 0;
    }

    uint16_t readcount = 0;
    uint16_t recv_len = 0;

    while (len) {

        int16_t tmp = I2C_ReadByte();
        if (tmp < 0) {
            return tmp;
        }

        *data = (uint8_t)tmp & 0xFF;

        len--;

        // Starting firmware v4 the length is encoded on the first two bytes.
        switch (readcount) {
            case 0: {
                // Length (MSB)
                recv_len = (*data) << 8;
                break;
            }
            case 1: {
                // Length (LSB)
                recv_len += *data;

                // old packages..
                if (recv_len > 0x0200) {
                    // [0] = len
                    // [1] = data
                    recv_len >>= 8;
                    data++;
                }

                // Adjust len if needed
                if (len > recv_len) {
                    len = recv_len;
                }
                break;
            }
            default: {
                // Data byte received
                data++;
                break;
            }
        }

        readcount++;

        // acknowledgements. After last byte send NACK.
        if (len == 0) {
            I2C_NoAck();
        } else {
            I2C_Ack();
        }
    }

    I2C_Stop();

    // return bytecount - bytes encoding length
    return readcount - 2;
}

// read one array of data (Data array, Readout length, command to be written , SlaveDevice address  ).
// len = uint16 because we need to read up to 256bytes
// No data process logic, only raw rx.
int16_t I2C_BufferReadRaw(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address) {

    // sanity check
    if (data == NULL || len == 0) {
        return 0;
    }

//    uint8_t *pd = data;

    // extra wait  500us (514us measured)
    // 200us  (xx measured)
    WaitUS(600);

    bool _break = true;

    do {
        if (I2C_Start() == false) {
            return 0;
        }

        // 0xB0 / 0xC0  == i2c write
        I2C_SendByte(device_address & 0xFE);
        if (I2C_WaitAck() == false) {
            break;
        }

        I2C_SendByte(device_cmd);
        if (I2C_WaitAck() == false) {
            break;
        }

        // 0xB1 / 0xC1 == i2c read
        I2C_Start();
        I2C_SendByte(device_address | 1);
        if (I2C_WaitAck() == false) {
            break;
        }

        _break = false;
    } while (false);

    if (_break) {
        I2C_Stop();
        if (g_dbglevel > DBG_DEBUG) DbpString(I2C_ERROR);
        return 0;
    }

    int16_t count = 0;

    while (len) {
        int16_t tmp = I2C_ReadByte();
        if (tmp < 0) {
            return tmp;
        }

        data[count] = (uint8_t)tmp & 0xFF;
        len--;
        count++;

        // acknowledgements. After last byte send NACK.
        if (len == 0) {
            I2C_NoAck();
        } else {
            I2C_Ack();
        }
    }

    I2C_Stop();

//    Dbprintf("rec len...  %u  count... %u", recv_len, count);
//    Dbhexdump(count, data, false);

    return count;
}

int16_t I2C_ReadFW(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address) {
    //START, 0xB0, 0x00, 0x00, START, 0xB1, xx, yy, zz, ......, STOP
    bool _break = true;
    uint8_t readcount = 0;

    // sending
    do {
        if (I2C_Start() == false) {
            return 0;
        }

        // 0xB0 / 0xC0  i2c write
        I2C_SendByte(device_address & 0xFE);
        if (I2C_WaitAck() == false)
            break;

        I2C_SendByte(msb);
        if (I2C_WaitAck() == false) {
            break;
        }

        I2C_SendByte(lsb);
        if (I2C_WaitAck() == false) {
            break;
        }

        // 0xB1 / 0xC1  i2c read
        I2C_Start();
        I2C_SendByte(device_address | 1);
        if (I2C_WaitAck() == false) {
            break;
        }

        _break = false;
    } while (false);

    if (_break) {
        I2C_Stop();
        if (g_dbglevel > DBG_DEBUG) DbpString(I2C_ERROR);
        return 0;
    }

    // reading
    while (len) {

        int16_t tmp = I2C_ReadByte();
        if (tmp < 0) {
            return tmp;
        }

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
    bool _break = true;

    do {
        if (I2C_Start() == false) {
            return false;
        }

        // 0xB0  == i2c write
        I2C_SendByte(device_address & 0xFE);
        if (I2C_WaitAck() == false) {
            break;
        }

        I2C_SendByte(msb);
        if (I2C_WaitAck() == false) {
            break;
        }

        I2C_SendByte(lsb);
        if (I2C_WaitAck() == false) {
            break;
        }

        while (len) {
            I2C_SendByte(*data);
            if (I2C_WaitAck() == false) {
                break;
            }
            len--;
            data++;
        }

        if (len == 0) {
            _break = false;
        }

    } while (false);

    I2C_Stop();

    if (_break) {
        if (g_dbglevel > DBG_DEBUG) DbpString(I2C_ERROR);
        return false;
    }
    return true;
}

static bool sim_module_at_least(uint8_t major, uint8_t minor, uint8_t want_major, uint8_t want_minor) {
    return ((major > want_major) || ((major == want_major) && (minor >= want_minor)));
}

void I2C_print_status(void) {
    DbpString(_CYAN_("Smart card module (ISO 7816)"));

    uint8_t major, minor;
    if (I2C_get_version(&major, &minor) == PM3_SUCCESS) {

        bool ok = sim_module_at_least(major, minor, SIM_MODULE_VERS_MIN_HI, SIM_MODULE_VERS_MIN_LO);
        bool t1 = sim_module_at_least(major, minor, SIM_MODULE_VERS_T1_HI, SIM_MODULE_VERS_T1_LO);

        Dbprintf("  version................. v%d.%02d ( %s )"
                 , major
                 , minor
                 , ok ? _GREEN_("ok") : _RED_("Outdated")
                );

        Dbprintf("  T=1, PPS................ ( %s )"
                 , t1 ? _GREEN_("supported") : _YELLOW_("not in this firmware")
                );
    } else {
        DbpString("  version................. ( " _RED_("fail") " )");
    }
}

int I2C_get_version(uint8_t *major, uint8_t *minor) {
    uint8_t resp[] = {0, 0, 0, 0};
    I2C_Reset_EnterMainProgram();
    uint8_t len = I2C_BufferRead(resp, sizeof(resp), I2C_DEVICE_CMD_GETVERSION, I2C_DEVICE_ADDRESS_MAIN);
    if (len > 1) {
        *major = resp[0];
        *minor = resp[1];
        return PM3_SUCCESS;
    }
    return PM3_EDEVNOTSUPP;
}

// Will read response from smart card module,  retries 3 times to get the data.
bool sc_rx_bytes(uint8_t *dest, uint16_t *destlen, uint32_t wait) {

    uint8_t i = 10;
    int16_t len = 0;
    while (i--) {

        I2C_WaitForSim(wait);

        len = I2C_BufferRead(dest, *destlen, I2C_DEVICE_CMD_READ, I2C_DEVICE_ADDRESS_MAIN);

        LED_C_ON();

        if (len > 1) {
            break;
        } else if (len == 1) {
            continue;
        } else {
            return false;
        }
    }

    *destlen = len;
    return true;
}

/*
 * ISO/IEC 7816-3 clause 8: the protocols on offer are the low nibbles of the
 * TDi bytes.  With no TD1 at all, only T=0 is offered.  T=15 carries global
 * interface bytes rather than a transmission protocol and is ignored here.
 */
static uint8_t atr_protocols(const uint8_t *atr, uint8_t len) {

    if (len < 2) {
        return 0;
    }

    uint8_t y = (uint8_t)(atr[1] >> 4);      // T0
    uint8_t i = 2;
    uint8_t mask = 0;

    while (y) {

        if (y & 0x01) i++;                   // TA(i)
        if (y & 0x02) i++;                   // TB(i)
        if (y & 0x04) i++;                   // TC(i)

        if ((y & 0x08) == 0) {
            break;                           // no TD(i), nothing further named
        }
        if (i >= len) {
            break;                           // truncated ATR
        }

        uint8_t td = atr[i++];
        uint8_t t = (uint8_t)(td & 0x0F);
        if (t < 8) {
            mask |= (uint8_t)(1u << t);
        }
        y = (uint8_t)(td >> 4);
    }

    if (mask == 0) {
        mask = SC_PROTO_T0;                  // clause 8.2.3
    }
    return mask;
}

uint8_t sc_raw_device_cmd(smartcard_command_t flags) {

    // An explicit T=1 request is always honoured as asked - it is an override,
    // and a card that supports T=1 without advertising it is a real thing.  But
    // say so when the ATR disagrees, because the alternative is silence from
    // the card and no clue why.
    if ((flags & SC_RAW_T1) == SC_RAW_T1) {

        if ((s_card_protocols != 0) && ((s_card_protocols & SC_PROTO_T1) == 0)) {
            if ((g_dbglevel >= DBG_ERROR) && (s_proto_announced == false)) {
                s_proto_announced = true;
                DbpString("SC: " _YELLOW_("card offers no T=1") ", sending it anyway");
            }
        }
        return I2C_DEVICE_CMD_SEND_T1;
    }

    if ((flags & SC_RAW_T0) == SC_RAW_T0) {

        /*
         * A T=0 request to a card whose ATR offers no T=0 cannot work - the
         * card will not hear it at all, which shows up as silence rather than
         * an error.  Most modern EMV and JCOP cards are T=1 only, and callers
         * like ExchangeAPDUSC() ask for T=0 unconditionally.
         *
         * Only this one case is redirected, and only once an ATR has actually
         * been read.  A card that does offer T=0 is left alone even if it also
         * offers T=1, because there the caller's choice is a real one - use
         * SC_RAW_T1 to say otherwise.
         *
         * Note this cannot make anything worse even against a SIM module too
         * old to know SEND_T1: in the exact case it fires, the request as given
         * was already guaranteed to fail.
         */
        if ((s_card_protocols != 0) &&
                ((s_card_protocols & SC_PROTO_T0) == 0) &&
                ((s_card_protocols & SC_PROTO_T1) == SC_PROTO_T1)) {

            if ((g_dbglevel >= DBG_INFO) && (s_proto_announced == false)) {
                s_proto_announced = true;
                DbpString("SC: card offers no T=0, sending as T=1");
            }
            return I2C_DEVICE_CMD_SEND_T1;
        }

        return I2C_DEVICE_CMD_SEND_T0;
    }

    // Raw pass through: the host owns the framing, so never second guess it.
    return I2C_DEVICE_CMD_SEND;
}

bool GetATR(smart_card_atr_t *card_ptr, bool verbose) {

    if (card_ptr == NULL) {
        return false;
    }

    card_ptr->atr_len = 0;
    memset(card_ptr->atr, 0, sizeof(card_ptr->atr));

    // Send ATR
    // start [C0 01] stop start C1 len aa bb cc stop]
    I2C_WriteCmd(I2C_DEVICE_CMD_GENERATE_ATR, I2C_DEVICE_ADDRESS_MAIN);

    // wait for sim card to answer.
    // 1byte = 1ms ,  max frame 256bytes.  Should wait 256ms atleast just in case.
    if (I2C_WaitForSim(SIM_WAIT_DELAY) == false) {
        return false;
    }

    // read bytes from module
    uint16_t len = sizeof(card_ptr->atr);
    if (sc_rx_bytes(card_ptr->atr, &len, SIM_WAIT_DELAY) == false) {
        return false;
    }

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
                if (g_dbglevel > DBG_INFO) DbpString("Wrong ATR checksum");
            }
        }
    }

    card_ptr->atr_len = (uint8_t)(len & 0xff);

    s_card_protocols = atr_protocols(card_ptr->atr, card_ptr->atr_len);
    s_proto_announced = false;
    if (g_dbglevel >= DBG_INFO) {
        Dbprintf("SC: card offers%s%s"
                 , (s_card_protocols & SC_PROTO_T0) ? " T=0" : ""
                 , (s_card_protocols & SC_PROTO_T1) ? " T=1" : ""
                );
    }

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
    uint8_t *resp = BigBuf_calloc(ISO7816_MAX_FRAME);
    if (resp == NULL) {
        reply_ng(CMD_SMART_RAW, PM3_EMALLOC, NULL, 0);
        LEDsoff();
        return;
    }
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

    if (((flags & SC_RAW) == SC_RAW) ||
            ((flags & SC_RAW_T0) == SC_RAW_T0) ||
            ((flags & SC_RAW_T1) == SC_RAW_T1)) {

        uint32_t wait = SIM_WAIT_DELAY;
        if ((flags & SC_WAIT) == SC_WAIT) {
            // Asking for N ms now actually waits N ms.  The old conversion
            // assumed 3.07 us per iteration while the delay had been changed to
            // 20 us, so `--timeout 1000` sat there for six and a half seconds.
            uint32_t ms = p->wait_delay;
            if (ms > I2C_WAIT_MAX_MS) {
                ms = I2C_WAIT_MAX_MS;
            }
            wait = I2C_ITERS_FOR_MS(ms);
        }

        LogTrace(p->data, p->len, 0, 0, NULL, true);

        bool res = I2C_BufferWrite(
                       p->data,
                       p->len,
                       sc_raw_device_cmd(flags),
                       I2C_DEVICE_ADDRESS_MAIN
                   );

        if (res == false) {
            if (g_dbglevel > 3) {
                DbpString(I2C_ERROR);
            }
            reply_ng(CMD_SMART_RAW, PM3_ESOFT, NULL, 0);
            goto OUT;
        }

        // read bytes from module
        len = ISO7816_MAX_FRAME;
        res = sc_rx_bytes(resp, &len, wait);
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
    const uint8_t *fwdata = BigBuf_get_addr();
    uint8_t *verifydata = BigBuf_calloc(I2C_BLOCK_SIZE);
    if (verifydata == NULL) {
        reply_ng(CMD_SMART_UPGRADE, PM3_EMALLOC, NULL, 0);
        LED_C_OFF();
        return;
    }

    while (length) {

        uint8_t msb = (pos >> 8) & 0xFF;
        uint8_t lsb = pos & 0xFF;

        Dbprintf("FW %02X%02X", msb, lsb);

        size_t size = MIN(I2C_BLOCK_SIZE, length);

        // write
        int16_t res = I2C_WriteFW(fwdata + pos, size, msb, lsb, I2C_DEVICE_ADDRESS_BOOT);
        if (!res) {
            Dbprintf("Writing failed at offset 0x%04X", pos);
            isOK = false;
            break;
        }

        // writing takes time.
        WaitMS(50);

        // read
        res = I2C_ReadFW(verifydata, size, msb, lsb, I2C_DEVICE_ADDRESS_BOOT);
        if (res <= 0) {
            Dbprintf("Reading back failed at offset 0x%04X", pos);
            isOK = false;
            break;
        }

        // cmp
        if (0 != memcmp(fwdata + pos, verifydata, size)) {
            Dbprintf("Verify mismatch at offset 0x%04X", pos);
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

// Send a single byte to the SIM module's CMD_SETBAUD opcode (0x04).
// The 8051 firmware uses this to reload Timer1 (UART0 baud generator).
// Until 2026 the implementation was an empty stub; the SIM module silently
// ignored any host-driven baud renegotiation. Some smart cards (notably the
// HID Artemis SLE88 SAM family) advertise non-default Fi/Di in TA1 and need
// PPS to switch the bridge baud post-ATR.
void SmartCardSetBaud(uint64_t arg0) {
    LED_D_ON();
    I2C_Reset_EnterMainProgram();
    bool ok = I2C_WriteByte((uint8_t)(arg0 & 0xFF),
                            I2C_DEVICE_CMD_SETBAUD,
                            I2C_DEVICE_ADDRESS_MAIN);
    reply_ng(CMD_SMART_SETBAUD, ok ? PM3_SUCCESS : PM3_ESOFT, NULL, 0);
    LEDsoff();
}

/*
 * ISO/IEC 7816-3 clause 9 protocol and parameter selection.
 *
 * PPS is only legal in the window straight after the ATR, so the card is reset
 * and its ATR collected first - that also gives the SIM module the interface
 * bytes it needs to time the exchange.  The module answers with
 *
 *      [0] 1 when the card confirmed the request
 *      [1] the protocol now in force
 *      [2] the TA1 (FI/DI) now in force
 *
 * Note that SEND_T1 already runs a PPS on its own when the ATR offers T=1 but
 * names T=0 first, so this is only needed to negotiate Fi/Di explicitly.
 */
void SmartCardPPS(const smart_card_pps_t *p) {

    LED_D_ON();
    set_tracing(true);
    I2C_Reset_EnterMainProgram();

    smart_card_atr_t card;
    if (GetATR(&card, true) == false) {
        reply_ng(CMD_SMART_PPS, PM3_ETIMEOUT, NULL, 0);
        goto out;
    }

    uint8_t req[2];
    uint16_t reqlen = 1;
    req[0] = (uint8_t)(p->protocol & 0x0F);
    if (p->use_ta1) {
        req[1] = p->ta1;
        reqlen = 2;
    }

    if (I2C_BufferWrite(req, reqlen, I2C_DEVICE_CMD_PPS, I2C_DEVICE_ADDRESS_MAIN) == false) {
        if (g_dbglevel > DBG_DEBUG) {
            DbpString(I2C_ERROR);
        }
        reply_ng(CMD_SMART_PPS, PM3_ESOFT, NULL, 0);
        goto out;
    }

    uint8_t resp[8] = {0};
    uint16_t len = sizeof(resp);
    if ((sc_rx_bytes(resp, &len, SIM_WAIT_DELAY) == false) || (len < 3)) {
        reply_ng(CMD_SMART_PPS, PM3_ETIMEOUT, NULL, 0);
        goto out;
    }

    reply_ng(CMD_SMART_PPS, PM3_SUCCESS, resp, 3);

out:
    set_tracing(false);
    LEDsoff();
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
