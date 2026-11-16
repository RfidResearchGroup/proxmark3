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
// Bit banged I2C bus primitives, shared by every I2C device on the PM3.
//-----------------------------------------------------------------------------
#include "i2c_apis.h"

#include "gpio_apis.h"
#include "ticks_apis.h"
#include "dbprint.h"

#define I2C_DELAY_1CLK    SpinDelayUsPrecision(I2C_DELAY_1CLK_US)
#define I2C_DELAY_2CLK    SpinDelayUsPrecision(I2C_DELAY_2CLK_US)
#define I2C_DELAY_SDA     SpinDelayUsPrecision(s_fast_sda_timing ? I2C_DELAY_SDA_FAST_US : I2C_DELAY_SDA_US)
#define I2C_DELAY_HOLD    SpinDelayUsPrecision(I2C_DELAY_HOLD_US)
#define I2C_DELAY_HIGH    SpinDelayUsPrecision(I2C_DELAY_HIGH_US)

static bool s_fast_sda_timing = false;

// Returns the previous state, so a caller can save and restore around a burst
// of exchanges.
bool I2C_SetFastSDATiming(bool enabled) {
    bool previous = s_fast_sda_timing;
    s_fast_sda_timing = enabled && I2C_FAST_SDA_TIMING;
    return previous;
}

// try i2c bus recovery at 100kHz = 5us high, 5us low
void I2C_recovery(void) {
    DbpString("Performing i2c bus recovery");

    // reset I2C
    SDA_H;
    SCL_H;

    //9nth cycle acts as NACK
    for (int i = 0; i < 10; i++) {
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

// Setup and recovery I2C
void I2C_init(bool has_ticks) {
    gpio_i2c_hw_rst_setup();
    gpio_i2c_sw_bus_setup();

    if (has_ticks) {
        WaitMS(2);
    }

    bool isok = (SCL_read && SDA_read);
    if (isok == false)
        I2C_recovery();
}

// Wait for the clock to go High.
bool I2C_WaitSCL_H(uint32_t iters) {
    while (iters--) {
        if (SCL_read) {
            return true;
        }
        I2C_DELAY_1CLK;
    }
    return false;
}

bool I2C_WaitSCL_L(uint32_t iters) {
    while (iters--) {
        if (SCL_read == false) {
            return true;
        }
        I2C_DELAY_1CLK;
    }
    return false;
}

static bool WaitSCL_H(void) {
    return I2C_WaitSCL_H(I2C_ITERS_FOR_MS(I2C_STRETCH_TIMEOUT_MS));
}

static bool WaitSCL_L(void) {
    return I2C_WaitSCL_L(I2C_ITERS_FOR_MS(I2C_STRETCH_TIMEOUT_MS));
}

// Send i2c START
bool I2C_Start(void) {
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

// Send i2c STOP
void I2C_Stop(void) {
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
void I2C_Ack(void) {
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
void I2C_NoAck(void) {
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

// Wait for i2c ACK
bool I2C_WaitAck(void) {
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

// Byte write
void I2C_SendByte(uint8_t data) {
    uint8_t bits = 8;

    while (bits--) {
        SCL_L;

        I2C_DELAY_HOLD;

        if (data & 0x80)
            SDA_H;
        else
            SDA_L;

        data <<= 1;

        I2C_DELAY_SDA;

        SCL_H;
        if (WaitSCL_H() == false) {
            return;
        }

        I2C_DELAY_HIGH;
    }
    SCL_L;
}

// Byte read
int16_t I2C_ReadByte(void) {
    uint8_t bits = 8, b = 0;

    SDA_H;
    while (bits--) {
        b <<= 1;
        SCL_L;
        if (WaitSCL_L() == false) {
            return -2;
        }

        I2C_DELAY_SDA;
        SCL_H;
        if (WaitSCL_H() == false) {
            return -1;
        }

        I2C_DELAY_HIGH;
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
// Note: The first U16 data must is data length from device response! And '*data' exclude the U16 length info.
int16_t I2C_AdaptiveRead(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address) {
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

        *data = (uint8_t) tmp & 0xFF;

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
int16_t I2C_BufferRead(uint8_t *data, uint16_t len, uint8_t device_cmd, uint8_t device_address) {
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

        data[count] = (uint8_t) tmp & 0xFF;
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
