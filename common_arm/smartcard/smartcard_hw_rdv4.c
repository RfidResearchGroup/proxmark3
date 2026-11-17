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
// RDV4 card side: the SIM adapter, reached over the bit banged I2C bus.
//-----------------------------------------------------------------------------
#include "smartcard_hw_rdv4.h"

#include "smartcard_apis.h"

#include "i2c_apis.h"
#include "proxmark3_arm.h"
#include "ticks_apis.h"
#include "dbprint.h"

// set the reset state
void SmartCard_HwSetAdapterLines(uint8_t LineRST, uint8_t LineSCK, uint8_t LineSDA) {
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

// How long to allow the SIM module to *start* an operation, i.e. to pull SCL
// low after it has taken a command.
//
// This used to be 1200 ms, which is three orders of magnitude more than the
// module needs - its interrupt hands the command to the main loop and SCL goes
// low within microseconds of the STOP.  The only thing that long allowance ever
// bought was dead time: every caller that arrives when the module has *already*
// finished (SCL back high, and it is never going to go low again) sat here for
// the full 1200 ms before doing the read.  SmartCard_RxBytes() does exactly that on
// every call that follows a completed operation, which is why an ordinary
// `smart info` took about one and a half seconds.
//
// The result is ignored by SmartCard_RxBytes() anyway - reaching the end of this
// simply means the module is idle and the data is ready to read.
#define SIM_START_TIMEOUT_MS  50

static bool WaitSCL_L_timeout(void) {
    // How long the module may take to *start* stretching, not how long it may
    // hold. Polled at bus granularity: a command the module already finished
    // never shows SCL low at all, and at 1 ms a step that cost the full
    // timeout on every fast exchange.
    return I2C_WaitSCL_L(I2C_ITERS_FOR_MS(SIM_START_TIMEOUT_MS));
}

bool SmartCard_HwWaitForSim(uint32_t wait) {

    // wait for data from card
    if (WaitSCL_L_timeout() == false) {
        return false;
    }

    // wait is an iteration count; build it with I2C_ITERS_FOR_MS().
    return I2C_WaitSCL_H(wait);
}

bool SmartCard_RxBytes(uint8_t *dest, uint16_t *destlen, uint32_t wait) {

    uint8_t i = 10;
    int16_t len = 0;
    while (i--) {

        SmartCard_HwWaitForSim(wait);

        len = I2C_AdaptiveRead(dest, *destlen, I2C_DEVICE_CMD_READ, I2C_DEVICE_ADDRESS_MAIN);

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

// Reset the SIM_Adapter, then  enter the main program
void SmartCard_HwOpen(void) {
    I2C_init(true);
    SmartCard_HwSetAdapterLines(0, 0, 0);
    WaitMS(30);
    SmartCard_HwSetAdapterLines(1, 0, 0);
    WaitMS(30);
    SmartCard_HwSetAdapterLines(1, 1, 1);
    WaitMS(10);
}

// Reset the SIM_Adapter, then enter the bootloader program
// Reserve for firmware update.
void SmartCard_HwOpenBootloader(void) {
    I2C_init(true);
    SmartCard_HwSetAdapterLines(0, 1, 1);
    WaitMS(100);
    SmartCard_HwSetAdapterLines(1, 1, 1);
    WaitMS(10);
}

bool SmartCard_HwSetReload(uint16_t reload) {
    // SETBAUD carries TH1, which the module turns back into 256 - TH1. R = 256
    // wraps to 0, which is exactly what the timer wants.
    uint8_t th1 = (uint8_t)((256u - reload) & 0xFFu);
    return I2C_WriteByte(th1, I2C_DEVICE_CMD_SETBAUD, I2C_DEVICE_ADDRESS_MAIN);
}

void SmartCard_HwSetClock(uint64_t f) {
    // start [C0 05 xx] stop
    I2C_WriteByte((uint8_t)f, I2C_DEVICE_CMD_SIM_CLC, I2C_DEVICE_ADDRESS_MAIN);
}

static bool sim_module_at_least(uint8_t major, uint8_t minor, uint8_t want_major, uint8_t want_minor) {
    return ((major > want_major) || ((major == want_major) && (minor >= want_minor)));
}

int SmartCard_HwModuleInfo(uint8_t *major, uint8_t *minor, void *info) {
    uint8_t resp[] = {0, 0, 0, 0};
    uint8_t len = I2C_AdaptiveRead(resp, sizeof(resp), I2C_DEVICE_CMD_GETVERSION, I2C_DEVICE_ADDRESS_MAIN);
    if (len <= 1) {
        return PM3_EDEVNOTSUPP;
    }
    *major = resp[0];
    *minor = resp[1];
    if (info != NULL) {
        smartcard_rdv4_info_t *i = (smartcard_rdv4_info_t *)info;
        i->ok = sim_module_at_least(resp[0], resp[1], SIM_MODULE_VERS_MIN_HI, SIM_MODULE_VERS_MIN_LO);
        i->t1 = sim_module_at_least(resp[0], resp[1], SIM_MODULE_VERS_T1_HI, SIM_MODULE_VERS_T1_LO);
    }
    return PM3_SUCCESS;
}

// Raw sequential access to the adapter's byte address space, used to read back
// the firmware image for verification.
int16_t SmartCard_HwModuleRead(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address) {
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

bool SmartCard_HwModuleWrite(const uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address) {
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
