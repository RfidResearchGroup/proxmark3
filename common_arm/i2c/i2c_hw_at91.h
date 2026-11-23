//
// Created by dxl on 2026/11/16.
//

#ifndef I2C_HW_AT91_H
#define I2C_HW_AT91_H

// Bus timing lives here alongside the timeouts derived from it, so the two
// cannot drift apart.
//
// Bit banged bus timing. 1CLK is spent twice per bit, 2CLK once, so the bit
// period is 2 * 1CLK + 2CLK, 62 us or about 16 kHz. Every timeout below derives
// from these, so they are the only two numbers to change.
//
//Old value was 20/22 (16 kHz) - increased to 4/2 (100 kHz) and seems to be working reliably.
//It was previously reported that 5/7 (59 kHz) was too fast, but this was before SIM module firmware updates.
//Values above 4/2 (100 kHz) have been tested to work successfully, but they seem to run slower than 4/2.
#define I2C_DELAY_1CLK_US       4
#define I2C_DELAY_2CLK_US       2

#endif //I2C_HW_AT91_H
