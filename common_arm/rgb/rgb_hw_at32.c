#include "rgb_apis.h"
#include "i2c.h"        // RGB LED is driven over I2C
#include "ticks_apis.h" // I2C timing needs ticks running

// PM5 antenna RGB LED, driven by an I2C RGB controller (7-bit address 0x48).
// Register map (from the QC/bring-up code):
//   0x02 = index (which LED)
//   0x01 = count (number of LEDs on the string; must be set or nothing lights)
//   0x03 = data  (3 bytes RGB888 per LED)
#define RGB_I2C_ADDR   (0x48 << 1) // 8-bit address form expected by the I2C_* API
#define RGB_REG_COUNT  0x01
#define RGB_REG_INDEX  0x02
#define RGB_REG_DATA   0x03

void RgbLedSet(uint8_t r, uint8_t g, uint8_t b) {
    uint8_t rgb[3] = { r, g, b };
    StartTicks();
    I2C_init(true);
    I2C_WriteByte(0, RGB_REG_INDEX, RGB_I2C_ADDR); // address LED index 0
    I2C_WriteByte(1, RGB_REG_COUNT, RGB_I2C_ADDR); // 1 LED on the string
    I2C_BufferWrite(rgb, sizeof(rgb), RGB_REG_DATA, RGB_I2C_ADDR);
}
