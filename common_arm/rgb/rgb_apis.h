#ifndef RGB_APIS_H_
#define RGB_APIS_H_

#include "common.h"

//-----------------------------------------------------------------------------
// Antenna RGB LED control.
//
// Only implemented on platforms that actually have an RGB LED (currently PM5,
// driven by an I2C RGB controller). Other platforms don't build this module, so
// callers must guard usage accordingly (e.g. the CMD_PM5_RGB_SET handler).
//-----------------------------------------------------------------------------
void RgbLedSet(uint8_t r, uint8_t g, uint8_t b);

#endif // RGB_APIS_H_
