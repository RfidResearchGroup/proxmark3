#ifndef __I2C_H
#define __I2C_H

#include <stddef.h>
#include "proxmark3.h"
#include "apps.h"
#include "util.h"


#define I2C_DEVICE_ADDRESS_BOOT		0xB0
#define I2C_DEVICE_ADDRESS_MAIN		0xC0

#define I2C_DEVICE_CMD_GENERATE_ATR	0x01
#define I2C_DEVICE_CMD_SEND			0x02
#define I2C_DEVICE_CMD_READ			0x03
#define I2C_DEVICE_CMD_SETBAUD		0x04
#define I2C_DEVICE_CMD_SIM_CLC		0x05
#define I2C_DEVICE_CMD_GETVERSION	0x06


void I2C_init(void);
void I2C_Reset(void);
void I2C_SetResetStatus(uint8_t LineRST, uint8_t LineSCK, uint8_t LineSDA);

void I2C_Reset_EnterMainProgram(void);
void I2C_Reset_EnterBootloader(void);

bool I2C_WriteByte(uint8_t SendData, uint8_t device_cmd, uint8_t device_address);
bool I2C_BufferWrite(uint8_t *data, uint8_t len, uint8_t device_cmd, uint8_t device_address);
uint8_t I2C_BufferRead(uint8_t *data, uint8_t len, uint8_t device_cmd, uint8_t device_address);

void i2c_print_status(void);
#endif