#ifndef __I2C_H
#define __I2C_H

#include <stddef.h>
#include "proxmark3.h"
#include "apps.h"
#include "BigBuf.h"
#include "mifare.h"

#define I2C_DEVICE_ADDRESS_BOOT     0xB0
#define I2C_DEVICE_ADDRESS_MAIN     0xC0

#define I2C_DEVICE_CMD_GENERATE_ATR 0x01
#define I2C_DEVICE_CMD_SEND         0x02
#define I2C_DEVICE_CMD_READ         0x03
#define I2C_DEVICE_CMD_SETBAUD      0x04
#define I2C_DEVICE_CMD_SIM_CLC      0x05
#define I2C_DEVICE_CMD_GETVERSION   0x06
#define I2C_DEVICE_CMD_SEND_T0      0x07


void I2C_recovery(void);
void I2C_init(void);
void I2C_Reset(void);
void I2C_SetResetStatus(uint8_t LineRST, uint8_t LineSCK, uint8_t LineSDA);

void I2C_Reset_EnterMainProgram(void);
void I2C_Reset_EnterBootloader(void);

bool I2C_WriteCmd(uint8_t device_cmd, uint8_t device_address);

bool I2C_WriteByte(uint8_t data, uint8_t device_cmd, uint8_t device_address);
bool I2C_BufferWrite(uint8_t *data, uint8_t len, uint8_t device_cmd, uint8_t device_address);
int16_t I2C_BufferRead(uint8_t *data, uint8_t len, uint8_t device_cmd, uint8_t device_address);

// for firmware
int16_t I2C_ReadFW(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);
bool I2C_WriteFW(uint8_t *data, uint8_t len, uint8_t msb, uint8_t lsb, uint8_t device_address);

//
bool GetATR(smart_card_atr_t *card_ptr);

// generice functions
void SmartCardAtr(void);
void SmartCardRaw(uint64_t arg0, uint64_t arg1, uint8_t *data);
void SmartCardUpgrade(uint64_t arg0);
void SmartCardSetBaud(uint64_t arg0);
void SmartCardSetClock(uint64_t arg0);
void I2C_print_status(void);
int I2C_get_version(uint8_t *maj, uint8_t *min);
#endif
