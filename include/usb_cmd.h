//-----------------------------------------------------------------------------
// Definitions for all the types of commands that may be sent over USB; our
// own protocol.
// Jonathan Westhues, Mar 2006
// Edits by Gerhard de Koning Gans, Sep 2007
//-----------------------------------------------------------------------------

#ifndef __USB_CMD_H
#define __USB_CMD_H

typedef struct {
	DWORD	cmd;
	DWORD	ext1;
	DWORD	ext2;
	DWORD	ext3;
	union {
		BYTE	asBytes[48];
		DWORD	asDwords[12];
	} d;
} UsbCommand;

// For the bootloader
#define CMD_DEVICE_INFO																0x0000
#define CMD_SETUP_WRITE																0x0001
#define CMD_FINISH_WRITE															0x0003
#define CMD_HARDWARE_RESET														0x0004
#define CMD_START_FLASH																0x0005
#define CMD_NACK																				0x00fe
#define CMD_ACK																				0x00ff

// For general mucking around
#define CMD_DEBUG_PRINT_STRING												0x0100
#define CMD_DEBUG_PRINT_INTEGERS											0x0101
#define CMD_DEBUG_PRINT_BYTES													0x0102
#define CMD_LCD_RESET																	0x0103
#define CMD_LCD																				0x0104
#define CMD_BUFF_CLEAR																0x0105
#define CMD_READ_MEM																	0x0106
#define CMD_VERSION																	0x0107

// For low-frequency tags
#define CMD_READ_TI_TYPE															0x0202
#define CMD_WRITE_TI_TYPE															0x0203
#define CMD_DOWNLOADED_RAW_BITS_TI_TYPE								0x0204
#define CMD_ACQUIRE_RAW_ADC_SAMPLES_125K							0x0205
#define CMD_MOD_THEN_ACQUIRE_RAW_ADC_SAMPLES_125K			0x0206
#define CMD_DOWNLOAD_RAW_ADC_SAMPLES_125K							0x0207
#define CMD_DOWNLOADED_RAW_ADC_SAMPLES_125K						0x0208
#define CMD_DOWNLOADED_SIM_SAMPLES_125K								0x0209
#define CMD_SIMULATE_TAG_125K													0x020A
#define CMD_HID_DEMOD_FSK															0x020B
#define CMD_HID_SIM_TAG																0x020C
#define CMD_SET_LF_DIVISOR														0x020D
#define CMD_LF_SIMULATE_BIDIR														0x020E
#define CMD_SET_ADC_MUX										0x020F
/* CMD_SET_ADC_MUX: ext1 is 0 for lopkd, 1 for loraw, 2 for hipkd, 3 for hiraw */

// For the 13.56 MHz tags
#define CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_15693					0x0300
#define CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443					0x0301
#define CMD_ACQUIRE_RAW_ADC_SAMPLES_ISO_14443_SIM			0x0302
#define CMD_READ_SRI512_TAG														0x0303
#define CMD_READER_ISO_15693													0x0310
#define CMD_SIMTAG_ISO_15693													0x0311
#define CMD_SIMULATE_TAG_HF_LISTEN										0x0380
#define CMD_SIMULATE_TAG_ISO_14443										0x0381
#define CMD_SNOOP_ISO_14443														0x0382
#define CMD_SNOOP_ISO_14443a													0x0383
#define CMD_SIMULATE_TAG_ISO_14443a										0x0384
#define CMD_READER_ISO_14443a													0x0385
#define CMD_SIMULATE_MIFARE_CARD											0x0386

// For measurements of the antenna tuning
#define CMD_MEASURE_ANTENNA_TUNING										0x0400
#define CMD_MEASURED_ANTENNA_TUNING										0x0401
#define CMD_LISTEN_READER_FIELD												0x0402

// For direct FPGA control
#define CMD_FPGA_MAJOR_MODE_OFF												0x0500

// CMD_DEVICE_INFO response packet has flags in ext1, flag definitions:
#define DEVICE_INFO_FLAG_BOOTROM_PRESENT         (1<<0) /* Whether a bootloader that understands the common_area is present */ 
#define DEVICE_INFO_FLAG_OSIMAGE_PRESENT         (1<<1) /* Whether a osimage that understands the common_area is present */
#define DEVICE_INFO_FLAG_CURRENT_MODE_BOOTROM    (1<<2) /* Set if the bootloader is currently executing */
#define DEVICE_INFO_FLAG_CURRENT_MODE_OS         (1<<3) /* Set if the OS is currently executing */
#define DEVICE_INFO_FLAG_UNDERSTANDS_START_FLASH (1<<4) /* Set if this device understands the extend start flash command */

// CMD_START_FLASH may have three arguments: start of area to flash, end of area to flash, optional magic defined below
#define START_FLASH_MAGIC 0x54494f44 /* The bootrom will not allow to overwrite itself unless this magic is given as third parameter */

#endif
