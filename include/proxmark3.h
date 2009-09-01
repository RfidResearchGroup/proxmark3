//-----------------------------------------------------------------------------
// Definitions of interest to most of the software for this project.
// Jonathan Westhues, Mar 2006
//-----------------------------------------------------------------------------

#ifndef __PROXMARK3_H
#define __PROXMARK3_H

// Might as well have the hardware-specific defines everywhere.
#include <at91sam7s128.h>

#include <config_gpio.h>
#define LOW(x)	PIO_OUTPUT_DATA_CLEAR = (1 << (x))
#define HIGH(x)	PIO_OUTPUT_DATA_SET = (1 << (x))

#define SPI_FPGA_MODE	0
#define SPI_LCD_MODE	1

typedef unsigned long DWORD;
typedef signed long SDWORD;
typedef unsigned long long QWORD;
typedef int BOOL;
typedef unsigned char BYTE;
typedef signed char SBYTE;
typedef unsigned short WORD;
typedef signed short SWORD;
#define TRUE 1
#define FALSE 0

#include <usb_cmd.h>

#define PACKED __attribute__((__packed__))

#define USB_D_PLUS_PULLUP_ON() { \
		PIO_OUTPUT_DATA_SET = (1<<GPIO_USB_PU); \
		PIO_OUTPUT_ENABLE = (1<<GPIO_USB_PU); \
	}
#define USB_D_PLUS_PULLUP_OFF() PIO_OUTPUT_DISABLE = (1<<GPIO_USB_PU)

#define LED_A_ON()		PIO_OUTPUT_DATA_SET = (1<<GPIO_LED_A)
#define LED_A_OFF()		PIO_OUTPUT_DATA_CLEAR = (1<<GPIO_LED_A)
#define LED_B_ON()		PIO_OUTPUT_DATA_SET = (1<<GPIO_LED_B)
#define LED_B_OFF()		PIO_OUTPUT_DATA_CLEAR = (1<<GPIO_LED_B)
#define LED_C_ON()		PIO_OUTPUT_DATA_SET = (1<<GPIO_LED_C)
#define LED_C_OFF()		PIO_OUTPUT_DATA_CLEAR = (1<<GPIO_LED_C)
#define LED_D_ON()		PIO_OUTPUT_DATA_SET = (1<<GPIO_LED_D)
#define LED_D_OFF()		PIO_OUTPUT_DATA_CLEAR = (1<<GPIO_LED_D)
#define RELAY_ON()		PIO_OUTPUT_DATA_SET = (1<<GPIO_RELAY)
#define RELAY_OFF()		PIO_OUTPUT_DATA_CLEAR = (1<<GPIO_RELAY)
#define BUTTON_PRESS()	!(PIO_PIN_DATA_STATUS & (1<<GPIO_BUTTON))
//--------------------------------
// USB declarations

void UsbSendPacket(BYTE *packet, int len);
BOOL UsbConnected();
BOOL UsbPoll(BOOL blinkLeds);
void UsbStart(void);

// This function is provided by the apps/bootrom, and called from UsbPoll
// if data are available.
void UsbPacketReceived(BYTE *packet, int len);

#define VERSION_INFORMATION_MAGIC 0x56334d50
struct version_information {
	int magic; /* Magic sequence to identify this as a correct version information structure. Must be VERSION_INFORMATION_MAGIC */ 
	char versionversion; /* Must be 1 */
	char present; /* 1 if the version information could be created at compile time, otherwise 0 and the remaining fields (except for magic) are empty */
	char clean; /* 1: Tree was clean, no local changes. 0: Tree was unclean. 2: Couldn't be determined */
	char svnversion[9]; /* String with the SVN revision */
	char buildtime[30]; /* string with the build time */
} __attribute__((packed));

#define COMMON_AREA_MAGIC 0x43334d50
#define COMMON_AREA_COMMAND_NONE 0
#define COMMON_AREA_COMMAND_ENTER_FLASH_MODE 1
struct common_area {
	int magic; /* Magic sequence, to distinguish against random uninitialized memory */
	char version; /* Must be 1 */
	char command;
	struct {
		unsigned int bootrom_present:1; /* Set when a bootrom that is capable of parsing the common area is present */
		unsigned int osimage_present:1; /* Set when a osimage that is capable of parsing the common area is present */
	} __attribute__((packed)) flags;
	int arg1, arg2;
} __attribute__((packed));

#endif
