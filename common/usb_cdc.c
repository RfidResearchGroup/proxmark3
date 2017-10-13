/*
 * at91sam7s USB CDC device implementation
 *
 * Copyright (c) 2012, Roel Verdult
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holders nor the
 * names of its contributors may be used to endorse or promote products
 * derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ''AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * based on the "Basic USB Example" from ATMEL (doc6123.pdf)
 *
 * @file usb_cdc.c
 * @brief
 */

#include "usb_cdc.h"

/*
AT91SAM7S256  USB Device Port
• Embedded 328-byte dual-port RAM for endpoints
• Four endpoints 
– Endpoint 0: 8 bytes
– Endpoint 1 and 2: 64 bytes ping-pong
– Endpoint 3: 64 bytes
– Ping-pong Mode (two memory banks) for bulk endpoints
*/

#define AT91C_EP_CONTROL      0
#define AT91C_EP_CONTROL_SIZE 0x08

#define AT91C_EP_IN          2
#define AT91C_EP_IN_SIZE  0x40

#define AT91C_EP_OUT         1
#define AT91C_EP_OUT_SIZE 0x40

// Section: USB Descriptors
#define USB_DESCRIPTOR_DEVICE           0x01    // bDescriptorType for a Device Descriptor.
#define USB_DESCRIPTOR_CONFIGURATION    0x02    // bDescriptorType for a Configuration Descriptor.
#define USB_DESCRIPTOR_STRING           0x03    // bDescriptorType for a String Descriptor.
#define USB_DESCRIPTOR_INTERFACE        0x04    // bDescriptorType for an Interface Descriptor.
#define USB_DESCRIPTOR_ENDPOINT         0x05    // bDescriptorType for an Endpoint Descriptor.
#define USB_DESCRIPTOR_DEVICE_QUALIFIER 0x06    // bDescriptorType for a Device Qualifier.
#define USB_DESCRIPTOR_OTHER_SPEED      0x07    // bDescriptorType for a Other Speed Configuration.
#define USB_DESCRIPTOR_INTERFACE_POWER  0x08    // bDescriptorType for Interface Power.
#define USB_DESCRIPTOR_OTG              0x09    // bDescriptorType for an OTG Descriptor.

/* Configuration Attributes */
#define _DEFAULT    (0x01<<7)       //Default Value (Bit 7 is set)
#define _SELF       (0x01<<6)       //Self-powered (Supports if set)
#define _RWU        (0x01<<5)       //Remote Wakeup (Supports if set)
#define _HNP	    (0x01 << 1)     //HNP (Supports if set)
#define _SRP	  	(0x01)		    //SRP (Supports if set)

/* Endpoint Transfer Type */
#define _CTRL       0x00            //Control Transfer
#define _ISO        0x01            //Isochronous Transfer
#define _BULK       0x02 			//Bulk Transfer
#define _INTERRUPT  0x03			//Interrupt Transfer
					  
// (bit7 | 0 = OUT, 1 = IN)
#define _EP_IN      0x80
#define _EP_OUT     0x00
#define _EP01_OUT   0x01
#define _EP01_IN    0x81
#define _EP02_OUT   0x02
#define _EP02_IN    0x82
#define _EP03_OUT   0x03
#define _EP03_IN    0x83


/* WCID specific Request Code */
#define MS_OS_DESCRIPTOR_INDEX			0xEE 
#define MS_VENDOR_CODE					0x1C
#define MS_EXTENDED_COMPAT_ID           0x04
#define MS_EXTENDED_PROPERTIES          0x05
#define MS_WCID_GET_DESCRIPTOR			0xC0
#define MS_WCID_GET_FEATURE_DESCRIPTOR	0xC1

static const char devDescriptor[] = {
	/* Device descriptor */
	0x12,      // Length
	0x01,      // Descriptor Type (DEVICE)
	0x10,0x02, // Complies with USB Spec. Release (0200h = release 2.00)  0210 == release 2.10
	0x02,      // Device Class:    CDC class code
	0x02,      // Device Subclass: CDC class sub code ACM [ice 0x02 = win10 virtual comport :) ]
	0x00,      // Device Protocol: CDC Device protocol
	AT91C_EP_CONTROL_SIZE,      // MaxPacketSize0
    0xc4,0x9a, // Vendor ID  [0x9ac4 = J. Westhues]
    0x8f,0x4b, // Product ID [0x4b8f = Proxmark-3 RFID Instrument]
	0x01,0x00, // Device release number (0001)
	0x01,      // index Manufacturer  
	0x02,      // index Product
	0x03,      // index SerialNumber
	0x01       // Number of Configs
};

static const char cfgDescriptor[] = {
	/* ============== CONFIGURATION 1 =========== */
	/* Configuration 1 descriptor */
	0x09,   // Length
	USB_DESCRIPTOR_CONFIGURATION,   // Descriptor Type
	0x43,0x00,   // Total Length 2 EP + Control	
	0x02,   // Number of Interfaces
	0x01,   // Index value of this Configuration
	0x00,   // Configuration string index
	0xC0,   // Attributes 0xA0
	0xFA,   // Max Power consumption

	/* Communication Class Interface Descriptor Requirement */
	0x09, // Length
	USB_DESCRIPTOR_INTERFACE, // Descriptor Type
	0x00, // Interface Number
	0x00, // Alternate Setting
	0x01, // Number of Endpoints in this interface
	0x02, // Interface Class code (CDC)
	0x02, // Interface Subclass code (ACM)
	0x01, // InterfaceProtocol  (rfidler 0x00,  pm3 0x01 == VT25)
	0x00, // iInterface

	/* Header Functional Descriptor */
	0x05, // Function Length
	0x24, // Descriptor type: CS_INTERFACE
	0x00, // Descriptor subtype: Header Func Desc
	0x10,0x01, // bcd CDC:1.1	

	/* ACM Functional Descriptor */
	0x04, // Function Length
	0x24, // Descriptor Type: CS_INTERFACE
	0x02, // Descriptor Subtype: ACM Func Desc
	0x02, // Capabilities  (rfidler 0x04,  pm3 0x02,  zero should also work  )

	/* Union Functional Descriptor */
	0x05, // Function Length
	0x24, // Descriptor Type: CS_INTERFACE
	0x06, // Descriptor Subtype: Union Func Desc
	0x00, // MasterInterface: Communication Class Interface
	0x01, // SlaveInterface0: Data Class Interface

	/* Call Management Functional Descriptor */
	0x05, // Function Length
	0x24, // Descriptor Type: CS_INTERFACE
	0x01, // Descriptor Subtype: Call Management Func Desc 
	0x00, // Capabilities: D1 + D0
	0x01, // Data Interface: Data Class Interface 1

	/* Endpoint descriptor */
	0x07,		// Length
	USB_DESCRIPTOR_ENDPOINT, // Descriptor Type
	_EP03_IN,   // EndpointAddress, Endpoint 03-IN
	_INTERRUPT, // Attributes
	0x08, 0x00, // MaxPacket Size  (pm3 0x08)
	0x02,		// Interval polling (rfidler 0x02,  pm3 0xff)

	/* Data Class Interface Descriptor Requirement */
	0x09, // Length
	USB_DESCRIPTOR_INTERFACE, // Descriptor Type
	0x01, // Interface Number
	0x00, // Alternate Setting
	0x02, // Number of Endpoints
	0x0A, // Interface Class   ( Data interface class )
	0x00, // Interface Subclass
	0x00, // Interface Protocol
	0x00, // Interface - no string descriptor

	/* Endpoint descriptor */
	0x07,   	// Length
	USB_DESCRIPTOR_ENDPOINT, // Descriptor Type
	_EP01_OUT, 	// Endpoint Address, Endpoint 01-OUT
	_BULK,   	// Attributes      BULK
	0x40, 0x00, // MaxPacket Size	
	0x00,   	// Interval	   (ignored for bulk)

	/* Endpoint descriptor */
	0x07,   	// Length
	USB_DESCRIPTOR_ENDPOINT, // DescriptorType
	_EP02_IN,   // Endpoint Address, Endpoint 02-IN
	_BULK,   	// Attributes      BULK
	0x40, 0x00, // MaxPacket Size	
	0x00    	// Interval	   (ignored for bulk)
};

// Microsoft OS Extended Configuration Compatible ID Descriptor
static const char CompatIDFeatureDescriptor[] = {
		0x28, 0x00, 0x00, 0x00,							// Descriptor Length 40bytes (0x28)
		0x00, 0x01,										// Version ('1.0')
		MS_EXTENDED_COMPAT_ID, 0x00,					// Compatibility ID Descriptor Index  0x0004 
		0x01, 											// Number of sections. 0x1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,		// Reserved (7bytes)
		//-----function section 1------		
		0x00,											// Interface Number #0
		0x01,											// reserved 
		0x57, 0x49, 0x4E, 0x55, 0x53, 0x42, 0x00, 0x00,	// Compatible ID  ('WINUSB\0\0')  (8bytes)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// Sub-Compatible ID (8byte)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00				// Reserved (6bytes)
};

// Microsoft Extended Properties Feature Descriptor
static const char OSprop[] = {
		// u32 Descriptor Length (10+132+64+102 == 308
		0x34, 0x01, 0, 0,
		// u16 Version ('1.0')
		0, 1,
		// u16 wIndex
		MS_EXTENDED_PROPERTIES, 0,
		// u16 wCount  -- three section
		3, 0,
		
		//-----property section 1------
		// u32 size  ( 14+40+78 == 132)
		132, 0, 0, 0,
		// u32 type
		1, 0, 0, 0,  // unicode string
		// u16 namelen  (20*2 = 40)
		40, 0,
		// name  DeviceInterfaceGUID
		'D',0,'e',0,'v',0,'i',0,'c',0,'e',0,'I',0,'n',0,'t',0,'e',0,'r',0,'f',0,'a',0,'c',0,'e',0,'G',0,'U',0,'I',0,'D',0,0,0,
		// u32 datalen  (39*2 = 78)
		78, 0, 0, 0,
		// data {4D36E978-E325-11CE-BFC1-08002BE10318}
		'{',0,'4',0,'D',0,'3',0,'6',0,'E',0,'9',0,'7',0,'8',0,'-',0,'E',0,'3',0,'2',0,'5',0,
		'-',0,'1',0,'1',0,'C',0,'E',0,'-',0,'B',0,'F',0,'C',0,'1',0,'-',0,'0',0,'8',0,'0',0,
		'0',0,'2',0,'B',0,'E',0,'1',0,'0',0,'3',0,'1',0,'8',0,'}',0,0,0,		

		//-----property section 2------
		// u32 size  ( 14+12+38 == 64)
		64, 0, 0, 0,
		// u32 type
		1, 0, 0, 0,  // unicode string
		// u16 namelen (12)
		12, 0,
		// name Label
		'L',0,'a',0,'b',0,'e',0,'l',0,0,0,
		// u32 datalen ( 19*2 = 38 )
		38, 0, 0, 0,
		// data 'Awesome PM3 Device'
		'A',0,'w',0,'e',0,'s',0,'o',0,'m',0,'e',0,' ',0,'P',0,'M',0,'3',0,' ',0,'D',0,'e',0,'v',0,'i',0,'c',0,'e',0,0,0,

		//-----property section 3------
		// u32 size ( 14+12+76 == 102)
		102, 0, 0, 0,
		// u32 type
		2, 0, 0, 0,  //Unicode string with environment variables
		// u16 namelen (12)
		12, 0,		
		// name Icons
		'I',0,'c',0,'o',0,'n',0,'s',0,0,0,
		// u32 datalen ( 38*2 ==  76)
		76, 0, 0, 0,
		// data '%SystemRoot%\\system32\\Shell32.dll,-13'
		'%',0,'S',0,'y',0,'s',0,'t',0,'e',0,'m',0,'R',0,'o',0,'o',0,'t',0,'%',0,
		'\\',0,'s',0,'y',0,'s',0,'t',0,'e',0,'m',0,'3',0,'2',0,'\\',0,
		'S',0,'h',0,'e',0,'l',0,'l',0,'3',0,'2',0,'.',0,'d',0,'l',0,'l',0,',',0,
		'-',0,'1',0,'3',0,0,0
};

static const char StrLanguageCodes[] = {
  4,			// Length
  0x03,			// Type is string
  0x09, 0x04	// supported language Code 0 = 0x0409 (English)
};

static const char StrManufacturer[] = {
  26,			// Length
  0x03,			// Type is string
  'p',0,'r',0,'o',0,'x',0,'m',0,'a',0,'r',0,'k',0,'.',0,'o',0,'r',0,'g',0,
};

static const char StrProduct[] = {
	22,			// Length
	0x03,		// Type is string
	'P',0,'M',0,'3',0,' ',0,'D',0,'e',0,'v',0,'i',0,'c',0,'e',0
};

static const char StrSerialNumber[] = {
	18,			// Length
	0x03,		// Type is string
	'8',0,'8',0,'8',0,'8',0,'8',0,'8',0,'8',0,'8',0
};

// size inkluderar sitt egna fält.
static const char StrMS_OSDescriptor[] = {
    18,			// length 0x12
	0x03,		// Type is string
    'M',0,'S',0,'F',0,'T',0,'1',0,'0',0,'0',0,MS_VENDOR_CODE,0
};

const char* getStringDescriptor(uint8_t idx) {
	switch(idx) {
		case 0: return StrLanguageCodes; 
		case 1: return StrManufacturer;
		case 2: return StrProduct;
		case 3: return StrSerialNumber;
		case MS_OS_DESCRIPTOR_INDEX: return StrMS_OSDescriptor;
		default: 
			return(NULL);
	}
}

// Bitmap for all status bits in CSR which must be written as 1 to cause no effect
#define REG_NO_EFFECT_1_ALL      AT91C_UDP_RX_DATA_BK0 | AT91C_UDP_RX_DATA_BK1 \
                                |AT91C_UDP_STALLSENT   | AT91C_UDP_RXSETUP \
                                |AT91C_UDP_TXCOMP

// Clear flags in the UDP_CSR register and waits for synchronization
#define UDP_CLEAR_EP_FLAGS(endpoint, flags) { \
	volatile unsigned int reg; \
	reg = pUdp->UDP_CSR[(endpoint)]; \
	reg |= REG_NO_EFFECT_1_ALL; \
	reg &= ~(flags); \
	pUdp->UDP_CSR[(endpoint)] = reg; \
	while ( (pUdp->UDP_CSR[(endpoint)] & (flags)) == (flags)) {}; \
} \

// reset flags in the UDP_CSR register and waits for synchronization
#define UDP_SET_EP_FLAGS(endpoint, flags) { \
	volatile unsigned int reg; \
	reg = pUdp->UDP_CSR[(endpoint)]; \
	reg |= REG_NO_EFFECT_1_ALL; \
	reg |= (flags); \
	pUdp->UDP_CSR[(endpoint)] = reg; \
	while ( ( pUdp->UDP_CSR[(endpoint)] & (flags)) != (flags)) {}; \
} \

	
/* USB standard request code */
#define STD_GET_STATUS_ZERO           0x0080
#define STD_GET_STATUS_INTERFACE      0x0081
#define STD_GET_STATUS_ENDPOINT       0x0082

#define STD_CLEAR_FEATURE_ZERO        0x0100
#define STD_CLEAR_FEATURE_INTERFACE   0x0101
#define STD_CLEAR_FEATURE_ENDPOINT    0x0102

#define STD_SET_FEATURE_ZERO          0x0300
#define STD_SET_FEATURE_INTERFACE     0x0301
#define STD_SET_FEATURE_ENDPOINT      0x0302

#define STD_SET_ADDRESS               0x0500
#define STD_GET_DESCRIPTOR            0x0680
#define STD_SET_DESCRIPTOR            0x0700
#define STD_GET_CONFIGURATION         0x0880
#define STD_SET_CONFIGURATION         0x0900
#define STD_GET_INTERFACE             0x0A81
#define STD_SET_INTERFACE             0x0B01
#define STD_SYNCH_FRAME               0x0C82

/* CDC Class Specific Request Code */
#define GET_LINE_CODING               0x21A1
#define SET_LINE_CODING               0x2021
#define SET_CONTROL_LINE_STATE        0x2221

typedef struct {
	unsigned int dwDTERRate;
	char bCharFormat;
	char bParityType;
	char bDataBits;
} AT91S_CDC_LINE_CODING, *AT91PS_CDC_LINE_CODING;

AT91S_CDC_LINE_CODING line = {
	115200, // baudrate
	0,      // 1 Stop Bit
	0,      // None Parity
	8};     // 8 Data bits

AT91PS_UDP pUdp = AT91C_BASE_UDP;
uint16_t btConfiguration = 0;
uint16_t btConnection    = 0;
byte_t btReceiveBank   = AT91C_UDP_RX_DATA_BK0;

//*----------------------------------------------------------------------------
//* \fn    usb_disable
//* \brief This function deactivates the USB device
//*----------------------------------------------------------------------------
void usb_disable() {
	// Disconnect the USB device
	AT91C_BASE_PIOA->PIO_ODR = GPIO_USB_PU;

	// Clear all lingering interrupts
	if (pUdp->UDP_ISR & AT91C_UDP_ENDBUSRES) {
		pUdp->UDP_ICR = AT91C_UDP_ENDBUSRES;
	}
}

//*----------------------------------------------------------------------------
//* \fn    usb_enable
//* \brief This function Activates the USB device
//*----------------------------------------------------------------------------
void usb_enable() {
	// Set the PLL USB Divider
	AT91C_BASE_CKGR->CKGR_PLLR |= AT91C_CKGR_USBDIV_1 ;

	// Specific Chip USB Initialisation
	// Enables the 48MHz USB clock UDPCK and System Peripheral USB Clock
	AT91C_BASE_PMC->PMC_SCER = AT91C_PMC_UDP;
	AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_UDP);

	// Enable UDP PullUp (USB_DP_PUP) : enable & Clear of the corresponding PIO
	// Set in PIO mode and Configure in Output
	AT91C_BASE_PIOA->PIO_PER = GPIO_USB_PU; // Set in PIO mode
	AT91C_BASE_PIOA->PIO_OER = GPIO_USB_PU; // Configure as Output

	// Clear for set the Pullup resistor
	AT91C_BASE_PIOA->PIO_CODR = GPIO_USB_PU;

	// Disconnect and reconnect USB controller for 100ms
	usb_disable();

	// Wait for a short while
	for (volatile size_t i=0; i<0x100000; i++) {};
	
	// Reconnect USB reconnect
	AT91C_BASE_PIOA->PIO_SODR = GPIO_USB_PU;
	AT91C_BASE_PIOA->PIO_OER = GPIO_USB_PU;
}

//*----------------------------------------------------------------------------
//* \fn    usb_check
//* \brief Test if the device is configured and handle enumeration
//*----------------------------------------------------------------------------
static int usb_reconnect = 0;
static int usb_configured = 0;
void SetUSBreconnect(int value) {
	usb_reconnect = value;
}
int GetUSBreconnect(void) {
	return usb_reconnect;
}
void SetUSBconfigured(int value) {
	usb_configured = value;
}
int GetUSBconfigured(void){
	return usb_configured;
}

bool usb_check() {
	
	/*
	// reconnected ONCE and 
	if ( !USB_ATTACHED() ){
		usb_reconnect = 1;
		LED_C_INV();
		LED_C_INV();
		LED_C_INV();
		LED_C_INV();
		LED_C_INV();
		LED_C_INV();
		return false;
	}
	
	// only one time after USB been disengaged and re-engaged	
	if ( USB_ATTACHED() && usb_reconnect == 1 ) {
			
		if ( usb_configured == 0) {			
			// blink
			LED_D_INV();
			LED_D_INV();
			LED_D_INV();
			LED_D_INV();
			LED_D_INV();
			LED_D_INV();
			LED_D_INV();
			LED_D_INV();
			LED_D_INV();
			LED_D_INV();
		
			usb_disable();
			usb_enable();		

			AT91F_CDC_Enumerate();
			
			usb_configured = 1;
			return false;
		}
	}
	*/

	WDT_HIT();
	
	// interrupt status register
	AT91_REG isr = pUdp->UDP_ISR;

	// end of bus reset
	if (isr & AT91C_UDP_ENDBUSRES) {
		pUdp->UDP_ICR = AT91C_UDP_ENDBUSRES;
		// reset all endpoints
		pUdp->UDP_RSTEP  = (unsigned int)-1;
		pUdp->UDP_RSTEP  = 0;
		// Enable the function
		pUdp->UDP_FADDR = AT91C_UDP_FEN;
		// Configure endpoint 0  (enable control endpoint)
		UDP_SET_EP_FLAGS(AT91C_EP_CONTROL, (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_CTRL));
		// clear it
		pUdp->UDP_ICR |= AT91C_UDP_ENDBUSRES;
	}
	else if (isr & AT91C_UDP_EPINT0) {
		pUdp->UDP_ICR = AT91C_UDP_EPINT0;
		AT91F_CDC_Enumerate();
		// clear it?
		pUdp->UDP_ICR |= AT91C_UDP_EPINT0;
	}
	return (btConfiguration) ? true : false;
}

bool usb_poll() {
	if (!usb_check()) return false;
	return (pUdp->UDP_CSR[AT91C_EP_OUT] & btReceiveBank);
}

/**
	In github PR #129, some users appears to get a false positive from
	usb_poll, which returns true, but the usb_read operation
	still returns 0.
	This check is basically the same as above, but also checks
	that the length available to read is non-zero, thus hopefully fixes the
	bug.
**/
bool usb_poll_validate_length() {
	if (!usb_check()) return false;
	if (!(pUdp->UDP_CSR[AT91C_EP_OUT] & btReceiveBank)) return false;
	return (pUdp->UDP_CSR[AT91C_EP_OUT] >> 16) >  0;
}

//*----------------------------------------------------------------------------
//* \fn    usb_read
//* \brief Read available data from Endpoint OUT
//*----------------------------------------------------------------------------
uint32_t usb_read(byte_t* data, size_t len) {
	byte_t bank = btReceiveBank;
	uint32_t packetSize, nbBytesRcv = 0;
	uint32_t time_out = 0;
  
	while (len)  {
		if (!usb_check()) break;

		if ( pUdp->UDP_CSR[AT91C_EP_OUT] & bank ) {
			packetSize = MIN(pUdp->UDP_CSR[AT91C_EP_OUT] >> 16, len);
			len -= packetSize;
			while (packetSize--)
				data[nbBytesRcv++] = pUdp->UDP_FDR[AT91C_EP_OUT];

			UDP_CLEAR_EP_FLAGS(AT91C_EP_OUT, bank)			

			if (bank == AT91C_UDP_RX_DATA_BK0)
				bank = AT91C_UDP_RX_DATA_BK1;
			else
				bank = AT91C_UDP_RX_DATA_BK0;		
		}
		if (time_out++ == 0x1fff) break;
	}

	btReceiveBank = bank;
	return nbBytesRcv;
}

//*----------------------------------------------------------------------------
//* \fn    usb_write
//* \brief Send through endpoint 2
//*----------------------------------------------------------------------------
uint32_t usb_write(const byte_t* data, const size_t len) {

	if (!len) return 0;
	if (!usb_check()) return 0;
	
	size_t length = len;
	uint32_t cpt = 0;
 
	// Send the first packet
	cpt = MIN(length, AT91C_EP_IN_SIZE-1);
	length -= cpt;
	while (cpt--) pUdp->UDP_FDR[AT91C_EP_IN] = *data++;

	UDP_SET_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXPKTRDY)

	while (length) {
		// Fill the second bank
		cpt = MIN(length, AT91C_EP_IN_SIZE-1);
		length -= cpt;
		while (cpt--) pUdp->UDP_FDR[AT91C_EP_IN] = *data++;
		// Wait for the first bank to be sent
		while (!(pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP)) {
			if (!usb_check()) return length;
		}
		
		UDP_CLEAR_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXCOMP)
	
		UDP_SET_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXPKTRDY)
	}
  
	// Wait for the end of transfer
	while (!(pUdp->UDP_CSR[AT91C_EP_IN] & AT91C_UDP_TXCOMP)) {
		if (!usb_check()) return length;
	}

	UDP_CLEAR_EP_FLAGS(AT91C_EP_IN, AT91C_UDP_TXCOMP)

	return length;
}

//*----------------------------------------------------------------------------
//* \fn    AT91F_USB_SendData
//* \brief Send Data through the control endpoint
//*----------------------------------------------------------------------------
void AT91F_USB_SendData(AT91PS_UDP pUdp, const char *pData, uint32_t length) {
	uint32_t cpt = 0;

	do {
		cpt = MIN(length, AT91C_EP_CONTROL_SIZE);
		length -= cpt;

		while (cpt--)
			pUdp->UDP_FDR[0] = *pData++;

		if (pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_TXCOMP) {
			
			UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXCOMP)
		}

		UDP_SET_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXPKTRDY)

		do {
			// Data IN stage has been stopped by a status OUT
			if ( pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_RX_DATA_BK0) {
				
				UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_RX_DATA_BK0)
				return;
			}
		} while ( !( pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_TXCOMP) );

	} while (length);

	if (pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_TXCOMP) {
		
		UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXCOMP)
	}
}

//*----------------------------------------------------------------------------
//* \fn    AT91F_USB_SendZlp
//* \brief Send zero length packet through the control endpoint
//*----------------------------------------------------------------------------
void AT91F_USB_SendZlp(AT91PS_UDP pUdp) {
	UDP_SET_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXPKTRDY);	
	UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_TXCOMP);
}

//*----------------------------------------------------------------------------
//* \fn    AT91F_USB_SendStall
//* \brief Stall the control endpoint
//*----------------------------------------------------------------------------
void AT91F_USB_SendStall(AT91PS_UDP pUdp) {
	UDP_SET_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_FORCESTALL);
	while ( !(pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_ISOERROR) );
	UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, (AT91C_UDP_FORCESTALL | AT91C_UDP_ISOERROR));	
}

//*----------------------------------------------------------------------------
//* \fn    AT91F_CDC_Enumerate
//* \brief This function is a callback invoked when a SETUP packet is received
//*----------------------------------------------------------------------------
void AT91F_CDC_Enumerate() {
	byte_t bmRequestType, bRequest;
	uint16_t wValue, wIndex, wLength, wStatus;

	if ( !(pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_RXSETUP) )
		return;

	bmRequestType = pUdp->UDP_FDR[0];
	bRequest      = pUdp->UDP_FDR[0];
	wValue        = (pUdp->UDP_FDR[0] & 0xFF);
	wValue       |= (pUdp->UDP_FDR[0] << 8);
	wIndex        = (pUdp->UDP_FDR[0] & 0xFF);
	wIndex       |= (pUdp->UDP_FDR[0] << 8);
	wLength       = (pUdp->UDP_FDR[0] & 0xFF);
	wLength      |= (pUdp->UDP_FDR[0] << 8);

	if (bmRequestType & 0x80) {
		UDP_SET_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_DIR)
	}
	UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_RXSETUP)

	if ( bRequest == MS_VENDOR_CODE) {
		if ( bmRequestType == MS_WCID_GET_DESCRIPTOR ) { // C0
			if ( wIndex == MS_EXTENDED_COMPAT_ID ) {  // 4
				AT91F_USB_SendData(pUdp, CompatIDFeatureDescriptor, MIN(sizeof(CompatIDFeatureDescriptor), wLength));
				return;
			} 
		}
		if ( bmRequestType == MS_WCID_GET_FEATURE_DESCRIPTOR ) {  //C1
			//if ( wIndex == MS_EXTENDED_PROPERTIES ) { // 5  - winusb bug with wIndex == interface index,  so I just send it always)
				AT91F_USB_SendData(pUdp, OSprop, MIN(sizeof(OSprop), wLength));
				return;
			//} 
		}
	}
	// Handle supported standard device request Cf Table 9-3 in USB specification Rev 1.1
	switch ((bRequest << 8) | bmRequestType) {
	case STD_GET_DESCRIPTOR:
		if (wValue == 0x100)       // Return Device Descriptor
			AT91F_USB_SendData(pUdp, devDescriptor, MIN(sizeof(devDescriptor), wLength));
		else if (wValue == 0x200)  // Return Configuration Descriptor
			AT91F_USB_SendData(pUdp, cfgDescriptor, MIN(sizeof(cfgDescriptor), wLength));
		else if ((wValue & 0x300) == 0x300) { // Return String Descriptor
			
			const char *strDescriptor = getStringDescriptor(wValue & 0xff);
			if (strDescriptor != NULL) {
				AT91F_USB_SendData(pUdp, strDescriptor, MIN(strDescriptor[0], wLength));
			} else {
				AT91F_USB_SendStall(pUdp);
			}
		}
		else
			AT91F_USB_SendStall(pUdp);
		break;
	case STD_SET_ADDRESS:
		AT91F_USB_SendZlp(pUdp);
		pUdp->UDP_FADDR = (AT91C_UDP_FEN | wValue);
		pUdp->UDP_GLBSTATE  = (wValue) ? AT91C_UDP_FADDEN : 0;
		break;
	case STD_SET_CONFIGURATION:
		btConfiguration = wValue;
		AT91F_USB_SendZlp(pUdp);
		pUdp->UDP_GLBSTATE  = (wValue) ? AT91C_UDP_CONFG : AT91C_UDP_FADDEN;
		
		UDP_SET_EP_FLAGS(1, (wValue) ? (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_OUT) : 0 );
		UDP_SET_EP_FLAGS(2, (wValue) ? (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_IN)  : 0 ); 
		UDP_SET_EP_FLAGS(3, (wValue) ? (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_INT_IN)   : 0 );
//		pUdp->UDP_CSR[1] = (wValue) ? (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_OUT) : 0;
//		pUdp->UDP_CSR[2] = (wValue) ? (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_IN)  : 0;
//		pUdp->UDP_CSR[3] = (wValue) ? (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_INT_IN)   : 0;
		break;
	case STD_GET_CONFIGURATION:
		AT91F_USB_SendData(pUdp, (char *) &(btConfiguration), sizeof(btConfiguration));
		break;
	case STD_GET_STATUS_ZERO:
		wStatus = 0;
		AT91F_USB_SendData(pUdp, (char *) &wStatus, sizeof(wStatus));
		break;
	case STD_GET_STATUS_INTERFACE:
		wStatus = 0;
		AT91F_USB_SendData(pUdp, (char *) &wStatus, sizeof(wStatus));
		break;
	case STD_GET_STATUS_ENDPOINT:
		wStatus = 0;
		wIndex &= 0x0F;
		if ((pUdp->UDP_GLBSTATE & AT91C_UDP_CONFG) && (wIndex <= 3)) {
			wStatus = (pUdp->UDP_CSR[wIndex] & AT91C_UDP_EPEDS) ? 0 : 1;
			AT91F_USB_SendData(pUdp, (char *) &wStatus, sizeof(wStatus));
		}
		else if ((pUdp->UDP_GLBSTATE & AT91C_UDP_FADDEN) && (wIndex == 0)) {
			wStatus = (pUdp->UDP_CSR[wIndex] & AT91C_UDP_EPEDS) ? 0 : 1;
			AT91F_USB_SendData(pUdp, (char *) &wStatus, sizeof(wStatus));
		} else {
			AT91F_USB_SendStall(pUdp);
		}
		break;
	case STD_SET_FEATURE_ZERO:
		AT91F_USB_SendStall(pUdp);
	    break;
	case STD_SET_FEATURE_INTERFACE:
		AT91F_USB_SendZlp(pUdp);
		break;
	case STD_SET_FEATURE_ENDPOINT:
		wIndex &= 0x0F;
		if ((wValue == 0) && wIndex && (wIndex <= 3)) {
			pUdp->UDP_CSR[wIndex] = 0;
			AT91F_USB_SendZlp(pUdp);
		} else {
			AT91F_USB_SendStall(pUdp);
		}
		break;
	case STD_CLEAR_FEATURE_ZERO:
		AT91F_USB_SendStall(pUdp);
	    break;
	case STD_CLEAR_FEATURE_INTERFACE:
		AT91F_USB_SendZlp(pUdp);
		break;
	case STD_CLEAR_FEATURE_ENDPOINT:
		wIndex &= 0x0F;
		if ((wValue == 0) && wIndex && (wIndex <= 3)) {
			if (wIndex == 1) {
				//pUdp->UDP_CSR[1] = (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_OUT);
				UDP_SET_EP_FLAGS(1, (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_OUT) );
			}
			else if (wIndex == 2) {
				//pUdp->UDP_CSR[2] = (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_IN);
				UDP_SET_EP_FLAGS(2, (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_BULK_IN) );
			}
			else if (wIndex == 3) {
				//pUdp->UDP_CSR[3] = (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_ISO_IN);
				UDP_SET_EP_FLAGS(3, (AT91C_UDP_EPEDS | AT91C_UDP_EPTYPE_ISO_IN) );
			}
			AT91F_USB_SendZlp(pUdp);
		} else {
			AT91F_USB_SendStall(pUdp);
		}
		break;

	// handle CDC class requests
	case SET_LINE_CODING:
		// ignor SET_LINE_CODING...
		while ( !(pUdp->UDP_CSR[AT91C_EP_CONTROL] & AT91C_UDP_RX_DATA_BK0) );
		UDP_CLEAR_EP_FLAGS(AT91C_EP_CONTROL, AT91C_UDP_RX_DATA_BK0);
		AT91F_USB_SendZlp(pUdp);
		break;
	case GET_LINE_CODING:
		AT91F_USB_SendData(pUdp, (char *) &line, MIN(sizeof(line), wLength));
		break;
	case SET_CONTROL_LINE_STATE:
		btConnection = wValue;
		AT91F_USB_SendZlp(pUdp);
		break;
	default:
		AT91F_USB_SendStall(pUdp);
	    break;
	}
}