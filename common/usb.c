//-----------------------------------------------------------------------------
// Jonathan Westhues, split Aug 14 2005
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// The common USB driver used for both the bootloader and the application.
//-----------------------------------------------------------------------------

#include <proxmark3.h>

#define min(a, b) (((a) > (b)) ? (b) : (a))

#define USB_REPORT_PACKET_SIZE 64

typedef struct PACKED {
	uint8_t		bmRequestType;
	uint8_t		bRequest;
	uint16_t	wValue;
	uint16_t	wIndex;
	uint16_t	wLength;
} UsbSetupData;

#define USB_REQUEST_GET_STATUS					0
#define USB_REQUEST_CLEAR_FEATURE				1
#define USB_REQUEST_SET_FEATURE					3
#define USB_REQUEST_SET_ADDRESS					5
#define USB_REQUEST_GET_DESCRIPTOR				6
#define USB_REQUEST_SET_DESCRIPTOR				7
#define USB_REQUEST_GET_CONFIGURATION			8
#define USB_REQUEST_SET_CONFIGURATION			9
#define USB_REQUEST_GET_INTERFACE				10
#define USB_REQUEST_SET_INTERFACE				11
#define USB_REQUEST_SYNC_FRAME					12

#define USB_DESCRIPTOR_TYPE_DEVICE				1
#define USB_DESCRIPTOR_TYPE_CONFIGURATION		2
#define USB_DESCRIPTOR_TYPE_STRING				3
#define USB_DESCRIPTOR_TYPE_INTERFACE			4
#define USB_DESCRIPTOR_TYPE_ENDPOINT			5
#define USB_DESCRIPTOR_TYPE_DEVICE_QUALIFIER	6
#define USB_DESCRIPTOR_TYPE_OTHER_SPEED_CONF	7
#define USB_DESCRIPTOR_TYPE_INTERFACE_POWER		8
#define USB_DESCRIPTOR_TYPE_HID					0x21
#define USB_DESCRIPTOR_TYPE_HID_REPORT			0x22

#define USB_DEVICE_CLASS_HID					0x03

static const uint8_t HidReportDescriptor[] = {
	0x06,0xA0,0xFF,	// Usage Page (vendor defined) FFA0
	0x09,0x01,		// Usage (vendor defined)
	0xA1,0x01,	 	// Collection (Application)
	0x09,0x02,   	// Usage (vendor defined)
	0xA1,0x00,   	// Collection (Physical)
	0x06,0xA1,0xFF,	// Usage Page (vendor defined)

	//The,input report
	0x09,0x03,   	// usage - vendor defined
	0x09,0x04,   	// usage - vendor defined
	0x15,0x80,   	// Logical Minimum (-128)
	0x25,0x7F,   	// Logical Maximum (127)
	0x35,0x00,   	// Physical Minimum (0)
	0x45,0xFF,   	// Physical Maximum (255)
	0x75,0x08,   	// Report Size (8)  (bits)
	0x95,0x40,   	// Report Count (64)  (fields)
	0x81,0x02,   	// Input (Data,Variable,Absolute)

	//The,output report
	0x09,0x05,   	// usage - vendor defined
	0x09,0x06,   	// usage - vendor defined
	0x15,0x80,   	// Logical Minimum (-128)
	0x25,0x7F,   	// Logical Maximum (127)
	0x35,0x00,   	// Physical Minimum (0)
	0x45,0xFF,   	// Physical Maximum (255)
	0x75,0x08,   	// Report Size (8)  (bits)
	0x95,0x40,   	// Report Count (64)  (fields)
	0x91,0x02,   	// Output (Data,Variable,Absolute)

	0xC0,			// End Collection

	0xC0,			// End Collection
};

static const uint8_t DeviceDescriptor[] = {
	0x12,			// Descriptor length (18 bytes)
	0x01,			// Descriptor type (Device)
	0x10,0x01,		// Complies with USB Spec. Release (0110h = release 1.10)
	0x00,			// Class code (0)
	0x00,			// Subclass code (0)
	0x00,			// Protocol (No specific protocol)
	0x08,			// Maximum packet size for Endpoint 0 (8 bytes)
	0xc4,0x9a,		// Vendor ID (random numbers)
	0x8f,0x4b,		// Product ID (random numbers)
	0x01,0x00,		// Device release number (0001)
	0x01,			// Manufacturer string descriptor index
	0x02,			// Product string descriptor index
	0x00,			// Serial Number string descriptor index (None)
	0x01,			// Number of possible configurations (1)
};

static const uint8_t ConfigurationDescriptor[] = {
	0x09,			// Descriptor length (9 bytes)
	0x02,			// Descriptor type (Configuration)
	0x29,0x00,		// Total data length (41 bytes)
	0x01,			// Interface supported (1)
	0x01,			// Configuration value (1)
	0x00,			// Index of string descriptor (None)
	0x80,			// Configuration (Bus powered)
	250,			// Maximum power consumption (500mA)

	//interface
	0x09,			// Descriptor length (9 bytes)
	0x04,			// Descriptor type (Interface)
	0x00,			// Number of interface (0)
	0x00,			// Alternate setting (0)
	0x02,			// Number of interface endpoint (2)
	0x03,			// Class code (HID)
	0x00,			// Subclass code ()
	0x00,			// Protocol code ()
	0x00,			// Index of string()

	// class
	0x09,			// Descriptor length (9 bytes)
	0x21,			// Descriptor type (HID)
	0x00,0x01,		// HID class release number (1.00)
	0x00,			// Localized country code (None)
	0x01,			// # of HID class dscrptr to follow (1)
	0x22,			// Report descriptor type (HID)
	// Total length of report descriptor
	sizeof(HidReportDescriptor),0x00,

	// endpoint 1
	0x07,			// Descriptor length (7 bytes)
	0x05,			// Descriptor type (Endpoint)
	0x01,			// Encoded address (Respond to OUT)
	0x03,			// Endpoint attribute (Interrupt transfer)
	0x08,0x00,		// Maximum packet size (8 bytes)
	0x01,			// Polling interval (1 ms)

	// endpoint 2
	0x07,			// Descriptor length (7 bytes)
	0x05,			// Descriptor type (Endpoint)
	0x82,			// Encoded address (Respond to IN)
	0x03,			// Endpoint attribute (Interrupt transfer)
	0x08,0x00,		// Maximum packet size (8 bytes)
	0x01,			// Polling interval (1 ms)
};

static const uint8_t StringDescriptor0[] = {
	0x04,			// Length
	0x03,			// Type is string
	0x09,			// English
	0x04,			//  US
};

static const uint8_t StringDescriptor1[] = {
	24,				// Length
	0x03,			// Type is string
	'J', 0x00,
	'.', 0x00,
	' ', 0x00,
	'W', 0x00,
	'e', 0x00,
	's', 0x00,
	't', 0x00,
	'h', 0x00,
	'u', 0x00,
	'e', 0x00,
	's', 0x00,
};

static const uint8_t StringDescriptor2[] = {
	54,				// Length
	0x03,			// Type is string
	'P', 0x00,
	'r', 0x00,
	'o', 0x00,
	'x', 0x00,
	'M', 0x00,
	'a', 0x00,
	'r', 0x00,
	'k', 0x00,
	'-', 0x00,
	'3', 0x00,
	' ', 0x00,
	'R', 0x00,
	'F', 0x00,
	'I', 0x00,
	'D', 0x00,
	' ', 0x00,
	'I', 0x00,
	'n', 0x00,
	's', 0x00,
	't', 0x00,
	'r', 0x00,
	'u', 0x00,
	'm', 0x00,
	'e', 0x00,
	'n', 0x00,
	't', 0x00,
};

static const uint8_t * const StringDescriptors[] = {
	StringDescriptor0,
	StringDescriptor1,
	StringDescriptor2,
};


static uint8_t UsbBuffer[64];
static int  UsbSoFarCount;

static uint8_t CurrentConfiguration;

static void UsbSendEp0(const uint8_t *data, int len)
{
	int thisTime, i;

	do {
		thisTime = min(len, 8);
		len -= thisTime;

		for(i = 0; i < thisTime; i++) {
			AT91C_BASE_UDP->UDP_FDR[0] = *data;
			data++;
		}

		if(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_TXCOMP) {
			AT91C_BASE_UDP->UDP_CSR[0] &= ~AT91C_UDP_TXCOMP;
			while(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_TXCOMP)
				;
		}

		AT91C_BASE_UDP->UDP_CSR[0] |= AT91C_UDP_TXPKTRDY;

		do {
			if(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_RX_DATA_BK0) {
				// This means that the host is trying to write to us, so
				// abandon our write to them.
				AT91C_BASE_UDP->UDP_CSR[0] &= ~AT91C_UDP_RX_DATA_BK0;
				return;
			}
		} while(!(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_TXCOMP));
	} while(len > 0);

	if(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_TXCOMP) {
		AT91C_BASE_UDP->UDP_CSR[0] &= ~AT91C_UDP_TXCOMP;
		while(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_TXCOMP)
			;
	}
}

static void UsbSendZeroLength(void)
{
	AT91C_BASE_UDP->UDP_CSR[0] |= AT91C_UDP_TXPKTRDY;

	while(!(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_TXCOMP))
		;

	AT91C_BASE_UDP->UDP_CSR[0] &= ~AT91C_UDP_TXCOMP;

	while(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_TXCOMP)
		;
}

static void UsbSendStall(void)
{
	AT91C_BASE_UDP->UDP_CSR[0] |= AT91C_UDP_FORCESTALL;

	while(!(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_STALLSENT))
		;

	AT91C_BASE_UDP->UDP_CSR[0] &= ~AT91C_UDP_STALLSENT;

	while(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_STALLSENT)
		;
}

static void HandleRxdSetupData(void)
{
	int i;
	UsbSetupData usd;

	for(i = 0; i < sizeof(usd); i++) {
		((uint8_t *)&usd)[i] = AT91C_BASE_UDP->UDP_FDR[0];
	}

	if(usd.bmRequestType & 0x80) {
		AT91C_BASE_UDP->UDP_CSR[0] |= AT91C_UDP_DIR;
		while(!(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_DIR))
			;
	}

	AT91C_BASE_UDP->UDP_CSR[0] &= ~AT91C_UDP_RXSETUP;
	while(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_RXSETUP)
		;

	switch(usd.bRequest) {
		case USB_REQUEST_GET_DESCRIPTOR:
			if((usd.wValue >> 8) == USB_DESCRIPTOR_TYPE_DEVICE) {
				UsbSendEp0((uint8_t *)&DeviceDescriptor,
					min(sizeof(DeviceDescriptor), usd.wLength));
			} else if((usd.wValue >> 8) == USB_DESCRIPTOR_TYPE_CONFIGURATION) {
				UsbSendEp0((uint8_t *)&ConfigurationDescriptor,
					min(sizeof(ConfigurationDescriptor), usd.wLength));
			} else if((usd.wValue >> 8) == USB_DESCRIPTOR_TYPE_STRING) {
				const uint8_t *s = StringDescriptors[usd.wValue & 0xff];
				UsbSendEp0(s, min(s[0], usd.wLength));
			} else if((usd.wValue >> 8) == USB_DESCRIPTOR_TYPE_HID_REPORT) {
				UsbSendEp0((uint8_t *)&HidReportDescriptor,
					min(sizeof(HidReportDescriptor), usd.wLength));
			} else {
				*((uint32_t *)0x00200000) = usd.wValue;
			}
			break;

		case USB_REQUEST_SET_ADDRESS:
			UsbSendZeroLength();
			AT91C_BASE_UDP->UDP_FADDR = AT91C_UDP_FEN | usd.wValue ;
			if(usd.wValue != 0) {
				AT91C_BASE_UDP->UDP_GLBSTATE = AT91C_UDP_FADDEN;
			} else {
				AT91C_BASE_UDP->UDP_GLBSTATE = 0;
			}
			break;

		case USB_REQUEST_GET_CONFIGURATION:
			UsbSendEp0(&CurrentConfiguration, sizeof(CurrentConfiguration));
			break;

		case USB_REQUEST_GET_STATUS: {
			if(usd.bmRequestType & 0x80) {
				uint16_t w = 0;
				UsbSendEp0((uint8_t *)&w, sizeof(w));
			}
			break;
		}
		case USB_REQUEST_SET_CONFIGURATION:
			CurrentConfiguration = usd.wValue;
			if(CurrentConfiguration) {
				AT91C_BASE_UDP->UDP_GLBSTATE = AT91C_UDP_CONFG;
				AT91C_BASE_UDP->UDP_CSR[1] = AT91C_UDP_EPEDS |
					AT91C_UDP_EPTYPE_INT_OUT;
				AT91C_BASE_UDP->UDP_CSR[2] = AT91C_UDP_EPEDS |
					AT91C_UDP_EPTYPE_INT_IN;
			} else {
				AT91C_BASE_UDP->UDP_GLBSTATE = AT91C_UDP_FADDEN;
				AT91C_BASE_UDP->UDP_CSR[1] = 0;
				AT91C_BASE_UDP->UDP_CSR[2] = 0;
			}
			UsbSendZeroLength();
			break;

		case USB_REQUEST_GET_INTERFACE: {
			uint8_t b = 0;
			UsbSendEp0(&b, sizeof(b));
			break;
		}

		case USB_REQUEST_SET_INTERFACE:
			UsbSendZeroLength();
			break;

		case USB_REQUEST_CLEAR_FEATURE:
		case USB_REQUEST_SET_FEATURE:
			UsbSendStall();
			break;
		case USB_REQUEST_SET_DESCRIPTOR:
		case USB_REQUEST_SYNC_FRAME:
		default:
			break;
	}
}

void UsbSendPacket(uint8_t *packet, int len)
{
	int i, thisTime;

	while(len > 0) {
		thisTime = min(len, 8);

		for(i = 0; i < thisTime; i++) {
			AT91C_BASE_UDP->UDP_FDR[2] = packet[i];
		}
		AT91C_BASE_UDP->UDP_CSR[2] |= AT91C_UDP_TXPKTRDY;

		while(!(AT91C_BASE_UDP->UDP_CSR[2] & AT91C_UDP_TXCOMP))
			;
		AT91C_BASE_UDP->UDP_CSR[2] &= ~AT91C_UDP_TXCOMP;

		while(AT91C_BASE_UDP->UDP_CSR[2] & AT91C_UDP_TXCOMP)
			;

		len -= thisTime;
		packet += thisTime;
	}
}

static void HandleRxdData(void)
{
	int i, len;

	if(AT91C_BASE_UDP->UDP_CSR[1] & AT91C_UDP_RX_DATA_BK0) {
		len = UDP_CSR_BYTES_RECEIVED(AT91C_BASE_UDP->UDP_CSR[1]);

		for(i = 0; i < len; i++) {
			UsbBuffer[UsbSoFarCount] = AT91C_BASE_UDP->UDP_FDR[1];
			UsbSoFarCount++;
		}

		AT91C_BASE_UDP->UDP_CSR[1] &= ~AT91C_UDP_RX_DATA_BK0;
		while(AT91C_BASE_UDP->UDP_CSR[1] & AT91C_UDP_RX_DATA_BK0)
			;

		if(UsbSoFarCount >= 64) {
			UsbPacketReceived(UsbBuffer, UsbSoFarCount);
			UsbSoFarCount = 0;
		}
	}

	if(AT91C_BASE_UDP->UDP_CSR[1] & AT91C_UDP_RX_DATA_BK1) {
		len = UDP_CSR_BYTES_RECEIVED(AT91C_BASE_UDP->UDP_CSR[1]);

		for(i = 0; i < len; i++) {
			UsbBuffer[UsbSoFarCount] = AT91C_BASE_UDP->UDP_FDR[1];
			UsbSoFarCount++;
		}

		AT91C_BASE_UDP->UDP_CSR[1] &= ~AT91C_UDP_RX_DATA_BK1;
		while(AT91C_BASE_UDP->UDP_CSR[1] & AT91C_UDP_RX_DATA_BK1)
			;

		if(UsbSoFarCount >= 64) {
			UsbPacketReceived(UsbBuffer, UsbSoFarCount);
			UsbSoFarCount = 0;
		}
	}
}

void UsbStart(void)
{
	volatile int i;

	UsbSoFarCount = 0;

	USB_D_PLUS_PULLUP_OFF();

	for(i = 0; i < 1000000; i++)
		;

	USB_D_PLUS_PULLUP_ON();

	if(AT91C_BASE_UDP->UDP_ISR & AT91C_UDP_ENDBUSRES) {
		AT91C_BASE_UDP->UDP_ICR = AT91C_UDP_ENDBUSRES;
	}
}

int UsbConnected()
{
	if (AT91C_BASE_UDP->UDP_GLBSTATE & AT91C_UDP_CONFG)
		return TRUE;
	else
		return FALSE;
}

int UsbPoll(int blinkLeds)
{
	int ret = FALSE;

	if(AT91C_BASE_UDP->UDP_ISR & AT91C_UDP_ENDBUSRES) {
		AT91C_BASE_UDP->UDP_ICR = AT91C_UDP_ENDBUSRES;

		// following a reset we should be ready to receive a setup packet
		AT91C_BASE_UDP->UDP_RSTEP = 0xf;
		AT91C_BASE_UDP->UDP_RSTEP = 0;

		AT91C_BASE_UDP->UDP_FADDR = AT91C_UDP_FEN;

		AT91C_BASE_UDP->UDP_CSR[0] = AT91C_UDP_EPTYPE_CTRL | AT91C_UDP_EPEDS;

		CurrentConfiguration = 0;

		ret = TRUE;
	}

	if(AT91C_BASE_UDP->UDP_ISR & UDP_INTERRUPT_ENDPOINT(0)) {
		if(AT91C_BASE_UDP->UDP_CSR[0] & AT91C_UDP_RXSETUP) {
			HandleRxdSetupData();
			ret = TRUE;
		}
	}

	if(AT91C_BASE_UDP->UDP_ISR & UDP_INTERRUPT_ENDPOINT(1)) {
		HandleRxdData();
		ret = TRUE;
	}

	return ret;
}
