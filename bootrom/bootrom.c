#include <proxmark3.h>

static void ConfigClocks(void)
{
    // we are using a 16 MHz crystal as the basis for everything
    // slow clock runs at 32Khz typical regardless of crystal

    // enable system clock and USB clock
    PMC_SYS_CLK_ENABLE = PMC_SYS_CLK_PROCESSOR_CLK | PMC_SYS_CLK_UDP_CLK;

	// enable the clock to the following peripherals
    PMC_PERIPHERAL_CLK_ENABLE =
        (1<<PERIPH_PIOA) |
        (1<<PERIPH_ADC) |
        (1<<PERIPH_SPI) |
        (1<<PERIPH_SSC) |
        (1<<PERIPH_PWMC) |
        (1<<PERIPH_UDP);

	// worst case scenario, with 16Mhz xtal startup delay is 14.5ms
	// with a slow clock running at it worst case (max) frequency of 42khz
	// max startup delay = (14.5ms*42k)/8 = 76 = 0x4C round up to 0x50

	// enable main oscillator and set startup delay
    PMC_MAIN_OSCILLATOR = PMC_MAIN_OSCILLATOR_ENABLE |
        PMC_MAIN_OSCILLATOR_STARTUP_DELAY(0x50);

	// wait for main oscillator to stabilize
	while ( !(PMC_INTERRUPT_STATUS & PMC_MAIN_OSCILLATOR_STABILIZED) )
		;

    // minimum PLL clock frequency is 80 MHz in range 00 (96 here so okay)
    // frequency is crystal * multiplier / divisor = 16Mhz * 12 / 2 = 96Mhz
    PMC_PLL = PMC_PLL_DIVISOR(2) | PMC_PLL_COUNT_BEFORE_LOCK(0x50) |
        PMC_PLL_FREQUENCY_RANGE(0) | PMC_PLL_MULTIPLIER(12) |
        PMC_PLL_USB_DIVISOR(1);

	// wait for PLL to lock
	while ( !(PMC_INTERRUPT_STATUS & PMC_MAIN_OSCILLATOR_PLL_LOCK) )
		;

	// we want a master clock (MCK) to be PLL clock / 2 = 96Mhz / 2 = 48Mhz
	// as per datasheet, this register must be programmed in two operations
	// when changing to PLL, program the prescaler first then the source
    PMC_MASTER_CLK = PMC_CLK_PRESCALE_DIV_2;

	// wait for main clock ready signal
	while ( !(PMC_INTERRUPT_STATUS & PMC_MAIN_OSCILLATOR_MCK_READY) )
		;

	// set the source to PLL
    PMC_MASTER_CLK = PMC_CLK_SELECTION_PLL_CLOCK | PMC_CLK_PRESCALE_DIV_2;

	// wait for main clock ready signal
	while ( !(PMC_INTERRUPT_STATUS & PMC_MAIN_OSCILLATOR_MCK_READY) )
		;
}

static void Fatal(void)
{
    for(;;);
}

void UsbPacketReceived(BYTE *packet, int len)
{
    int i;
    UsbCommand *c = (UsbCommand *)packet;
    volatile DWORD *p;

    if(len != sizeof(*c)) {
        Fatal();
    }

    switch(c->cmd) {
        case CMD_DEVICE_INFO:
            break;

        case CMD_SETUP_WRITE:
            p = (volatile DWORD *)0;
            for(i = 0; i < 12; i++) {
                p[i+c->ext1] = c->d.asDwords[i];
            }
            break;

        case CMD_FINISH_WRITE:
            p = (volatile DWORD *)0;
            for(i = 0; i < 4; i++) {
                p[i+60] = c->d.asDwords[i];
            }

            MC_FLASH_COMMAND = MC_FLASH_COMMAND_KEY |
                MC_FLASH_COMMAND_PAGEN(c->ext1/FLASH_PAGE_SIZE_BYTES) |
                FCMD_WRITE_PAGE;
            while(!(MC_FLASH_STATUS & MC_FLASH_STATUS_READY))
                ;
            break;

        case CMD_HARDWARE_RESET:
            break;

        default:
            Fatal();
            break;
    }

    c->cmd = CMD_ACK;
    UsbSendPacket(packet, len);
}

extern char _osimage_entry;
void BootROM(void)
{
    //------------
    // First set up all the I/O pins; GPIOs configured directly, other ones
    // just need to be assigned to the appropriate peripheral.

    // Kill all the pullups, especially the one on USB D+; leave them for
    // the unused pins, though.
    PIO_NO_PULL_UP_ENABLE =     (1 << GPIO_USB_PU)          |
                                (1 << GPIO_LED_A)           |
                                (1 << GPIO_LED_B)           |
                                (1 << GPIO_LED_C)           |
                                (1 << GPIO_LED_D)           |
                                (1 << GPIO_FPGA_DIN)        |
                                (1 << GPIO_FPGA_DOUT)       |
                                (1 << GPIO_FPGA_CCLK)       |
                                (1 << GPIO_FPGA_NINIT)      |
                                (1 << GPIO_FPGA_NPROGRAM)   |
                                (1 << GPIO_FPGA_DONE)       |
                                (1 << GPIO_MUXSEL_HIPKD)    |
                                (1 << GPIO_MUXSEL_HIRAW)    |
                                (1 << GPIO_MUXSEL_LOPKD)    |
                                (1 << GPIO_MUXSEL_LORAW)    |
                                (1 << GPIO_RELAY)	        |
                                (1 << GPIO_NVDD_ON);
                                // (and add GPIO_FPGA_ON)
	// These pins are outputs
    PIO_OUTPUT_ENABLE =         (1 << GPIO_LED_A)           |
                                (1 << GPIO_LED_B)           |
                                (1 << GPIO_LED_C)           |
                                (1 << GPIO_LED_D)           |
                                (1 << GPIO_RELAY)	        |
                                (1 << GPIO_NVDD_ON);
	// PIO controls the following pins
    PIO_ENABLE =                (1 << GPIO_USB_PU)          |
                                (1 << GPIO_LED_A)           |
                                (1 << GPIO_LED_B)           |
                                (1 << GPIO_LED_C)           |
                                (1 << GPIO_LED_D);

    USB_D_PLUS_PULLUP_OFF();
    LED_D_OFF();
    LED_C_ON();
    LED_B_OFF();
    LED_A_OFF();

	// if 512K FLASH part - TODO make some defines :)
	if ((DBGU_CIDR | 0xf00) == 0xa00) {
		MC_FLASH_MODE0 = MC_FLASH_MODE_FLASH_WAIT_STATES(1) |
			MC_FLASH_MODE_MASTER_CLK_IN_MHZ(0x48);
		MC_FLASH_MODE1 = MC_FLASH_MODE_FLASH_WAIT_STATES(1) |
			MC_FLASH_MODE_MASTER_CLK_IN_MHZ(0x48);
	} else {
		MC_FLASH_MODE0 = MC_FLASH_MODE_FLASH_WAIT_STATES(0) |
			MC_FLASH_MODE_MASTER_CLK_IN_MHZ(48);
	}

	// Initialize all system clocks
    ConfigClocks();

    LED_A_ON();

	if(BUTTON_PRESS()) {
    	UsbStart();
	}

    for(;;) {
        WDT_HIT();

        UsbPoll(TRUE);

		if(!BUTTON_PRESS()) {
            USB_D_PLUS_PULLUP_OFF();
            LED_B_ON();

			// jump to Flash address of the osimage entry point (LSBit set for thumb mode)
            asm("bx %0\n" : : "r" ( ((int)&_osimage_entry) | 0x1 ) );
        }
    }
}
