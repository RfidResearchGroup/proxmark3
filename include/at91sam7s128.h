//-----------------------------------------------------------------------------
// Incomplete register definitions for the AT91SAM7S128 chip.
// Jonathan Westhues, Jul 2005
//-----------------------------------------------------------------------------

#ifndef __AT91SAM7S128_H
#define __AT91SAM7S128_H

#define REG(x) (*(volatile unsigned long *)(x))

//-------------
// Peripheral IDs

#define PERIPH_AIC_FIQ								0
#define PERIPH_SYSIRQ								1
#define PERIPH_PIOA									2
#define PERIPH_ADC									4
#define PERIPH_SPI									5
#define PERIPH_US0									6
#define PERIPH_US1									7
#define PERIPH_SSC									8
#define PERIPH_TWI									9
#define PERIPH_PWMC									10
#define PERIPH_UDP									11
#define PERIPH_TC0									12
#define PERIPH_TC1									13
#define PERIPH_TC2									14
#define PERIPH_AIC_IRQ0 							30
#define PERIPH_AIC_IRQ1 							31

//-------------
// Reset Controller

#define RSTC_BASE									(0xfffffd00)

#define RSTC_CONTROL								REG(RSTC_BASE+0x00)
#define RSTC_STATUS								REG(RSTC_BASE+0x04)

#define RST_CONTROL_KEY								(0xa5<<24)
#define RST_CONTROL_PROCESSOR_RESET					(1<<0)
#define RST_STATUS_TYPE_MASK							(7<<8)
#define RST_STATUS_TYPE_POWERUP								(0<<8)
#define RST_STATUS_TYPE_WATCHDOG							(2<<8)
#define RST_STATUS_TYPE_SOFTWARE							(3<<8)
#define RST_STATUS_TYPE_USER								(4<<8)
#define RST_STATUS_TYPE_BROWNOUT							(5<<8)


//-------------
// PWM Controller

#define PWM_BASE									(0xfffcc000)

#define PWM_MODE									REG(PWM_BASE+0x00)
#define PWM_ENABLE									REG(PWM_BASE+0x04)
#define PWM_DISABLE									REG(PWM_BASE+0x08)
#define PWM_STATUS									REG(PWM_BASE+0x0c)
#define PWM_INTERRUPT_ENABLE						REG(PWM_BASE+0x10)
#define PWM_INTERRUPT_DISABLE						REG(PWM_BASE+0x14)
#define PWM_INTERRUPT_MASK							REG(PWM_BASE+0x18)
#define PWM_INTERRUPT_STATUS						REG(PWM_BASE+0x1c)
#define PWM_CH_MODE(x)								REG(PWM_BASE+0x200+((x)*0x20))
#define PWM_CH_DUTY_CYCLE(x)						REG(PWM_BASE+0x204+((x)*0x20))
#define PWM_CH_PERIOD(x)							REG(PWM_BASE+0x208+((x)*0x20))
#define PWM_CH_COUNTER(x)							REG(PWM_BASE+0x20c+((x)*0x20))
#define PWM_CH_UPDATE(x)							REG(PWM_BASE+0x210+((x)*0x20))

#define PWM_MODE_DIVA(x)							((x)<<0)
#define PWM_MODE_PREA(x)							((x)<<8)
#define PWM_MODE_DIVB(x)							((x)<<16)
#define PWM_MODE_PREB(x)							((x)<<24)

#define PWM_CHANNEL(x)								(1<<(x))

#define PWM_CH_MODE_PRESCALER(x)					((x)<<0)
#define PWM_CH_MODE_PERIOD_CENTER_ALIGNED			(1<<8)
#define PWM_CH_MODE_POLARITY_STARTS_HIGH			(1<<9)
#define PWM_CH_MODE_UPDATE_UPDATES_PERIOD			(1<<10)

//-------------
// Debug Unit

#define DBG_BASE									(0xfffff200)

#define DBGU_CR										REG(DBG_BASE+0x0000)
#define DBGU_MR										REG(DBG_BASE+0x0004)
#define DBGU_IER									REG(DBG_BASE+0x0008)
#define DBGU_IDR									REG(DBG_BASE+0x000C)
#define DBGU_IMR									REG(DBG_BASE+0x0010)
#define DBGU_SR										REG(DBG_BASE+0x0014)
#define DBGU_RHR									REG(DBG_BASE+0x0018)
#define DBGU_THR									REG(DBG_BASE+0x001C)
#define DBGU_BRGR									REG(DBG_BASE+0x0020)
#define DBGU_CIDR									REG(DBG_BASE+0x0040)
#define DBGU_EXID									REG(DBG_BASE+0x0044)
#define DBGU_FNR									REG(DBG_BASE+0x0048)

//-------------
// Embedded Flash Controller

#define MC_BASE 									(0xffffff00)

#define MC_FLASH_MODE0								REG(MC_BASE+0x60)
#define MC_FLASH_COMMAND							REG(MC_BASE+0x64)
#define MC_FLASH_STATUS								REG(MC_BASE+0x68)
#define MC_FLASH_MODE1								REG(MC_BASE+0x70)

#define MC_FLASH_MODE_READY_INTERRUPT_ENABLE		(1<<0)
#define MC_FLASH_MODE_LOCK_INTERRUPT_ENABLE			(1<<2)
#define MC_FLASH_MODE_PROG_ERROR_INTERRUPT_ENABLE	(1<<3)
#define MC_FLASH_MODE_NO_ERASE_BEFORE_PROGRAMMING	(1<<7)
#define MC_FLASH_MODE_FLASH_WAIT_STATES(x)			((x)<<8)
#define MC_FLASH_MODE_MASTER_CLK_IN_MHZ(x)			((x)<<16)

#define MC_FLASH_COMMAND_FCMD(x)					((x)<<0)
#define MC_FLASH_COMMAND_PAGEN(x)					((x)<<8)
#define MC_FLASH_COMMAND_KEY						((0x5a)<<24)

#define FCMD_NOP									0x0
#define FCMD_WRITE_PAGE								0x1
#define FCMD_SET_LOCK_BIT							0x2
#define FCMD_WRITE_PAGE_LOCK						0x3
#define FCMD_CLEAR_LOCK_BIT							0x4
#define FCMD_ERASE_ALL								0x8
#define FCMD_SET_GP_NVM_BIT							0xb
#define FCMD_SET_SECURITY_BIT						0xf

#define MC_FLASH_STATUS_READY						(1<<0)
#define MC_FLASH_STATUS_LOCK_ERROR					(1<<2)
#define MC_FLASH_STATUS_PROGRAMMING_ERROR			(1<<3)
#define MC_FLASH_STATUS_SECURITY_BIT_ACTIVE			(1<<4)
#define MC_FLASH_STATUS_GP_NVM_ACTIVE_0				(1<<8)
#define MC_FLASH_STATUS_GP_NVM_ACTIVE_1				(1<<9)
#define MC_FLASH_STATUS_LOCK_ACTIVE(x)				(1<<((x)+16))

#define FLASH_PAGE_SIZE_BYTES						256
#define FLASH_PAGE_COUNT							512

//-------------
// Watchdog Timer - 12 bit down counter, uses slow clock divided by 128 as source

#define WDT_BASE									(0xfffffd40)

#define WDT_CONTROL									REG(WDT_BASE+0x00)
#define WDT_MODE									REG(WDT_BASE+0x04)
#define WDT_STATUS									REG(WDT_BASE+0x08)

#define WDT_HIT()									WDT_CONTROL = 0xa5000001

#define WDT_MODE_COUNT(x)							((x)<<0)
#define WDT_MODE_INTERRUPT_ON_EVENT					(1<<12)
#define WDT_MODE_RESET_ON_EVENT_ENABLE				(1<<13)
#define WDT_MODE_RESET_ON_EVENT						(1<<14)
#define WDT_MODE_WATCHDOG_DELTA(x)					((x)<<16)
#define WDT_MODE_HALT_IN_DEBUG_MODE					(1<<28)
#define WDT_MODE_HALT_IN_IDLE_MODE					(1<<29)
#define WDT_MODE_DISABLE							(1<<15)

//-------------
// Parallel Input/Output Controller

#define PIO_BASE									(0xfffff400)

#define PIO_ENABLE									REG(PIO_BASE+0x000)
#define PIO_DISABLE									REG(PIO_BASE+0x004)
#define PIO_STATUS									REG(PIO_BASE+0x008)
#define PIO_OUTPUT_ENABLE							REG(PIO_BASE+0x010)
#define PIO_OUTPUT_DISABLE							REG(PIO_BASE+0x014)
#define PIO_OUTPUT_STATUS							REG(PIO_BASE+0x018)
#define PIO_GLITCH_ENABLE							REG(PIO_BASE+0x020)
#define PIO_GLITCH_DISABLE							REG(PIO_BASE+0x024)
#define PIO_GLITCH_STATUS							REG(PIO_BASE+0x028)
#define PIO_OUTPUT_DATA_SET							REG(PIO_BASE+0x030)
#define PIO_OUTPUT_DATA_CLEAR						REG(PIO_BASE+0x034)
#define PIO_OUTPUT_DATA_STATUS						REG(PIO_BASE+0x038)
#define PIO_PIN_DATA_STATUS							REG(PIO_BASE+0x03c)
#define PIO_OPEN_DRAIN_ENABLE						REG(PIO_BASE+0x050)
#define PIO_OPEN_DRAIN_DISABLE						REG(PIO_BASE+0x054)
#define PIO_OPEN_DRAIN_STATUS						REG(PIO_BASE+0x058)
#define PIO_NO_PULL_UP_ENABLE						REG(PIO_BASE+0x060)
#define PIO_NO_PULL_UP_DISABLE						REG(PIO_BASE+0x064)
#define PIO_NO_PULL_UP_STATUS						REG(PIO_BASE+0x068)
#define PIO_PERIPHERAL_A_SEL						REG(PIO_BASE+0x070)
#define PIO_PERIPHERAL_B_SEL						REG(PIO_BASE+0x074)
#define PIO_PERIPHERAL_WHICH						REG(PIO_BASE+0x078)
#define PIO_OUT_WRITE_ENABLE						REG(PIO_BASE+0x0a0)
#define PIO_OUT_WRITE_DISABLE						REG(PIO_BASE+0x0a4)
#define PIO_OUT_WRITE_STATUS						REG(PIO_BASE+0x0a8)

//-------------
// USB Device Port

#define UDP_BASE									(0xfffb0000)

#define UDP_FRAME_NUMBER							REG(UDP_BASE+0x0000)
#define UDP_GLOBAL_STATE							REG(UDP_BASE+0x0004)
#define UDP_FUNCTION_ADDR							REG(UDP_BASE+0x0008)
#define UDP_INTERRUPT_ENABLE						REG(UDP_BASE+0x0010)
#define UDP_INTERRUPT_DISABLE						REG(UDP_BASE+0x0014)
#define UDP_INTERRUPT_MASK							REG(UDP_BASE+0x0018)
#define UDP_INTERRUPT_STATUS						REG(UDP_BASE+0x001c)
#define UDP_INTERRUPT_CLEAR							REG(UDP_BASE+0x0020)
#define UDP_RESET_ENDPOINT							REG(UDP_BASE+0x0028)
#define UDP_ENDPOINT_CSR(x)							REG(UDP_BASE+0x0030+((x)*4))
#define UDP_ENDPOINT_FIFO(x)						REG(UDP_BASE+0x0050+((x)*4))
#define UDP_TRANSCEIVER_CTRL						REG(UDP_BASE+0x0074)

#define UDP_GLOBAL_STATE_ADDRESSED					(1<<0)
#define UDP_GLOBAL_STATE_CONFIGURED					(1<<1)
#define UDP_GLOBAL_STATE_SEND_RESUME_ENABLED		(1<<2)
#define UDP_GLOBAL_STATE_RESUME_RECEIVED			(1<<3)
#define UDP_GLOBAL_STATE_REMOTE_WAKE_UP_ENABLED 	(1<<4)

#define UDP_FUNCTION_ADDR_ENABLED					(1<<8)

#define UDP_INTERRUPT_ENDPOINT(x)					(1<<(x))
#define UDP_INTERRUPT_SUSPEND						(1<<8)
#define UDP_INTERRUPT_RESUME						(1<<9)
#define UDP_INTERRUPT_EXTERNAL_RESUME				(1<<10)
#define UDP_INTERRUPT_SOF							(1<<11)
#define UDP_INTERRUPT_END_OF_BUS_RESET				(1<<12)
#define UDP_INTERRUPT_WAKEUP						(1<<13)

#define UDP_RESET_ENDPOINT_NUMBER(x)				(1<<(x))

#define UDP_CSR_TX_PACKET_ACKED						(1<<0)
#define UDP_CSR_RX_PACKET_RECEIVED_BANK_0			(1<<1)
#define UDP_CSR_RX_HAVE_READ_SETUP_DATA				(1<<2)
#define UDP_CSR_STALL_SENT							(1<<3)
#define UDP_CSR_TX_PACKET							(1<<4)
#define UDP_CSR_FORCE_STALL							(1<<5)
#define UDP_CSR_RX_PACKET_RECEIVED_BANK_1			(1<<6)
#define UDP_CSR_CONTROL_DATA_DIR					(1<<7)
#define UDP_CSR_EPTYPE_CONTROL						(0<<8)
#define UDP_CSR_EPTYPE_ISOCHRON_OUT					(1<<8)
#define UDP_CSR_EPTYPE_ISOCHRON_IN					(5<<8)
#define UDP_CSR_EPTYPE_BULK_OUT						(2<<8)
#define UDP_CSR_EPTYPE_BULK_IN						(6<<8)
#define UDP_CSR_EPTYPE_INTERRUPT_OUT				(3<<8)
#define UDP_CSR_EPTYPE_INTERRUPT_IN					(7<<8)
#define UDP_CSR_IS_DATA1							(1<<11)
#define UDP_CSR_ENABLE_EP							(1<<15)
#define UDP_CSR_BYTES_RECEIVED(x)					(((x) >> 16) & 0x7ff)

#define UDP_TRANSCEIVER_CTRL_DISABLE				(1<<8)

//-------------
// Power Management Controller

#define PMC_BASE									(0xfffffc00)

#define PMC_SYS_CLK_ENABLE							REG(PMC_BASE+0x0000)
#define PMC_SYS_CLK_DISABLE							REG(PMC_BASE+0x0004)
#define PMC_SYS_CLK_STATUS							REG(PMC_BASE+0x0008)
#define PMC_PERIPHERAL_CLK_ENABLE					REG(PMC_BASE+0x0010)
#define PMC_PERIPHERAL_CLK_DISABLE					REG(PMC_BASE+0x0014)
#define PMC_PERIPHERAL_CLK_STATUS					REG(PMC_BASE+0x0018)
#define PMC_MAIN_OSCILLATOR							REG(PMC_BASE+0x0020)
#define PMC_MAIN_CLK_FREQUENCY						REG(PMC_BASE+0x0024)
#define PMC_PLL										REG(PMC_BASE+0x002c)
#define PMC_MASTER_CLK								REG(PMC_BASE+0x0030)
#define PMC_PROGRAMMABLE_CLK_0						REG(PMC_BASE+0x0040)
#define PMC_PROGRAMMABLE_CLK_1						REG(PMC_BASE+0x0044)
#define PMC_INTERRUPT_ENABLE						REG(PMC_BASE+0x0060)
#define PMC_INTERRUPT_DISABLE						REG(PMC_BASE+0x0064)
#define PMC_INTERRUPT_STATUS						REG(PMC_BASE+0x0068)
#define PMC_INTERRUPT_MASK							REG(PMC_BASE+0x006c)

#define PMC_SYS_CLK_PROCESSOR_CLK					(1<<0)
#define PMC_SYS_CLK_UDP_CLK							(1<<7)
#define PMC_SYS_CLK_PROGRAMMABLE_CLK_0				(1<<8)
#define PMC_SYS_CLK_PROGRAMMABLE_CLK_1				(1<<9)
#define PMC_SYS_CLK_PROGRAMMABLE_CLK_2				(1<<10)

#define PMC_MAIN_OSCILLATOR_STABILIZED				(1<<0)
#define PMC_MAIN_OSCILLATOR_PLL_LOCK				(1<<2)
#define PMC_MAIN_OSCILLATOR_MCK_READY				(1<<3)
#define PMC_MAIN_OSCILLATOR_ENABLE					(1<<0)
#define PMC_MAIN_OSCILLATOR_BYPASS					(1<<1)
#define PMC_MAIN_OSCILLATOR_STARTUP_DELAY(x)		((x)<<8)

#define PMC_PLL_DIVISOR(x)							(x)
#define PMC_PLL_COUNT_BEFORE_LOCK(x)				((x)<<8)
#define PMC_PLL_FREQUENCY_RANGE(x)					((x)<<14)
#define PMC_PLL_MULTIPLIER(x)						(((x)-1)<<16)
#define PMC_PLL_USB_DIVISOR(x)						((x)<<28)

#define PMC_CLK_SELECTION_PLL_CLOCK					(3<<0)
#define PMC_CLK_SELECTION_MAIN_CLOCK				(1<<0)
#define PMC_CLK_SELECTION_SLOW_CLOCK				(0<<0)
#define PMC_CLK_PRESCALE_DIV_1						(0<<2)
#define PMC_CLK_PRESCALE_DIV_2						(1<<2)
#define PMC_CLK_PRESCALE_DIV_4						(2<<2)
#define PMC_CLK_PRESCALE_DIV_8						(3<<2)
#define PMC_CLK_PRESCALE_DIV_16						(4<<2)
#define PMC_CLK_PRESCALE_DIV_32						(5<<2)
#define PMC_CLK_PRESCALE_DIV_64						(6<<2)

//-------------
// Serial Peripheral Interface (SPI)

#define SPI_BASE									(0xfffe0000)

#define SPI_CONTROL									REG(SPI_BASE+0x00)
#define SPI_MODE									REG(SPI_BASE+0x04)
#define SPI_RX_DATA									REG(SPI_BASE+0x08)
#define SPI_TX_DATA									REG(SPI_BASE+0x0c)
#define SPI_STATUS									REG(SPI_BASE+0x10)
#define SPI_INTERRUPT_ENABLE						REG(SPI_BASE+0x14)
#define SPI_INTERRUPT_DISABLE						REG(SPI_BASE+0x18)
#define SPI_INTERRUPT_MASK							REG(SPI_BASE+0x1c)
#define SPI_FOR_CHIPSEL_0							REG(SPI_BASE+0x30)
#define SPI_FOR_CHIPSEL_1							REG(SPI_BASE+0x34)
#define SPI_FOR_CHIPSEL_2							REG(SPI_BASE+0x38)
#define SPI_FOR_CHIPSEL_3							REG(SPI_BASE+0x3c)

#define SPI_CONTROL_ENABLE							(1<<0)
#define SPI_CONTROL_DISABLE							(1<<1)
#define SPI_CONTROL_RESET							(1<<7)
#define SPI_CONTROL_LAST_TRANSFER					(1<<24)

#define SPI_MODE_MASTER								(1<<0)
#define SPI_MODE_VARIABLE_CHIPSEL					(1<<1)
#define SPI_MODE_CHIPSELS_DECODED					(1<<2)
#define SPI_MODE_USE_DIVIDED_CLOCK					(1<<3)
#define SPI_MODE_MODE_FAULT_DETECTION_OFF			(1<<4)
#define SPI_MODE_LOOPBACK							(1<<7)
#define SPI_MODE_CHIPSEL(x)							((x)<<16)
#define SPI_MODE_DELAY_BETWEEN_CHIPSELS(x)			((x)<<24)

#define SPI_RX_DATA_CHIPSEL(x)						(((x)>>16)&0xf)

#define SPI_TX_DATA_CHIPSEL(x)						((x)<<16)
#define SPI_TX_DATA_LAST_TRANSFER					(1<<24)

#define SPI_STATUS_RECEIVE_FULL						(1<<0)
#define SPI_STATUS_TRANSMIT_EMPTY					(1<<1)
#define SPI_STATUS_MODE_FAULT						(1<<2)
#define SPI_STATUS_OVERRUN							(1<<3)
#define SPI_STATUS_END_OF_RX_BUFFER					(1<<4)
#define SPI_STATUS_END_OF_TX_BUFFER					(1<<5)
#define SPI_STATUS_RX_BUFFER_FULL					(1<<6)
#define SPI_STATUS_TX_BUFFER_EMPTY					(1<<7)
#define SPI_STATUS_NSS_RISING_DETECTED				(1<<8)
#define SPI_STATUS_TX_EMPTY							(1<<9)
#define SPI_STATUS_SPI_ENABLED						(1<<16)

#define SPI_FOR_CHIPSEL_INACTIVE_CLK_1				(1<<0)
#define SPI_FOR_CHIPSEL_PHASE						(1<<1)
#define SPI_FOR_CHIPSEL_LEAVE_CHIPSEL_LOW			(1<<3)
#define SPI_FOR_CHIPSEL_BITS_IN_WORD(x)				((x)<<4)
#define SPI_FOR_CHIPSEL_DIVISOR(x)					((x)<<8)
#define SPI_FOR_CHIPSEL_DELAY_BEFORE_CLK(x) 		((x)<<16)
#define SPI_FOR_CHIPSEL_INTERWORD_DELAY(x)			((x)<<24)

//-------------
// Analog to Digital Converter

#define ADC_BASE		(0xfffd8000)

#define ADC_CONTROL									REG(ADC_BASE+0x00)
#define ADC_MODE									REG(ADC_BASE+0x04)
#define ADC_CHANNEL_ENABLE							REG(ADC_BASE+0x10)
#define ADC_CHANNEL_DISABLE							REG(ADC_BASE+0x14)
#define ADC_CHANNEL_STATUS							REG(ADC_BASE+0x18)
#define ADC_STATUS									REG(ADC_BASE+0x1c)
#define ADC_LAST_CONVERTED_DATA						REG(ADC_BASE+0x20)
#define ADC_INTERRUPT_ENABLE						REG(ADC_BASE+0x24)
#define ADC_INTERRUPT_DISABLE						REG(ADC_BASE+0x28)
#define ADC_INTERRUPT_MASK							REG(ADC_BASE+0x2c)
#define ADC_CHANNEL_DATA(x)							REG(ADC_BASE+0x30+(4*(x)))

#define ADC_CONTROL_RESET							(1<<0)
#define ADC_CONTROL_START							(1<<1)

#define ADC_MODE_HW_TRIGGERS_ENABLED				(1<<0)
#define ADC_MODE_8_BIT_RESOLUTION					(1<<4)
#define ADC_MODE_SLEEP								(1<<5)
#define ADC_MODE_PRESCALE(x)						((x)<<8)
#define ADC_MODE_STARTUP_TIME(x)					((x)<<16)
#define ADC_MODE_SAMPLE_HOLD_TIME(x)				((x)<<24)

#define ADC_CHANNEL(x)								(1<<(x))

#define ADC_END_OF_CONVERSION(x)					(1<<(x))
#define ADC_OVERRUN_ERROR(x)						(1<<(8+(x)))
#define ADC_DATA_READY								(1<<16)
#define ADC_GENERAL_OVERRUN							(1<<17)
#define ADC_END_OF_RX_BUFFER						(1<<18)
#define ADC_RX_BUFFER_FULL							(1<<19)

#define ADC_CHAN_LF							4
#define ADC_CHAN_HF							5
//-------------
// Synchronous Serial Controller

#define SSC_BASE									(0xfffd4000)

#define SSC_CONTROL									REG(SSC_BASE+0x00)
#define SSC_CLOCK_DIVISOR							REG(SSC_BASE+0x04)
#define SSC_RECEIVE_CLOCK_MODE						REG(SSC_BASE+0x10)
#define SSC_RECEIVE_FRAME_MODE						REG(SSC_BASE+0x14)
#define SSC_TRANSMIT_CLOCK_MODE						REG(SSC_BASE+0x18)
#define SSC_TRANSMIT_FRAME_MODE						REG(SSC_BASE+0x1c)
#define SSC_RECEIVE_HOLDING							REG(SSC_BASE+0x20)
#define SSC_TRANSMIT_HOLDING						REG(SSC_BASE+0x24)
#define SSC_RECEIVE_SYNC_HOLDING					REG(SSC_BASE+0x30)
#define SSC_TRANSMIT_SYNC_HOLDING					REG(SSC_BASE+0x34)
#define SSC_STATUS									REG(SSC_BASE+0x40)
#define SSC_INTERRUPT_ENABLE						REG(SSC_BASE+0x44)
#define SSC_INTERRUPT_DISABLE						REG(SSC_BASE+0x48)
#define SSC_INTERRUPT_MASK							REG(SSC_BASE+0x4c)

#define SSC_CONTROL_RX_ENABLE						(1<<0)
#define SSC_CONTROL_RX_DISABLE						(1<<1)
#define SSC_CONTROL_TX_ENABLE						(1<<8)
#define SSC_CONTROL_TX_DISABLE						(1<<9)
#define SSC_CONTROL_RESET							(1<<15)

#define SSC_CLOCK_MODE_SELECT(x)					((x)<<0)
#define SSC_CLOCK_MODE_OUTPUT(x)					((x)<<2)
#define SSC_CLOCK_MODE_INVERT						(1<<5)
#define SSC_CLOCK_MODE_START(x)						((x)<<8)
#define SSC_CLOCK_MODE_START_DELAY(x)				((x)<<16)
#define SSC_CLOCK_MODE_FRAME_PERIOD(x)				((x)<<24)

#define SSC_FRAME_MODE_BITS_IN_WORD(x)				(((x)-1)<<0)
#define SSC_FRAME_MODE_LOOPBACK						(1<<5) // for RX
#define SSC_FRAME_MODE_DEFAULT_IS_1					(1<<5) // for TX
#define SSC_FRAME_MODE_MSB_FIRST					(1<<7)
#define SSC_FRAME_MODE_WORDS_PER_TRANSFER(x)		((x)<<8)
#define SSC_FRAME_MODE_FRAME_SYNC_LEN(x)			((x)<<16)
#define SSC_FRAME_MODE_FRAME_SYNC_TYPE(x)			((x)<<20)
#define SSC_FRAME_MODE_SYNC_DATA_ENABLE				(1<<23) // for TX only
#define SSC_FRAME_MODE_NEGATIVE_EDGE				(1<<24)

#define SSC_STATUS_TX_READY							(1<<0)
#define SSC_STATUS_TX_EMPTY							(1<<1)
#define SSC_STATUS_TX_ENDED							(1<<2)
#define SSC_STATUS_TX_BUF_EMPTY						(1<<3)
#define SSC_STATUS_RX_READY							(1<<4)
#define SSC_STATUS_RX_OVERRUN						(1<<5)
#define SSC_STATUS_RX_ENDED							(1<<6)
#define SSC_STATUS_RX_BUF_FULL						(1<<7)
#define SSC_STATUS_TX_SYNC_OCCURRED					(1<<10)
#define SSC_STATUS_RX_SYNC_OCCURRED					(1<<11)
#define SSC_STATUS_TX_ENABLED						(1<<16)
#define SSC_STATUS_RX_ENABLED						(1<<17)

//-------------
// Peripheral DMA Controller
//
// There is one set of registers for every peripheral that supports DMA.

#define PDC_RX_POINTER(x)							REG((x)+0x100)
#define PDC_RX_COUNTER(x)							REG((x)+0x104)
#define PDC_TX_POINTER(x)							REG((x)+0x108)
#define PDC_TX_COUNTER(x)							REG((x)+0x10c)
#define PDC_RX_NEXT_POINTER(x)						REG((x)+0x110)
#define PDC_RX_NEXT_COUNTER(x)						REG((x)+0x114)
#define PDC_TX_NEXT_POINTER(x)						REG((x)+0x118)
#define PDC_TX_NEXT_COUNTER(x)						REG((x)+0x11c)
#define PDC_CONTROL(x)								REG((x)+0x120)
#define PDC_STATUS(x)								REG((x)+0x124)

#define PDC_RX_ENABLE								(1<<0)
#define PDC_RX_DISABLE								(1<<1)
#define PDC_TX_ENABLE								(1<<8)
#define PDC_TX_DISABLE								(1<<9)

//-------------
// Timer/Counter base

#define TC_BASE 							(0xfffa0000)

#define TC_BCR								REG(TC_BASE+0xC0)
#define TC_BMR								REG(TC_BASE+0xC4)

#define TC_BCR_SYNC							(1<<0)

#define TC_CCR_CLKEN							(1<<0)
#define TC_CCR_CLKDIS							(1<<1)
#define TC_CCR_SWTRG							(1<<2)

#define TC_CMR_TCCLKS							(7<<0)
#define TC_CMR_TCCLKS_TIMER_CLOCK1						(0<<0)
#define TC_CMR_TCCLKS_TIMER_CLOCK2						(1<<0)
#define TC_CMR_TCCLKS_TIMER_CLOCK3						(2<<0)
#define TC_CMR_TCCLKS_TIMER_CLOCK4						(3<<0)
#define TC_CMR_TCCLKS_TIMER_CLOCK5						(4<<0)
#define TC_CMR_TCCLKS_XC0							(5<<0)
#define TC_CMR_TCCLKS_XC1							(6<<0)
#define TC_CMR_TCCLKS_XC2							(7<<0)
#define TC_CMR_CLKI							(1<<3)
#define TC_CMR_BURST							(3<<4)
#define TC_CMR_BURST_XC0							(1<<4)
#define TC_CMR_BURST_XC1							(2<<4)
#define TC_CMR_BURST_XC2							(3<<4)
#define TC_CMR_LDBSTOP							(1<<6)
#define TC_CMR_CPCSTOP							(1<<6)
#define TC_CMR_LDBDIS							(1<<7)
#define TC_CMR_CPCDIS							(1<<7)
#define TC_CMR_ETRGEDG							(3<<8)
#define TC_CMR_ETRGEDG_NONE							(0<<8)
#define TC_CMR_ETRGEDG_RISING							(1<<8)
#define TC_CMR_ETRGEDG_FALLING							(2<<8)
#define TC_CMR_ETRGEDG_EACH							(3<<8)
#define TC_CMR_EEVTEDG							(3<<8)
#define TC_CMR_EEVTEDG_NONE							(0<<8)
#define TC_CMR_EEVTEDG_RISING							(1<<8)
#define TC_CMR_EEVTEDG_FALLING							(2<<8)
#define TC_CMR_EEVTEDG_EACH							(3<<8)
#define TC_CMR_ABETRG							(1<<10)
#define TC_CMR_EEVT							(3<<10)
#define TC_CMR_EEVT_TIOB							(0<<10)
#define TC_CMR_EEVT_XC0								(1<<10)
#define TC_CMR_EEVT_XC1								(2<<10)
#define TC_CMR_EEVT_XC2								(3<<10)
#define TC_CMR_ENETRG							(1<<12)
#define TC_CMR_WAVSEL							(3<<13)
#define TC_CMR_WAVSEL_UP							(0<<13)
#define TC_CMR_WAVSEL_UP_AUTO							(2<<13)
#define TC_CMR_WAVSEL_UPDOWN							(1<<13)
#define TC_CMR_WAVSEL_UPDOWN_AUTO						(3<<13)
#define TC_CMR_CPCTRG							(1<<14)
#define TC_CMR_WAVE							(1<<15)
#define TC_CMR_LDRA							(3<<16)
#define TC_CMR_LDRA_NONE							(0<<16)
#define TC_CMR_LDRA_RISING							(1<<16)
#define TC_CMR_LDRA_FALLING							(2<<16)
#define TC_CMR_LDRA_EACH							(3<<16)
#define TC_CMR_ACPA							(3<<16)
#define TC_CMR_ACPA_NONE							(0<<16)
#define TC_CMR_ACPA_SET								(1<<16)
#define TC_CMR_ACPA_CLEAR							(2<<16)
#define TC_CMR_ACPA_TOGGLE							(3<<16)
#define TC_CMR_LDRB							(3<<18)
#define TC_CMR_LDRB_NONE							(0<<18)
#define TC_CMR_LDRB_RISING							(1<<18)
#define TC_CMR_LDRB_FALLING							(2<<18)
#define TC_CMR_LDRB_EACH							(3<<18)
#define TC_CMR_ACPC							(3<<18)
#define TC_CMR_ACPC_NONE							(0<<18)
#define TC_CMR_ACPC_SET								(1<<18)
#define TC_CMR_ACPC_CLEAR							(2<<18)
#define TC_CMR_ACPC_TOGGLE							(3<<18)
#define TC_CMR_AEEVT							(3<<20)
#define TC_CMR_AEEVT_NONE							(0<<20)
#define TC_CMR_AEEVT_SET							(1<<20)
#define TC_CMR_AEEVT_CLEAR							(2<<20)
#define TC_CMR_AEEVT_TOGGLE							(3<<20)
#define TC_CMR_ASWTRG							(3<<22)
#define TC_CMR_ASWTRG_NONE							(0<<22)
#define TC_CMR_ASWTRG_SET							(1<<22)
#define TC_CMR_ASWTRG_CLEAR							(2<<22)
#define TC_CMR_ASWTRG_TOGGLE							(3<<22)
#define TC_CMR_BCPB							(3<<24)
#define TC_CMR_BCPB_NONE							(0<<24)
#define TC_CMR_BCPB_SET								(1<<24)
#define TC_CMR_BCPB_CLEAR							(2<<24)
#define TC_CMR_BCPB_TOGGLE							(3<<24)
#define TC_CMR_BCPC							(3<<26)
#define TC_CMR_BCPC_NONE							(0<<26)
#define TC_CMR_BCPC_SET								(1<<26)
#define TC_CMR_BCPC_CLEAR							(2<<26)
#define TC_CMR_BCPC_TOGGLE							(3<<26)
#define TC_CMR_BEEVT							(3<<28)
#define TC_CMR_BEEVT_NONE							(0<<28)
#define TC_CMR_BEEVT_SET							(1<<28)
#define TC_CMR_BEEVT_CLEAR							(2<<28)
#define TC_CMR_BEEVT_TOGGLE							(3<<28)
#define TC_CMR_BSWTRG							(3<<30)
#define TC_CMR_BSWTRG_NONE							(0<<30)
#define TC_CMR_BSWTRG_SET							(1<<30)
#define TC_CMR_BSWTRG_CLEAR							(2<<30)
#define TC_CMR_BSWTRG_TOGGLE							(3<<30)

#define TC_SR_COVFS							(1<<0)
#define TC_SR_LOVFS							(1<<1)
#define TC_SR_CPAS							(1<<2)
#define TC_SR_CPBS							(1<<3)
#define TC_SR_CPCS							(1<<4)
#define TC_SR_LDRAS							(1<<5)
#define TC_SR_LDRBS							(1<<6)
#define TC_SR_ETRGS							(1<<7)
#define TC_SR_CLKSTA							(1<<16)
#define TC_SR_MTIOA							(1<<17)
#define TC_SR_MTIOB							(1<<18)

//-------------
// Timer/Counter 0

#define TC0_BASE							(TC_BASE+0x40*0)

#define TC0_CCR								REG(TC0_BASE+0x00)
#define TC0_CMR								REG(TC0_BASE+0x04)
#define TC0_CV								REG(TC0_BASE+0x10)
#define TC0_RA								REG(TC0_BASE+0x14)
#define TC0_RB								REG(TC0_BASE+0x18)
#define TC0_RC								REG(TC0_BASE+0x1C)
#define TC0_SR								REG(TC0_BASE+0x20)
#define TC0_IER								REG(TC0_BASE+0x24)
#define TC0_IDR								REG(TC0_BASE+0x28)
#define TC0_IMR								REG(TC0_BASE+0x2C)

//-------------
// Timer/Counter 1

#define TC1_BASE							(TC_BASE+0x40*1)

#define TC1_CCR								REG(TC1_BASE+0x00)
#define TC1_CMR								REG(TC1_BASE+0x04)
#define TC1_CV								REG(TC1_BASE+0x10)
#define TC1_RA								REG(TC1_BASE+0x14)
#define TC1_RB								REG(TC1_BASE+0x18)
#define TC1_RC								REG(TC1_BASE+0x1C)
#define TC1_SR								REG(TC1_BASE+0x20)
#define TC1_IER								REG(TC1_BASE+0x24)
#define TC1_IDR								REG(TC1_BASE+0x28)
#define TC1_IMR								REG(TC1_BASE+0x2C)

//-------------
// Timer/Counter 2

#define TC2_BASE							(TC_BASE+0x40*2)

#define TC2_CCR								REG(TC2_BASE+0x00)
#define TC2_CMR								REG(TC2_BASE+0x04)
#define TC2_CV								REG(TC2_BASE+0x10)
#define TC2_RA								REG(TC2_BASE+0x14)
#define TC2_RB								REG(TC2_BASE+0x18)
#define TC2_RC								REG(TC2_BASE+0x1C)
#define TC2_SR								REG(TC2_BASE+0x20)
#define TC2_IER								REG(TC2_BASE+0x24)
#define TC2_IDR								REG(TC2_BASE+0x28)
#define TC2_IMR								REG(TC2_BASE+0x2C)


#endif
