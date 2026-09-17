#include "at91sam7s512.h"
#include "fpga_apis.h"
#include "fpga_loader.h"
#include "common.h"
#include "proxmark3_arm.h"
#include "dbprint.h"

void FpgaSetup24MHzClk(void) {
    // The FPGA gets its clock from us from PCK0 output, so set that up.
    AT91C_BASE_PIOA->PIO_BSR = GPIO_PCK0;
    AT91C_BASE_PIOA->PIO_PDR = GPIO_PCK0;
    AT91C_BASE_PMC->PMC_SCER |= AT91C_PMC_PCK0;
    // PCK0 is PLL clock / 4 = 96MHz / 4 = 24MHz
    AT91C_BASE_PMC->PMC_PCKR[0] = AT91C_PMC_CSS_PLL_CLK | AT91C_PMC_PRES_CLK_4; //  4 for 24MHz pck0, 2 for 48 MHZ pck0
    AT91C_BASE_PIOA->PIO_OER = GPIO_PCK0;
}

void FpgaResetComInterface(void) {
    // Reset SPI
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SWRST;
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SWRST; // errata says it needs twice to be correctly set.

    // Reset SSC
    AT91C_BASE_SSC->SSC_CR = AT91C_SSC_SWRST;
}

void FpgaSetupSsc(uint16_t fpga_mode) {
    // First configure the GPIOs, and get ourselves a clock.
    AT91C_BASE_PIOA->PIO_ASR =
        GPIO_SSC_FRAME  |
        GPIO_SSC_DIN    |
        GPIO_SSC_DOUT   |
        GPIO_SSC_CLK;
    AT91C_BASE_PIOA->PIO_PDR = GPIO_SSC_DOUT;

    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_SSC);

    // Now set up the SSC proper, starting from a known state.
    AT91C_BASE_SSC->SSC_CR = AT91C_SSC_SWRST;

    // RX clock comes from TX clock, RX starts on Transmit Start,
    // data and frame signal is sampled on falling edge of RK
    AT91C_BASE_SSC->SSC_RCMR = SSC_CLOCK_MODE_SELECT(1) | SSC_CLOCK_MODE_START(1);

    // 8 or 16 per transfer, no loopback, MSB first, 1 transfer per sync pulse, no output sync
    if (FpgaIs16BitMsbMode(fpga_mode)) {
        AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(16) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    } else {
        AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    }

    // TX clock comes from TK pin, no clock output, outputs change on rising edge of TK,
    // TF (frame sync) is sampled on falling edge of TK, start TX on rising edge of TF
    AT91C_BASE_SSC->SSC_TCMR = SSC_CLOCK_MODE_SELECT(2) | SSC_CLOCK_MODE_START(5);

    // tx framing is the same as the rx framing
    AT91C_BASE_SSC->SSC_TFMR = AT91C_BASE_SSC->SSC_RFMR;

    AT91C_BASE_SSC->SSC_CR = AT91C_SSC_RXEN | AT91C_SSC_TXEN;
}

void FpgaUpdateFrameMode(uint8_t bits, bool rx_msb, bool tx_msb) {
    // AT91C_SSC_MSBF = (0x1 <<  7)
    // It's a magic, if we need msb, the msb param is 1, so we can set a valid enable bit to msb reg.
    //  0 = 0 << 7, so lsb will skip update.
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(bits) | (rx_msb <<  7);
    AT91C_BASE_SSC->SSC_TFMR = SSC_FRAME_MODE_BITS_IN_WORD(bits) | (tx_msb <<  7);
}

bool FpgaSetupSscRxDmaRepeat(void *buf, uint16_t len) {
    if (buf == NULL) {
        return false;
    }

    // len is a count of PDC *transfers*, not bytes. SSC_RFMR.DATLEN sets the width:
    // DATLEN <= 7 transfers bytes, 8..15 half-words. FpgaSetupSsc() picks 16 bits for
    // FPGA_MAJOR_MODE_HF_READER on the HF/HF_15 bitstreams and 8 bits otherwise, so
    // the same len is twice the memory on the reader paths - which is why get_dma16()
    // allocates DMA_BUFFER_SIZE * sizeof(uint16_t) while get_dma8() allocates
    // DMA_BUFFER_SIZE. Half-word transfers also need a 2 byte aligned buf.
    FPGA_SSC_DMA_RX_Disable();
    AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) buf;  // transfer to this memory address
    AT91C_BASE_PDC_SSC->PDC_RCR = len;             // this many transfers
    AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) buf; // next transfer to same memory address
    AT91C_BASE_PDC_SSC->PDC_RNCR = len;            // ... with the same count
    FPGA_SSC_DMA_RX_Enable();
    return true;
}

bool FpgaSetupSscRxDmaSingle(void *buf, uint16_t len) {
    if (buf == NULL) {
        return false;
    }

    FPGA_SSC_DMA_RX_Disable();                         // Disable DMA Transfer
    AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) buf;      // start transfer to this memory address
    AT91C_BASE_PDC_SSC->PDC_RCR = len;                 // transfer this many samples
    ((uint8_t *)buf)[0] = (uint8_t)FPGA_SSC_RX_Value(); // clear receive register
    FPGA_SSC_DMA_RX_Enable();                          // Start DMA transfer

    return true;
}

//-----------------------------------------------------------------------------
// Set up the Serial Peripheral Interface as master
// Used to write the FPGA config word
// May also be used to write to other SPI attached devices like an LCD
//-----------------------------------------------------------------------------
static void DisableSpi(void) {
    //* Reset all the Chip Select register
    AT91C_BASE_SPI->SPI_CSR[0] = 0;
    AT91C_BASE_SPI->SPI_CSR[1] = 0;
    AT91C_BASE_SPI->SPI_CSR[2] = 0;
    AT91C_BASE_SPI->SPI_CSR[3] = 0;

    // Reset the SPI mode
    AT91C_BASE_SPI->SPI_MR = 0;

    // Disable all interrupts
    AT91C_BASE_SPI->SPI_IDR = 0xFFFFFFFF;

    // SPI disable
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIDIS;
}

static void SetupSpi(int mode) {
    // PA1  -> SPI_NCS3 chip select (MEM)
    // PA10 -> SPI_NCS2 chip select (LCD)
    // PA11 -> SPI_NCS0 chip select (FPGA)
    // PA12 -> SPI_MISO Master-In Slave-Out
    // PA13 -> SPI_MOSI Master-Out Slave-In
    // PA14 -> SPI_SPCK Serial Clock

    // Disable PIO control of the following pins, allows use by the SPI peripheral
    AT91C_BASE_PIOA->PIO_PDR = GPIO_NCS0 | GPIO_MISO | GPIO_MOSI | GPIO_SPCK;

    // Peripheral A
    AT91C_BASE_PIOA->PIO_ASR = GPIO_NCS0 | GPIO_MISO | GPIO_MOSI | GPIO_SPCK;

    // Peripheral B
    //AT91C_BASE_PIOA->PIO_BSR |= GPIO_NCS2;

    //enable the SPI Peripheral clock
    AT91C_BASE_PMC->PMC_PCER = (1 << AT91C_ID_SPI);
    // Enable SPI
    AT91C_BASE_SPI->SPI_CR = AT91C_SPI_SPIEN;

    switch (mode) {
        case SPI_FPGA_MODE:
            AT91C_BASE_SPI->SPI_MR =
                (0 << 24)          |  // Delay between chip selects (take default: 6 MCK periods)
                (0xE << 16)        |  // Peripheral Chip Select (selects FPGA SPI_NCS0 or PA11)
                (0 << 7)           |  // Local Loopback Disabled
                AT91C_SPI_MODFDIS  |  // Mode Fault Detection disabled
                (0 << 2)           |  // Chip selects connected directly to peripheral
                AT91C_SPI_PS_FIXED |  // Fixed Peripheral Select
                AT91C_SPI_MSTR;       // Master Mode

            AT91C_BASE_SPI->SPI_CSR[0] =
                (1 << 24)          |  // Delay between Consecutive Transfers (32 MCK periods)
                (1 << 16)          |  // Delay Before SPCK (1 MCK period)
                (6 << 8)           |  // Serial Clock Baud Rate (baudrate = MCK/6 = 24MHz/6 = 4M baud
                AT91C_SPI_BITS_16  |  // Bits per Transfer (16 bits)
                (0 << 3)           |  // Chip Select inactive after transfer
                AT91C_SPI_NCPHA    |  // Clock Phase data captured on leading edge, changes on following edge
                (0 << 0);             // Clock Polarity inactive state is logic 0
            break;
        /*
                    case SPI_LCD_MODE:
                    AT91C_BASE_SPI->SPI_MR =
                        ( 0 << 24)         |  // Delay between chip selects (take default: 6 MCK periods)
                        (0xB << 16)        |  // Peripheral Chip Select (selects LCD SPI_NCS2 or PA10)
                        ( 0 << 7)          |  // Local Loopback Disabled
                        ( 1 << 4)          |  // Mode Fault Detection disabled
                        ( 0 << 2)          |  // Chip selects connected directly to peripheral
                        ( 0 << 1)          |  // Fixed Peripheral Select
                        ( 1 << 0);            // Master Mode

                    AT91C_BASE_SPI->SPI_CSR[2] =
                        ( 1 << 24)         |  // Delay between Consecutive Transfers (32 MCK periods)
                        ( 1 << 16)         |  // Delay Before SPCK (1 MCK period)
                        ( 6 << 8)          |  // Serial Clock Baud Rate (baudrate = MCK/6 = 24MHz/6 = 4M baud
                        AT91C_SPI_BITS_9   |  // Bits per Transfer (9 bits)
                        ( 0 << 3)          |  // Chip Select inactive after transfer
                        ( 1 << 1)          |  // Clock Phase data captured on leading edge, changes on following edge
                        ( 0 << 0);            // Clock Polarity inactive state is logic 0
                    break;
        */
        default:
            DisableSpi();
            break;
    }
}

void FpgaSendCommand(uint16_t cmd, uint16_t v) {
    SetupSpi(SPI_FPGA_MODE);

    // RDRF is cleared only by reading SPI_RDR, or by an SPI software reset.  Nothing
    // here used to read it, so it latched on the very first transfer and the wait at
    // the end of this function became a no-op for every call after that one, leaving
    // the word still shifting out when we returned.  That matters because the FPGA
    // decodes shift_reg[15:12] on the rising edge of NCS with no bit count of its own
    // (fpga_pm3_top.v): a word cut short latches whatever the *previous* word left in
    // those four bits - a different command, or, since the case has no default, none
    // at all, silently dropping the write.  The drains below are what make RDRF mean
    // "this transfer finished" again.
    while ((AT91C_BASE_SPI->SPI_SR & AT91C_SPI_TXEMPTY) == 0) {}; // wait for any previous transfer
    (void)AT91C_BASE_SPI->SPI_RDR;                                // clear a stale RDRF

    AT91C_BASE_SPI->SPI_TDR = AT91C_SPI_LASTXFER | cmd | v;       // send the data

    // Bounded: 16 bits at MCK/6 = 4 MHz takes ~4us, so this is orders of magnitude of
    // headroom.  It is a loop rather than a spin because a dead SPI - clock gated, or
    // the bus reset underneath us by the shared flash driver - must not hang the device
    // here, where there is no WDT_HIT().
    for (uint32_t i = 0; i < 100000; i++) {
        if (AT91C_BASE_SPI->SPI_SR & AT91C_SPI_RDRF) {
            break;
        }
    }
    (void)AT91C_BASE_SPI->SPI_RDR;                                // leave RDRF clear
}

void Fpga_print_status(void) {
    DbpString(_CYAN_("Current FPGA image"));
    Dbprintf("  mode.................... %s", FpgaGetCurrentVersionString());
}

// -------------------------------------------------------------------
//                  Config bitstream for FPGA
// Waiting for impl...

int FpgaStartConfig(bool configSram, uint32_t fileLength) {
    // TODO DXL: Not implemented
    return PM3_ENOTIMPL;
}

int FpgaConfigWrite(uint8_t *data, uint32_t data_length) {
    return PM3_ENOTIMPL;
}
int FpgaStopConfig(void) {
    return PM3_ENOTIMPL;
}

uint32_t FpgaConfigPlatformStatus(void) {
    return 0;
}

// -------------------------------------------------------------------
