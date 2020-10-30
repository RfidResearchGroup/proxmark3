//-----------------------------------------------------------------------------
// piwi, 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to get sample data from FPGA.
//-----------------------------------------------------------------------------
#include "hfsnoop.h"
#include "proxmark3_arm.h"
#include "BigBuf.h"
#include "fpgaloader.h"
#include "ticks.h"
#include "dbprint.h"
#include "util.h"
#include "fpga.h"
#include "appmain.h"
#include "cmd.h"

static void RAMFUNC optimizedSniff(uint16_t *dest, uint16_t dsize) {
    while (dsize > 0) {
        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            *dest = (uint16_t)(AT91C_BASE_SSC->SSC_RHR);
            dest++;
            dsize -= sizeof(dsize);
        }
    }
}

int HfSniff(uint32_t samplesToSkip, uint32_t triggersToSkip, uint16_t *len) {
    BigBuf_free();
    BigBuf_Clear_ext(false);

    Dbprintf("Skipping first %d sample pairs, Skipping %d triggers", samplesToSkip, triggersToSkip);

    LED_D_ON();

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

    // Set up the synchronous serial port
    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_SNIFF);

    // Setting Frame Mode For better performance on high speed data transfer.
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(16);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_SNIFF);
    SpinDelay(100);

    *len = (BigBuf_max_traceLen() & 0xFFFE);
    uint8_t *mem = BigBuf_malloc(*len);

    uint32_t trigger_cnt = 0;
    uint16_t r = 0, interval = 0;

    bool pressed = false;
    while (pressed == false) {
        WDT_HIT();

        // cancel w usb command.
        if (interval == 2000) {
            if (data_available())
                break;

            interval = 0;
        } else {
            interval++;
        }

        // check if trigger is reached
        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            r = (uint16_t)AT91C_BASE_SSC->SSC_RHR;

            r = MAX(r & 0xFF, r >> 8);

            // 180 (0xB4) arbitary value to see if a strong RF field is near.
            if (r > 180) {

                if (++trigger_cnt > triggersToSkip) {
                    break;
                }
            }
        }

        pressed = BUTTON_PRESS();
    }

    if (pressed == false) {

        // skip samples loop
        while (samplesToSkip != 0) {

            if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
                samplesToSkip--;
            }
        }

        optimizedSniff((uint16_t *)mem, *len);

        if (DBGLEVEL >= DBG_INFO) {
            Dbprintf("Trigger kicked in (%d >= 180)", r);
            Dbprintf("Collected %u samples", *len);
        }
    }

    //Resetting Frame mode (First set in fpgaloader.c)
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    LED_D_OFF();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    BigBuf_free();
    return (pressed) ? PM3_EOPABORTED : PM3_SUCCESS;
}

void HfPlotDownload(void) {

    tosend_t *ts = get_tosend();
    uint8_t *this_buf = ts->buf;

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    FpgaSetupSsc(FPGA_MAJOR_MODE_HF_GET_TRACE);

    AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTDIS;   // Disable DMA Transfer
    AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) this_buf; // start transfer to this memory address
    AT91C_BASE_PDC_SSC->PDC_RCR = PM3_CMD_DATA_SIZE;   // transfer this many samples
    ts->buf[0] = (uint8_t)AT91C_BASE_SSC->SSC_RHR;         // clear receive register
    AT91C_BASE_PDC_SSC->PDC_PTCR = AT91C_PDC_RXTEN;    // Start DMA transfer

    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_GET_TRACE);   // let FPGA transfer its internal Block-RAM

    LED_B_ON();
    for (size_t i = 0; i < FPGA_TRACE_SIZE; i += PM3_CMD_DATA_SIZE) {
        // prepare next DMA transfer:
        uint8_t *next_buf = ts->buf + ((i + PM3_CMD_DATA_SIZE) % (2 * PM3_CMD_DATA_SIZE));

        AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t)next_buf;
        AT91C_BASE_PDC_SSC->PDC_RNCR = PM3_CMD_DATA_SIZE;

        size_t len = MIN(FPGA_TRACE_SIZE - i, PM3_CMD_DATA_SIZE);

        while (!(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_ENDRX))) {}; // wait for DMA transfer to complete

        reply_old(CMD_FPGAMEM_DOWNLOADED, i, len, FPGA_TRACE_SIZE, this_buf, len);
        this_buf = next_buf;
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);

    // Trigger a finish downloading signal with an ACK frame
    reply_mix(CMD_ACK, 1, 0, FPGA_TRACE_SIZE, 0, 0);
    LED_B_OFF();
}
