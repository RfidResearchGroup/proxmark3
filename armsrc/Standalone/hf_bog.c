//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for standalone HF Sniff (and ULC/NTAG/ULEV1 pwd storing)
//-----------------------------------------------------------------------------

/*
This can actually be used in two separate ways.
It can either be used to just HF 14a sniff on the go and/or grab the
authentication attempts for ULC/NTAG/ULEV1 into the flash mem (RDV4).

The retrieved sniffing session can be acquired by connecting the device
to a client that supports the reconnect capability and issue 'hf 14a list'.

In order to view the grabbed authentication attempts in the flash mem,
you can simply run 'script run read_pwd_mem' or just 'mem read l 256'
from the client to view the stored quadlets.
*/

#include "hf_bog.h"

#define DELAY_READER_AIR2ARM_AS_SNIFFER (2 + 3 + 8)
#define DELAY_TAG_AIR2ARM_AS_SNIFFER (3 + 14 + 8)

// Maximum number of auth attempts per standalone session
#define MAX_PWDS_PER_SESSION 64

uint8_t FindOffsetInFlash() {
    uint8_t mem[4] = { 0x00, 0x00, 0x00, 0x00 };
    uint8_t eom[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint8_t memcnt = 0;

    while (memcnt < 0xFF) {
        Flash_ReadData(memcnt, mem, 4);
        if (memcmp(mem, eom, 4) == 0) {
            return memcnt;
        }
        memcnt += 4;
    }

    return 0; // wrap-around
}

void EraseMemory() {
    if (!FlashInit()) {
        return;
    }

    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();
    Flash_Erase4k(0, 0);

    if (DBGLEVEL > 1) Dbprintf("[!] Erased flash!");
    FlashStop();
    SpinDelay(100);
}

// This is actually copied from SniffIso14443a
void RAMFUNC SniffAndStore(uint8_t param) {

    iso14443a_setup(FPGA_HF_ISO14443A_SNIFFER);

    // Allocate memory from BigBuf for some buffers
    // free all previous allocations first
    BigBuf_free();
    BigBuf_Clear_ext(false);
    clear_trace();
    set_tracing(true);

    // Array to store the authpwds
    uint8_t *capturedPwds = BigBuf_malloc(4 * MAX_PWDS_PER_SESSION);

    // The command (reader -> tag) that we're receiving.
    uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);
    uint8_t *receivedCmdPar = BigBuf_malloc(MAX_PARITY_SIZE);

    // The response (tag -> reader) that we're receiving.
    uint8_t *receivedResp = BigBuf_malloc(MAX_FRAME_SIZE);
    uint8_t *receivedRespPar = BigBuf_malloc(MAX_PARITY_SIZE);

    // The DMA buffer, used to stream samples from the FPGA
    uint8_t *dmaBuf = BigBuf_malloc(DMA_BUFFER_SIZE);
    uint8_t *data = dmaBuf;

    uint8_t previous_data = 0;
    int dataLen;
    bool TagIsActive = false;
    bool ReaderIsActive = false;

    // Set up the demodulator for tag -> reader responses.
    DemodInit(receivedResp, receivedRespPar);

    // Set up the demodulator for the reader -> tag commands
    UartInit(receivedCmd, receivedCmdPar);

    // Setup and start DMA.
    if (!FpgaSetupSscDma((uint8_t *) dmaBuf, DMA_BUFFER_SIZE)) {
        if (DBGLEVEL > 1) Dbprintf("FpgaSetupSscDma failed. Exiting");
        return;
    }

    tUart *uart = GetUart();
    tDemod *demod = GetDemod();

    // We won't start recording the frames that we acquire until we trigger;
    // a good trigger condition to get started is probably when we see a
    // response from the tag.
    // triggered == false -- to wait first for card
    bool triggered = !(param & 0x03);

    uint32_t my_rsamples = 0;

    // Current captured passwords counter
    uint8_t auth_attempts = 0;

    SpinDelay(50);

    // loop and listen
    while (!BUTTON_PRESS()) {
        WDT_HIT();
        LED_A_ON();

        int register readBufDataP = data - dmaBuf;
        int register dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
        if (readBufDataP <= dmaBufDataP)
            dataLen = dmaBufDataP - readBufDataP;
        else
            dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP;

        // test for length of buffer
        if (dataLen > DMA_BUFFER_SIZE) { // TODO: Check if this works properly
            Dbprintf("[!] blew circular buffer! | datalen %u", dataLen);
            break;
        }
        if (dataLen < 1) continue;

        // primary buffer was stopped( <-- we lost data!
        if (!AT91C_BASE_PDC_SSC->PDC_RCR) {
            AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dmaBuf;
            AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
            //Dbprintf("[-] RxEmpty ERROR | data length %d", dataLen); // temporary
        }
        // secondary buffer sets as primary, secondary buffer was stopped
        if (!AT91C_BASE_PDC_SSC->PDC_RNCR) {
            AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;
            AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
        }

        LED_A_OFF();

        // Need two samples to feed Miller and Manchester-Decoder
        if (my_rsamples & 0x01) {

            if (!TagIsActive) { // no need to try decoding reader data if the tag is sending
                uint8_t readerdata = (previous_data & 0xF0) | (*data >> 4);
                if (MillerDecoding(readerdata, (my_rsamples - 1) * 4)) {
                    LED_C_ON();

                    // check - if there is a short 7bit request from reader
                    if ((!triggered) && (param & 0x02) && (uart->len == 1) && (uart->bitCount == 7)) triggered = true;

                    if (triggered) {
                        if ((receivedCmd) && ((receivedCmd[0] == MIFARE_ULEV1_AUTH) || (receivedCmd[0] == MIFARE_ULC_AUTH_1))) {
                            if (DBGLEVEL > 1) Dbprintf("PWD-AUTH KEY: 0x%02x%02x%02x%02x", receivedCmd[1], receivedCmd[2], receivedCmd[3], receivedCmd[4]);

                            // temporarily save the captured pwd in our array
                            memcpy(&capturedPwds[4 * auth_attempts], receivedCmd + 1, 4);
                            auth_attempts++;
                        }

                        if (!LogTrace(receivedCmd,
                                      uart->len,
                                      uart->startTime * 16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
                                      uart->endTime * 16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
                                      uart->parity,
                                      true)) break;
                    }
                    /* ready to receive another command. */
                    UartReset();
                    /* reset the demod code, which might have been */
                    /* false-triggered by the commands from the reader. */
                    DemodReset();
                    LED_B_OFF();
                }
                ReaderIsActive = (uart->state != STATE_UNSYNCD);
            }

            // no need to try decoding tag data if the reader is sending - and we cannot afford the time
            if (!ReaderIsActive) {
                uint8_t tagdata = (previous_data << 4) | (*data & 0x0F);
                if (ManchesterDecoding(tagdata, 0, (my_rsamples - 1) * 4)) {
                    LED_B_ON();

                    if (!LogTrace(receivedResp,
                                  demod->len,
                                  demod->startTime * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
                                  demod->endTime * 16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
                                  demod->parity,
                                  false)) break;

                    if ((!triggered) && (param & 0x01)) triggered = true;

                    // ready to receive another response.
                    DemodReset();
                    // reset the Miller decoder including its (now outdated) input buffer
                    UartReset();
                    //UartInit(receivedCmd, receivedCmdPar);
                    LED_C_OFF();
                }
                TagIsActive = (demod->state != DEMOD_UNSYNCD);
            }
        }

        previous_data = *data;
        my_rsamples++;
        data++;
        if (data == dmaBuf + DMA_BUFFER_SIZE) {
            data = dmaBuf;
        }
    } // end main loop

    FpgaDisableSscDma();
    set_tracing(false);

    Dbprintf("Stopped sniffing");

    SpinDelay(200);

    // Write stuff to flash
    if (auth_attempts > 0) {
        if (DBGLEVEL > 1) Dbprintf("[!] Authentication attempts = %u", auth_attempts);

        // Setting the SPI Baudrate to 48MHz to avoid the bit-flip issue (https://github.com/RfidResearchGroup/proxmark3/issues/34)
        FlashmemSetSpiBaudrate(48000000);

        // Find the offset in flash mem to continue writing the auth attempts
        uint8_t memoffset = FindOffsetInFlash();
        if (DBGLEVEL > 1) Dbprintf("[!] Memory offset = %u", memoffset);

        if ((memoffset + 4 * auth_attempts) > 0xFF) {
            // We opt to keep the new data only
            memoffset = 0;
            if (DBGLEVEL > 1) Dbprintf("[!] Size of total data > 256 bytes. Discarding the old data.");
        }

        // Get previous data from flash mem
        uint8_t *previousdata = BigBuf_malloc(memoffset);
        if (memoffset > 0) {
            uint16_t readlen = Flash_ReadData(0, previousdata, memoffset);
            if (DBGLEVEL > 1) Dbprintf("[!] Read %u bytes from flash mem", readlen);
        }

        // create new bigbuf to hold all data
        size_t total_size = memoffset + 4 * auth_attempts;
        uint8_t *total_data = BigBuf_malloc(total_size);

        // Add the previousdata array into total_data array
        memcpy(total_data, previousdata, memoffset);

        // Copy bytes of capturedPwds immediately following bytes of previousdata
        memcpy(total_data + memoffset, capturedPwds, 4 * auth_attempts);

        // Erase first page of flash mem
        EraseMemory();

        // Write total data to flash mem
        uint16_t writelen = Flash_WriteData(0, total_data, memoffset + 4 * auth_attempts);
        if (DBGLEVEL > 1) Dbprintf("[!] Wrote %u bytes into flash mem", writelen);

        // If pwd saved successfully, blink led A three times
        if (writelen > 0) {
            SpinErr(0, 200, 5); // blink led A
        }

        SpinDelay(100);

        // Reset the SPI Baudrate to the default value (24MHz)
        FlashmemSetSpiBaudrate(24000000);
    }
}

void ModInfo(void) {
    DbpString("   HF 14a sniff standalone with ULC/ULEV1/NTAG auth storing in flashmem - aka BogitoRun (Bogito)");
}

void RunMod() {

    StandAloneMode();

    Dbprintf(">>  Bogiton 14a Sniff UL/UL-EV1/NTAG a.k.a BogitoRun Started  <<");
    Dbprintf("Starting to sniff");

    // param:
    // bit 0 - trigger from first card answer
    // bit 1 - trigger from first reader 7-bit request
    SniffAndStore(0);
    LEDsoff();
    SpinDelay(300);
    Dbprintf("- [ End ] -> You can take shell back ...");
    Dbprintf("- [  !  ] -> use 'script run read_pwd_mem' to print passwords");
}
