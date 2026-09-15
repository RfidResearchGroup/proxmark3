//-----------------------------------------------------------------------------
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
// MIFARE DESFire tag simulation.
//
// Serves the card image `hf mfdes eload` put in emulator memory. The layout is
// in include/desfire_em.h; nothing here parses json or knows about files on the
// host, it only walks that image.
//
// This file is the DESFire half only. Anticollision, RATS, framing and timing
// are SimulateIso14443aTag()'s job over in iso14443a.c, which activates tag
// type 3 from the identity in the image and hands every ISO 14443-4 I-block to
// desfire_sim_apdu(). Duplicating that loop here got the ATQA wrong and would
// have kept drifting from the one that is exercised by every other tag type.
//
// Two timing regimes, and they want opposite things:
//
//  - Before RATS there is no negotiated frame waiting time, and a tag that
//    encodes its answer inside the response window is late. ATQA, the UID
//    cascades, SAK and ATS are therefore precompiled by SimulateIso14443aInit()
//    exactly as every other 14a simulation does.
//
//  - After RATS the EV1 ATS asks for FWI 8, which is 77.33 ms, about 3.7
//    million ARM cycles. Everything from SelectApplication onward is computed
//    on demand from the image. A software AES block costs a fraction of a
//    percent of that, so there is no reason to precompute answers and every
//    reason not to: a precomputed card cannot answer a write.
//
// What is implemented so far is the unauthenticated half: a reader can find the
// card, read its version, enumerate applications and files, and read file
// settings. Anything else answers ILLEGAL_COMMAND_CODE, which is what a real
// PICC says to a command it does not have.
//-----------------------------------------------------------------------------

#include "desfiresim.h"

#include "string.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "appmain.h"
#include "BigBuf.h"
#include "dbprint.h"
#include "util.h"
#include "iso14443a.h"
#include "crc16.h"
#include "fpga_apis.h"
#include "fpga_loader.h"
#include "protocols.h"
#include "desfire_em.h"

// ISO 7816 wrapping of the DESFire command set: class byte on the way in,
// first status byte on the way back.
#define DESFIRE_SIM_ISO7816_CLA 0x90
#define DESFIRE_SIM_ISO7816_SW1 0x91

// Largest answer built before the 14443-4 prologue and CRC are added.
// GetApplicationIDs on a full PICC is 28 * 3 bytes plus a status byte.
#define DESFIRE_SIM_MAX_RESP    128

typedef struct {
    const desfire_em_hdr_t *hdr;
    const desfire_em_app_t *apps;
    const desfire_em_file_t *files;
    const uint8_t *base;

    int selected;               // index into apps[], -1 when nothing is selected
    uint8_t chain_cmd;          // command being continued over 0xAF, 0 when none
    uint8_t chain_step;         // which frame of it comes next
} desfire_sim_state_t;

// The simulation runs one card at a time, and the 14a loop calls in here from
// several places, so the state is a file static rather than something the
// caller has to carry around.
static desfire_sim_state_t s_st;
static bool s_ready = false;

// ---------------------------------------------------------------- image walk

static bool desfire_sim_load(desfire_sim_state_t *st) {

    const uint8_t *em = BigBuf_get_EM_addr();
    if (em == NULL) {
        return false;
    }

    const desfire_em_hdr_t *hdr = (const desfire_em_hdr_t *)em;

    if (hdr->magic != DESFIRE_EM_MAGIC) {
        // Not an error: `hf 14a sim -t 3` with nothing loaded is a legitimate
        // bare PICC that answers the anticollision and nothing else. The caller
        // says so once, rather than this firing on every activation.
        if (g_dbglevel >= DBG_EXTENDED) {
            Dbprintf("No DESFire card image in emulator memory, magic is " _YELLOW_("%08x"), hdr->magic);
        }
        return false;
    }

    if (hdr->layout != DESFIRE_EM_LAYOUT_VERSION) {
        Dbprintf("Card image layout v%u, this firmware speaks v%u", hdr->layout, DESFIRE_EM_LAYOUT_VERSION);
        return false;
    }

    if (hdr->size > BigBuf_get_EM_size() || hdr->appcount == 0) {
        Dbprintf("Card image does not fit the emulator memory it was loaded into");
        return false;
    }

    st->base = em;
    st->hdr = hdr;
    st->apps = (const desfire_em_app_t *)(em + hdr->app_off);
    st->files = (const desfire_em_file_t *)(em + hdr->file_off);
    st->selected = 0;           // a PICC comes up with AID 000000 selected
    st->chain_cmd = 0;
    st->chain_step = 0;
    return true;
}

static uint32_t desfire_sim_aid(const desfire_em_app_t *a) {
    return a->aid[0] | (a->aid[1] << 8) | (a->aid[2] << 16);
}

static int desfire_sim_find_app(const desfire_sim_state_t *st, uint32_t aid) {

    for (uint8_t i = 0; i < st->hdr->appcount; i++) {
        if ((st->apps[i].flags & DESFIRE_EM_APP_DELETED) == 0 && desfire_sim_aid(&st->apps[i]) == aid) {
            return i;
        }
    }
    return -1;
}

// --------------------------------------------------------------- the answers

// Build one DESFire answer: a status byte and optional payload. Returns the
// length written to `out`.
static uint16_t desfire_sim_status(uint8_t *out, uint8_t status) {
    out[0] = status;
    return 1;
}

static uint16_t desfire_sim_payload(uint8_t *out, uint8_t status, const uint8_t *data, uint16_t len) {
    out[0] = status;
    if (len) {
        memcpy(out + 1, data, len);
    }
    return len + 1;
}

// Dispatch one DESFire command. `cmd` is the command byte, `in`/`inlen` the
// parameters after it. Writes the answer to `out` and returns its length.
static uint16_t desfire_sim_command(desfire_sim_state_t *st, uint8_t cmd, const uint8_t *in, uint16_t inlen, uint8_t *out) {

    const desfire_em_hdr_t *hdr = st->hdr;

    // an additional frame only means anything while a command is being chained
    if (cmd == MFDES_ADDITIONAL_FRAME && st->chain_cmd == 0) {
        return desfire_sim_status(out, MFDES_E_ILLEGAL_COMMAND_CODE);
    }

    if (cmd != MFDES_ADDITIONAL_FRAME) {
        st->chain_cmd = 0;
        st->chain_step = 0;
    }

    switch (cmd) {

        case MFDES_GET_VERSION: {
            // three frames: hardware, software, then production. The first two
            // are answered with ADDITIONAL_FRAME so the reader asks again.
            st->chain_cmd = MFDES_GET_VERSION;
            st->chain_step = 1;
            return desfire_sim_payload(out, MFDES_ADDITIONAL_FRAME, hdr->versionhw, hdr->versionhwlen);
        }

        case MFDES_ADDITIONAL_FRAME: {

            if (st->chain_cmd == MFDES_GET_VERSION) {

                if (st->chain_step == 1) {
                    st->chain_step = 2;
                    return desfire_sim_payload(out, MFDES_ADDITIONAL_FRAME, hdr->versionsw, hdr->versionswlen);
                }

                st->chain_cmd = 0;
                st->chain_step = 0;
                return desfire_sim_payload(out, MFDES_S_OPERATION_OK, hdr->versionprod, hdr->versionprodlen);
            }

            return desfire_sim_status(out, MFDES_E_ILLEGAL_COMMAND_CODE);
        }

        case MFDES_GET_APPLICATION_IDS: {
            // PICC level only
            if (st->selected != 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint8_t buf[DESFIRE_SIM_MAX_RESP] = {0};
            uint16_t n = 0;
            for (uint8_t i = 1; i < hdr->appcount && (n + 3) <= sizeof(buf); i++) {
                if (st->apps[i].flags & DESFIRE_EM_APP_DELETED) {
                    continue;
                }
                memcpy(buf + n, st->apps[i].aid, 3);
                n += 3;
            }
            return desfire_sim_payload(out, MFDES_S_OPERATION_OK, buf, n);
        }

        case MFDES_SELECT_APPLICATION: {

            if (inlen < 3) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            uint32_t aid = in[0] | (in[1] << 8) | (in[2] << 16);
            int idx = desfire_sim_find_app(st, aid);
            if (idx < 0) {
                return desfire_sim_status(out, MFDES_E_APPLICATION_NOT_FOUND);
            }

            st->selected = idx;
            return desfire_sim_status(out, MFDES_S_OPERATION_OK);
        }

        case MFDES_GET_FREE_MEMORY: {
            // what the card has left, not what emulator memory has left. Three
            // bytes, LSB first.
            uint32_t freemem = (hdr->cardsize > hdr->reserved) ? (hdr->cardsize - hdr->reserved) : 0;
            uint8_t buf[3] = { freemem & 0xFF, (freemem >> 8) & 0xFF, (freemem >> 16) & 0xFF };
            return desfire_sim_payload(out, MFDES_S_OPERATION_OK, buf, sizeof(buf));
        }

        case MFDES_GET_KEY_SETTINGS: {
            const desfire_em_app_t *a = &st->apps[st->selected];
            uint8_t buf[2] = { a->keysettings, a->numkeysraw };
            return desfire_sim_payload(out, MFDES_S_OPERATION_OK, buf, sizeof(buf));
        }

        case MFDES_GET_FILE_IDS: {

            if (st->selected == 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint8_t buf[DESFIRE_SIM_MAX_RESP] = {0};
            uint16_t n = 0;
            for (uint16_t i = 0; i < hdr->filecount && n < sizeof(buf); i++) {
                if (st->files[i].app != st->selected) {
                    continue;
                }
                if (st->files[i].flags & DESFIRE_EM_FILE_DELETED) {
                    continue;
                }
                buf[n++] = st->files[i].num;
            }
            return desfire_sim_payload(out, MFDES_S_OPERATION_OK, buf, n);
        }

        case MFDES_GET_FILE_SETTINGS: {

            if (inlen < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            for (uint16_t i = 0; i < hdr->filecount; i++) {

                const desfire_em_file_t *f = &st->files[i];
                if (f->app != st->selected || f->num != in[0]) {
                    continue;
                }
                if (f->flags & DESFIRE_EM_FILE_DELETED) {
                    break;
                }

                uint8_t buf[17] = {0};
                uint16_t n = 0;
                buf[n++] = f->type;
                buf[n++] = f->flags & DESFIRE_EM_FILE_COMM_MASK;
                buf[n++] = f->rights & 0xFF;
                buf[n++] = (f->rights >> 8) & 0xFF;

                switch (f->type) {
                    case 0x00:
                    case 0x01: {
                        // the size the file was created with, not the rounded
                        // allocation -- measured, a real card reports 1 for a
                        // file created with 1
                        uint32_t v = f->u.data.size;
                        buf[n++] = v & 0xFF;
                        buf[n++] = (v >> 8) & 0xFF;
                        buf[n++] = (v >> 16) & 0xFF;
                        break;
                    }
                    case 0x02: {
                        const uint32_t vals[3] = { f->u.value.lower, f->u.value.upper, f->u.value.value };
                        for (uint8_t v = 0; v < 3; v++) {
                            buf[n++] = vals[v] & 0xFF;
                            buf[n++] = (vals[v] >> 8) & 0xFF;
                            buf[n++] = (vals[v] >> 16) & 0xFF;
                            buf[n++] = (vals[v] >> 24) & 0xFF;
                        }
                        buf[n++] = (f->flags & DESFIRE_EM_FILE_LIMCREDIT) ? 1 : 0;
                        break;
                    }
                    case 0x03:
                    case 0x04: {
                        const uint32_t vals[3] = { f->u.record.recordsize, f->u.record.maxrecords, f->u.record.currecords };
                        for (uint8_t v = 0; v < 3; v++) {
                            buf[n++] = vals[v] & 0xFF;
                            buf[n++] = (vals[v] >> 8) & 0xFF;
                            buf[n++] = (vals[v] >> 16) & 0xFF;
                        }
                        break;
                    }
                    default:
                        break;
                }

                return desfire_sim_payload(out, MFDES_S_OPERATION_OK, buf, n);
            }

            return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
        }

        default:
            // Everything not implemented yet lands here, which is also the right
            // answer for a command this generation genuinely does not have.
            if (g_dbglevel >= DBG_EXTENDED) {
                Dbprintf("DESFire sim: unhandled command " _YELLOW_("%02x"), cmd);
            }
            return desfire_sim_status(out, MFDES_E_ILLEGAL_COMMAND_CODE);
    }
}

//---------------------------------------------------------------- entry points

static bool desfire_sim_init(void) {

    // Always re-parse rather than cache across calls: an eload between two
    // simulations replaces the image in place, and a stale parse would serve
    // the previous card. It is only pointer setup, so calling it twice during
    // activation costs nothing.
    s_ready = false;
    memset(&s_st, 0, sizeof(s_st));

    if (desfire_sim_load(&s_st) == false) {
        return false;
    }

    s_ready = true;
    return true;
}

static void desfire_sim_identity(uint8_t *uid, uint8_t *uidlen, uint8_t *atqa, uint8_t *sak, uint8_t *ats, uint8_t *atslen) {

    if (s_ready == false) {
        return;
    }

    const desfire_em_hdr_t *hdr = s_st.hdr;

    if (uid && hdr->uidlen <= sizeof(hdr->uid)) {
        memcpy(uid, hdr->uid, hdr->uidlen);
    }

    if (uidlen) {
        *uidlen = hdr->uidlen;
    }

    if (atqa) {
        atqa[0] = hdr->atqa[0];
        atqa[1] = hdr->atqa[1];
    }

    if (sak) {
        *sak = hdr->sak;
    }

    if (ats && atslen) {

        // The image keeps the whole ATS frame the card sent, CRC included,
        // because that is what round-trips through the dump file. The 14a layer
        // appends its own CRC and checks the length against TL, so hand it the
        // ATS proper.
        uint8_t n = hdr->atslen;
        if (n > 2 && hdr->ats[0] == n - 2) {
            n -= 2;
        }

        if (n > sizeof(hdr->ats)) {
            n = sizeof(hdr->ats);
        }

        memcpy(ats, hdr->ats, n);
        *atslen = n;
    }
}

static void desfire_sim_reset(void) {

    if (s_ready == false) {
        return;
    }

    s_st.selected = 0;          // a PICC comes up with AID 000000 selected
    s_st.chain_cmd = 0;
    s_st.chain_step = 0;
}

static uint16_t desfire_sim_apdu(const uint8_t *in, uint16_t inlen, uint8_t *out) {

    if (s_ready == false || inlen < 1) {
        return 0;
    }

    // Two framings carry the same commands and a reader may use either.
    //
    //   native        <cmd> <data...>              ->  <status> <data...>
    //   ISO 7816      90 <cmd> 00 00 Lc <data> Le  ->  <data...> 91 <status>
    //
    // The proxmark client defaults to the wrapped form, so a simulation that
    // only understands the native one answers ILLEGAL_COMMAND_CODE to
    // everything -- it reads the 0x90 class byte as the command.
    if (in[0] == DESFIRE_SIM_ISO7816_CLA && inlen >= 5) {

        uint8_t cmd = in[1];

        // 5 bytes is CLA INS P1 P2 Le, no data. Longer means in[4] is Lc and
        // the data follows, with Le after it.
        uint8_t lc = 0;
        const uint8_t *data = NULL;
        if (inlen > 5) {
            lc = in[4];
            data = in + 5;
            if ((uint16_t)5 + lc > inlen) {
                lc = inlen - 5;         // truncated frame, use what arrived
            }
        }

        uint8_t native[DESFIRE_SIM_MAX_RESP] = {0};
        uint16_t n = desfire_sim_command(&s_st, cmd, data, lc, native);
        if (n == 0) {
            return 0;
        }

        // status leads in the native answer and trails in the wrapped one
        if (n > 1) {
            memcpy(out, native + 1, n - 1);
        }
        out[n - 1] = DESFIRE_SIM_ISO7816_SW1;
        out[n] = native[0];
        return n + 1;
    }

    return desfire_sim_command(&s_st, in[0], in + 1, inlen - 1, out);
}

static void desfire_sim_print_banner(void) {

    if (s_ready == false) {
        return;
    }

    const desfire_em_hdr_t *hdr = s_st.hdr;

    Dbprintf("Simulating DESFire, %u application(s), " _YELLOW_("%u") " bytes free"
             , hdr->appcount - 1
             , (hdr->cardsize > hdr->reserved) ? (hdr->cardsize - hdr->reserved) : 0
            );

    // The image carries whatever generation the card it came from was, and the
    // version bytes we present say so. Only the EV1 command set is implemented,
    // so a reader that follows those version bytes into an EV2 or EV3 command
    // gets ILLEGAL_COMMAND_CODE. Say so rather than let it look like a bug.
    if (hdr->generation != DESFIRE_EM_GEN_EV1 && hdr->generation != DESFIRE_EM_GEN_D40) {
        Dbprintf(_YELLOW_("Only the EV1 command set is implemented"));
        Dbprintf(_YELLOW_("A reader using a later command will get ILLEGAL_COMMAND_CODE 0x1C"));
    }
}

//-------------------------------------------------------- the simulation loop

// ISO/IEC 14443-4 block prologue. The low bit of an I-block PCB is the block
// number and has to be echoed back, or the reader reads our answer as a
// retransmission and stalls.
#define PCB_TYPE_MASK           0xC0
#define PCB_TYPE_I              0x00
#define PCB_TYPE_R              0x80
#define PCB_TYPE_S              0xC0
#define PCB_I_CHAINING          0x10
#define PCB_BLOCKNUM            0x01
#define PCB_CID_FOLLOWS         0x08
#define PCB_NAD_FOLLOWS         0x04
#define PCB_S_DESELECT          0xC2

// enough for a 2 byte ATQA: 9 bytes of modulation per byte, plus framing
#define ATQA_MODULATION_BUFFER_SIZE  32

void SimulateDesfireTag(void) {

    //-------------------------------------------------------------------------
    // Get the bitstream in place before anything is allocated. iso14443a_setup()
    // below would otherwise do it, and a bitstream download frees and clears
    // BigBuf to get scratch space for the decompressor -- taking the emulator
    // memory holding our card image and the precompiled anticollision answers
    // with it. The pointers survive, the bytes behind them do not, and the tag
    // then clocks out zeros.
    //-------------------------------------------------------------------------
    FpgaDownloadAndGo_keep_EM(FPGA_BITSTREAM_HF);

    // keep emulator memory, that is where eload put the card image
    BigBuf_free_keep_EM();

    if (desfire_sim_init() == false) {
        Dbprintf("No DESFire card image in emulator memory");
        Dbprintf("Load one with " _YELLOW_("`hf mfdes eload -f <fn>`"));
        reply_ng(CMD_HF_DESFIRE_SIMULATE, PM3_EINVARG, NULL, 0);
        return;
    }

    uint8_t uid[10] = {0};
    uint8_t uidlen = 0;
    uint8_t atqa[2] = {0};
    uint8_t sak = 0;
    uint8_t ats[20] = {0};
    uint8_t atslen = 0;
    desfire_sim_identity(uid, &uidlen, atqa, &sak, ats, &atslen);

    uint16_t flags = FLAG_ATS_IN_DATA;
    switch (uidlen) {
        case 7:
            flags |= FLAG_7B_UID_IN_DATA;
            break;
        case 10:
            flags |= FLAG_10B_UID_IN_DATA;
            break;
        default:
            Dbprintf("Card image has a %u byte UID, cannot simulate that", uidlen);
            reply_ng(CMD_HF_DESFIRE_SIMULATE, PM3_EINVARG, NULL, 0);
            return;
    }

    tag_response_info_t *responses = NULL;
    uint32_t cuid = 0;
    uint8_t pages = 0;

    // tag type 3 gives the DESFire SAK and a DESFire shaped ATS; the ATS from
    // the image replaces it because FLAG_ATS_IN_DATA is set
    if (SimulateIso14443aInit(3, flags, uid, ats, atslen, &responses, &cuid, &pages, NULL) == false) {
        BigBuf_free_keep_EM();
        reply_ng(CMD_HF_DESFIRE_SIMULATE, PM3_EINIT, NULL, 0);
        return;
    }

    // SimulateIso14443aInit() derives the ATQA from the tag type, so a 7 byte
    // UID comes out 44 03 -- which is right for DESFire, but the image may say
    // otherwise. Rebuild that one precompiled answer when it differs.
    if ((atqa[0] || atqa[1]) &&
            (responses[RESP_INDEX_ATQA].response[0] != atqa[0] ||
             responses[RESP_INDEX_ATQA].response[1] != atqa[1])) {

        uint8_t *atqa_buf = BigBuf_calloc(ATQA_MODULATION_BUFFER_SIZE);
        if (atqa_buf != NULL) {

            uint8_t *p = atqa_buf;
            size_t avail = ATQA_MODULATION_BUFFER_SIZE;

            tag_response_info_t atqa_resp = {
                .response = atqa,
                .response_n = sizeof(atqa)
            };

            if (prepare_allocated_tag_modulation(&atqa_resp, &p, &avail)) {
                responses[RESP_INDEX_ATQA] = atqa_resp;
            } else {
                Dbprintf(_RED_("Could not build the ATQA answer, using the default"));
            }
        }
    }

    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    uint8_t receivedCmd[MAX_FRAME_SIZE] = {0};
    uint8_t receivedCmdPar[MAX_PARITY_SIZE] = {0};
    uint8_t answer[DESFIRE_SIM_MAX_RESP + 8] = {0};

    clear_trace();
    set_tracing(true);
    LED_A_ON();

    desfire_sim_print_banner();

    int retval = PM3_SUCCESS;
    uint32_t cmdcount = 0;

    for (;;) {

        WDT_HIT();

        int len = 0;
        if (GetIso14443aCommandFromReader(receivedCmd, sizeof(receivedCmd), receivedCmdPar, &len) == false) {
            Dbprintf("Emulator stopped. Trace length: %d", BigBuf_get_traceLen());
            retval = PM3_EOPABORTED;
            break;
        }

        if (len <= 0) {
            continue;
        }

        cmdcount++;

        tag_response_info_t *p_response = NULL;

        // ---- activation, all precompiled ----
        if (receivedCmd[0] == ISO14443A_CMD_WUPA || receivedCmd[0] == ISO14443A_CMD_REQA) {
            desfire_sim_reset();            // a fresh activation reselects the PICC
            p_response = &responses[RESP_INDEX_ATQA];

        } else if (len == 2 && receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT) {
            p_response = &responses[RESP_INDEX_UIDC1];
        } else if (len == 2 && receivedCmd[1] == 0x20 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2) {
            p_response = &responses[RESP_INDEX_UIDC2];
        } else if (len == 9 && receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT) {
            p_response = &responses[RESP_INDEX_SAKC1];
        } else if (len == 9 && receivedCmd[1] == 0x70 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2) {
            p_response = &responses[RESP_INDEX_SAKC2];
        } else if (receivedCmd[0] == ISO14443A_CMD_RATS && len == 4) {
            p_response = &responses[RESP_INDEX_ATS];
        } else if (receivedCmd[0] == ISO14443A_CMD_PPS) {
            p_response = &responses[RESP_INDEX_PPS];
        } else if (receivedCmd[0] == ISO14443A_CMD_HALT && len == 4) {
            desfire_sim_reset();
            continue;                       // a halted tag says nothing

        // ---- ISO/IEC 14443-4 ----
        } else if ((receivedCmd[0] & PCB_TYPE_MASK) == PCB_TYPE_S) {

            if (receivedCmd[0] == PCB_S_DESELECT) {
                uint8_t r[3] = { PCB_S_DESELECT, 0, 0 };
                AddCrc14A(r, 1);
                EmSendCmd(r, sizeof(r));
                desfire_sim_reset();
            }
            continue;

        } else if ((receivedCmd[0] & PCB_TYPE_MASK) == PCB_TYPE_R) {

            // R(ACK) is a retransmission request. We do not keep the previous
            // answer, so acknowledge and move on.
            uint8_t r[3] = { (uint8_t)(0xA2 | (receivedCmd[0] & PCB_BLOCKNUM)), 0, 0 };
            AddCrc14A(r, 1);
            EmSendCmd(r, sizeof(r));
            continue;

        } else if ((receivedCmd[0] & PCB_TYPE_MASK) == PCB_TYPE_I) {

            uint8_t prologue = 1;
            if (receivedCmd[0] & PCB_CID_FOLLOWS) {
                prologue++;
            }
            if (receivedCmd[0] & PCB_NAD_FOLLOWS) {
                prologue++;
            }

            // prologue + at least a command byte + CRC
            if (len < prologue + 1 + 2) {
                continue;
            }

            uint16_t n = desfire_sim_apdu(receivedCmd + prologue, len - prologue - 2, answer + prologue);
            if (n == 0) {
                continue;
            }

            // echo the prologue back, block number included
            memcpy(answer, receivedCmd, prologue);
            answer[0] &= ~PCB_I_CHAINING;

            AddCrc14A(answer, prologue + n);
            EmSendCmd(answer, prologue + n + 2);
            continue;

        } else {
            if (g_dbglevel >= DBG_EXTENDED) {
                Dbprintf("DESFire sim: unknown frame, %d bytes", len);
                Dbhexdump(len, receivedCmd, false);
            }
            continue;
        }

        EmSendPrecompiledCmd(p_response);
    }

    switch_off();
    set_tracing(false);
    BigBuf_free_keep_EM();

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("-[ commands received %u ]-", cmdcount);
    }

    reply_ng(CMD_HF_DESFIRE_SIMULATE, retval, NULL, 0);
}
