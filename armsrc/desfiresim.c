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
#include "crc32.h"
#include "crc.h"
#include "commonutil.h"
#include "fpga_apis.h"
#include "fpga_loader.h"
#include "rssi_apis.h"
#include "ticks_apis.h"
#include "protocols.h"
#include "desfire_em.h"
#include "desfire_crypto.h"

#define DESFIRE_CRC32_POLY  0xEDB88320

// ISO 7816 wrapping of the DESFire command set: class byte on the way in,
// first status byte on the way back.
#define DESFIRE_SIM_ISO7816_CLA 0x90
#define DESFIRE_SIM_ISO7816_SW1 0x91

// Largest answer built before the 14443-4 prologue and CRC are added.
// GetApplicationIDs on a full PICC is 28 * 3 bytes plus a status byte.
#define DESFIRE_SIM_MAX_RESP    128

// Largest write gathered across chained frames, header and secure messaging
// included.  A reader that asks to write more than this in one command is
// refused rather than served a truncated write.
#define DESFIRE_SIM_WRITE_MAX   272

// A reader chaining a long write fills its frames; a frame shorter than this
// is the last one.  The client splits native writes well below it.
#define DESFIRE_SIM_WRITE_FRAME 52

typedef struct {
    const desfire_em_hdr_t *hdr;
    const desfire_em_app_t *apps;
    const desfire_em_file_t *files;
    const desfire_em_key_t *keys;
    const uint8_t *base;

    int selected;               // index into apps[], -1 when nothing is selected
    uint8_t chain_cmd;          // command being continued over 0xAF, 0 when none
    uint8_t chain_step;         // which frame of it comes next

    // ---- a read being handed out over several frames
    // GetVersion and GetDFNames step through fixed records and only need
    // chain_step.  A file read has to remember where in the file it is, which
    // file, and the mode the first frame settled on -- the access rights are
    // evaluated once, when the command arrives, not again per frame.
    int16_t chain_file;         // index into files[], -1 when none
    uint32_t chain_base;        // where the read starts inside the file
    uint32_t chain_datalen;     // how many bytes of it the reader asked for
    uint32_t chain_off;         // position in the stream being handed out
    uint32_t chain_end;         // its total length
    uint8_t chain_comm;         // effective comm mode for the whole transfer
    uint8_t chain_crc[4];       // CRC32 of an enciphered read, computed up front

    // ---- authentication
    // auth_cmd is the handshake in flight, 0 when none.  The second frame
    // arrives as 0xAF, so the command has to be remembered across it.
    uint8_t auth_cmd;
    uint8_t auth_keynum;
    uint8_t rndb[16];
    uint8_t rndlen;
    uint8_t iv[16];             // runs through the handshake, then the session
    struct desfire_key authkey;

    bool authenticated;
    uint8_t auth_keyno;         // the key number we authenticated with
    struct desfire_key sesskey;

    // The session CMAC is taken a piece at a time, so up to one block of the
    // message is held back between calls -- see desfire_sim_cmac_update().
    uint8_t cmac_pend[DESFIRE_MAX_CRYPTO_BLOCK_SIZE];
    uint8_t cmac_pendlen;

    // ---- a write being gathered over several frames
    // A write is secured as one message, so none of it can be acted on until
    // the last frame is in: the MAC covers the whole thing, and an enciphered
    // write carries one CRC32 at the end of the lot.
    uint8_t wbuf[DESFIRE_SIM_WRITE_MAX];
    uint16_t wlen;
    uint8_t wcmd;               // the command being gathered, 0 when none
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
    st->keys = (const desfire_em_key_t *)(em + hdr->key_off);
    st->selected = 0;           // a PICC comes up with AID 000000 selected
    st->chain_cmd = 0;
    st->chain_step = 0;
    st->chain_file = -1;
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

// ------------------------------------------------------------ authentication

// Fixed tag nonce, the same approach the UL-C simulation takes. It makes a
// session reproducible, which is useful for testing, and means the simulation
// is replayable -- it is a simulation of a card, not a secure one.
static const uint8_t s_sim_rndb[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

// rotate left by one byte, the RndA/RndB' transform of the handshake
static void desfire_sim_rol(uint8_t *data, uint8_t len) {
    if (len < 2) {
        return;
    }
    uint8_t first = data[0];
    memmove(data, data + 1, len - 1);
    data[len - 1] = first;
}

// The key material for (application, key number), or NULL when the image does
// not hold it. A key we only know the version of cannot authenticate: the
// image format keeps DESFIRE_EM_KEY_PRESENT apart from DESFIRE_EM_KEY_VERKNOWN
// exactly so a simulation refuses rather than authenticating with zeros.
static const desfire_em_key_t *desfire_sim_find_key(const desfire_sim_state_t *st, uint8_t app, uint8_t keyno) {

    for (uint16_t i = 0; i < st->hdr->keycount; i++) {
        const desfire_em_key_t *k = &st->keys[i];
        if (k->app == app && k->num == keyno) {
            return (k->flags & DESFIRE_EM_KEY_PRESENT) ? k : NULL;
        }
    }
    return NULL;
}

// Build a crypto key of the application's algorithm from stored key material.
//
// DES and 2K3DES keys are both stored as 16 bytes and the key itself decides
// which one the PICC uses: "If the 2nd half of the key string is equal to the
// 1st half, the key is handled as a single DES key by the PICC" (M134034 8.1).
// The all zero default key is the common case of that.  It matters well beyond
// the cipher, because the same rule governs session key generation -- so a card
// that skips it authenticates fine, then MACs every later frame with a key the
// reader does not have.  The comparison is over the stored bytes including the
// version bits, which is why it is done here rather than after any constructor
// that clears them.
static void desfire_sim_make_key(struct desfire_key *out, uint8_t algo, const uint8_t *value) {

    memset(out, 0, sizeof(*out));
    switch (algo) {
        case T_DES:
            Desfire_des_key_new(value, out);
            break;
        case T_3DES:
            if (memcmp(value, value + 8, 8) == 0) {
                Desfire_des_key_new(value, out);
            } else {
                Desfire_3des_key_new(value, out);
            }
            break;
        case T_3K3DES:
            Desfire_3k3des_key_new(value, out);
            break;
        case T_AES:
        default:
            Desfire_aes_key_new(value, out);
            break;
    }
}

// Derive the session key from the two nonces.
//
// This does not call the tree's Desfire_session_key_new(): its 3K3DES branch
// passes the result through Desfire_3k3des_key_new(), which clears the low bit
// of the first eight bytes.  In a stored key those bits carry the key version,
// but a session key has no version and the reader keeps the derived bytes as
// they are -- clearing them here would leave the two sides MACing under
// different keys.  The layouts themselves are M134034 7.3.8.
static void desfire_sim_session_key(desfire_sim_state_t *st, const uint8_t *rnda, const uint8_t *rndb) {

    uint8_t buf[24] = {0};

    switch (st->authkey.type) {

        case T_DES:
            memcpy(buf, rnda, 4);
            memcpy(buf + 4, rndb, 4);
            Desfire_des_key_new_with_version(buf, &st->sesskey);
            break;

        case T_3DES:
            memcpy(buf, rnda, 4);
            memcpy(buf + 4, rndb, 4);
            memcpy(buf + 8, rnda + 4, 4);
            memcpy(buf + 12, rndb + 4, 4);
            Desfire_3des_key_new_with_version(buf, &st->sesskey);
            break;

        case T_3K3DES:
            memcpy(buf, rnda, 4);
            memcpy(buf + 4, rndb, 4);
            memcpy(buf + 8, rnda + 6, 4);
            memcpy(buf + 12, rndb + 6, 4);
            memcpy(buf + 16, rnda + 12, 4);
            memcpy(buf + 20, rndb + 12, 4);
            Desfire_3k3des_key_new_with_version(buf, &st->sesskey);
            break;

        case T_AES:
        default:
            memcpy(buf, rnda, 4);
            memcpy(buf + 4, rndb, 4);
            memcpy(buf + 8, rnda + 12, 4);
            memcpy(buf + 12, rndb + 12, 4);
            Desfire_aes_key_new(buf, &st->sesskey);
            break;
    }
}

// One CBC block chain in either direction, picking the cipher from the key.
static void desfire_sim_crypt(struct desfire_key *key, const uint8_t *in, uint8_t *out,
                              uint16_t len, uint8_t *iv, bool encrypt) {

    if (key->type == T_AES) {
        if (encrypt) {
            aes128_nxp_send(in, out, len, key->data, iv);
        } else {
            aes128_nxp_receive(in, out, len, key->data, iv);
        }
        return;
    }

    // 2 key or 3 key triple DES; a single DES key is stored doubled
    int keymode = (key->type == T_3K3DES) ? 3 : 2;
    if (encrypt) {
        tdes_nxp_send(in, out, len, key->data, iv, keymode);
    } else {
        tdes_nxp_receive(in, out, len, key->data, iv, keymode);
    }
}

// How long the challenge is for a given algorithm.
static uint8_t desfire_sim_rndlen(uint8_t algo) {
    return (algo == T_AES || algo == T_3K3DES) ? 16 : 8;
}

// Drop any authenticated session. SelectApplication does this, and so does any
// command the PICC answers with an error.
static void desfire_sim_auth_clear(desfire_sim_state_t *st) {
    st->auth_cmd = 0;
    st->authenticated = false;
    st->auth_keyno = 0;
    st->cmac_pendlen = 0;
    memset(st->cmac_pend, 0, sizeof(st->cmac_pend));
    memset(st->iv, 0, sizeof(st->iv));
    memset(&st->sesskey, 0, sizeof(st->sesskey));
    memset(&st->authkey, 0, sizeof(st->authkey));
}

// First frame of the handshake: pick the key, answer with E(RndB).
static uint16_t desfire_sim_auth_start(desfire_sim_state_t *st, uint8_t cmd,
                                       const uint8_t *in, uint16_t inlen, uint8_t *out) {

    if (inlen < 1) {
        return desfire_sim_status(out, MFDES_E_LENGTH);
    }

    uint8_t keyno = in[0] & 0x0F;
    const desfire_em_app_t *app = &st->apps[st->selected];

    if (keyno >= (app->numkeysraw & 0x0F) && keyno != 0) {
        return desfire_sim_status(out, MFDES_E_NO_SUCH_KEY);
    }

    const desfire_em_key_t *k = desfire_sim_find_key(st, st->selected, keyno);
    if (k == NULL) {
        // we do not hold this key, so we cannot play the other half
        if (g_dbglevel >= DBG_EXTENDED) {
            Dbprintf("DESFire sim: no key %u for app index %d in the image", keyno, st->selected);
        }
        return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
    }

    // the command has to match the application's key algorithm
    uint8_t algo = app->keytype;
    bool ok = ((cmd == MFDES_AUTHENTICATE && (algo == T_DES || algo == T_3DES)) ||
               (cmd == MFDES_AUTHENTICATE_ISO && (algo == T_DES || algo == T_3DES || algo == T_3K3DES)) ||
               (cmd == MFDES_AUTHENTICATE_AES && algo == T_AES));
    if (ok == false) {
        return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
    }

    desfire_sim_auth_clear(st);
    desfire_sim_make_key(&st->authkey, algo, k->key);

    st->rndlen = desfire_sim_rndlen(algo);
    memcpy(st->rndb, s_sim_rndb, st->rndlen);

    // tdes_nxp_send() casts away const and XORs the IV into its *input* buffer,
    // so anything handed to it is destroyed. With a zero IV and a single block
    // that is a no-op, which is why 2TDEA survives it, but a 16 byte challenge
    // is two blocks and the second one corrupts the stored RndB. Encrypt a copy.
    uint8_t plain[16] = {0};
    uint8_t encrndb[16] = {0};
    memcpy(plain, st->rndb, st->rndlen);
    memset(st->iv, 0, sizeof(st->iv));
    desfire_sim_crypt(&st->authkey, plain, encrndb, st->rndlen, st->iv, true);

    st->auth_cmd = cmd;
    st->auth_keynum = keyno;
    return desfire_sim_payload(out, MFDES_ADDITIONAL_FRAME, encrndb, st->rndlen);
}

// Second frame: E(RndA || RndB'). Check RndB', answer E(RndA') and derive the
// session key.
static uint16_t desfire_sim_auth_finish(desfire_sim_state_t *st, const uint8_t *in, uint16_t inlen, uint8_t *out) {

    uint16_t want = st->rndlen * 2;
    if (inlen < want) {
        desfire_sim_auth_clear(st);
        return desfire_sim_status(out, MFDES_E_LENGTH);
    }

    uint8_t both[32] = {0};
    desfire_sim_crypt(&st->authkey, in, both, want, st->iv, false);

    const uint8_t *rnda = both;
    const uint8_t *rndbprime = both + st->rndlen;

    uint8_t expect[16] = {0};
    memcpy(expect, st->rndb, st->rndlen);
    desfire_sim_rol(expect, st->rndlen);

    if (memcmp(expect, rndbprime, st->rndlen) != 0) {
        // the reader does not hold the key
        desfire_sim_auth_clear(st);
        return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
    }

    uint8_t rndaprime[16] = {0};
    memcpy(rndaprime, rnda, st->rndlen);
    desfire_sim_rol(rndaprime, st->rndlen);

    uint8_t encrndaprime[16] = {0};
    desfire_sim_crypt(&st->authkey, rndaprime, encrndaprime, st->rndlen, st->iv, true);

    // session key, and the CMAC subkeys the MACed mode will need
    desfire_sim_session_key(st, rnda, st->rndb);
    cmac_generate_subkeys(&st->sesskey);

    st->authenticated = true;
    st->auth_keyno = st->auth_keynum;
    st->auth_cmd = 0;
    memset(st->iv, 0, sizeof(st->iv));

    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("DESFire sim: authenticated app index %d key %u", st->selected, st->auth_keyno);
    }

    return desfire_sim_payload(out, MFDES_S_OPERATION_OK, encrndaprime, st->rndlen);
}

// ---------------------------------------------------------- secure messaging

// EV1 file communication modes, the raw 2 bit field of the file settings.
#define DESFIRE_SIM_COMM_PLAIN      0x00
#define DESFIRE_SIM_COMM_MACED      0x01
#define DESFIRE_SIM_COMM_PLAIN2     0x02    // a second plain encoding, EV1 9.3.1
#define DESFIRE_SIM_COMM_FULL       0x03

// Access rights are four nibbles in one word: read, write, read-write and
// change, from the top down.  0x0E grants everyone, 0x0F denies everyone, and
// anything else names the key that has to be authenticated.
#define DESFIRE_SIM_AR_READ(r)      (((r) >> 12) & 0x0F)
#define DESFIRE_SIM_AR_WRITE(r)     (((r) >> 8) & 0x0F)
#define DESFIRE_SIM_AR_RW(r)        (((r) >> 4) & 0x0F)
#define DESFIRE_SIM_AR_CHANGE(r)    ((r) & 0x0F)

#define DESFIRE_SIM_AR_FREE         0x0E
#define DESFIRE_SIM_AR_DENY         0x0F

// Does this access right let the current session through?  `keyed` is set when
// it was a key that granted it rather than free access, which the caller needs
// to pick the communication mode -- see desfire_sim_eff_comm().
static bool desfire_sim_right_ok(const desfire_sim_state_t *st, uint8_t right, bool *keyed) {

    if (right == DESFIRE_SIM_AR_DENY) {
        return false;
    }

    if (right == DESFIRE_SIM_AR_FREE) {
        return true;
    }

    if (st->authenticated && st->auth_keyno == right) {
        *keyed = true;
        return true;
    }

    return false;
}

// The mode a file operation actually runs in.
//
// Measured on a DESFire EV2 2K, and the same on the ev1 channel: the PICC
// applies the file's communication mode only when a key right matching the
// authenticated key granted the operation.  When free access (0x0E) granted it
// instead, the transfer is plain whatever the file settings say.  Free access
// alone is not the trigger -- a keyed right that matches wins, so both rights
// have to be evaluated before deciding.
static bool desfire_sim_eff_comm(const desfire_sim_state_t *st, const desfire_em_file_t *f,
                                 bool write, uint8_t *comm) {

    uint16_t r = f->rights;
    bool keyed = false;

    // read and write are each granted by their own right or by read-write
    bool a = desfire_sim_right_ok(st, write ? DESFIRE_SIM_AR_WRITE(r) : DESFIRE_SIM_AR_READ(r), &keyed);
    bool b = desfire_sim_right_ok(st, DESFIRE_SIM_AR_RW(r), &keyed);

    if ((a || b) == false) {
        return false;
    }

    *comm = keyed ? (f->flags & DESFIRE_EM_FILE_COMM_MASK) : DESFIRE_SIM_COMM_PLAIN;
    return true;
}

// GetValue, Debit and LimitedCredit are granted by any of the three rights,
// Credit by read-write alone -- measured, EV1 9.5.6.  The FreeValue option bit
// forces GetValue plain whatever the rights say.
static bool desfire_sim_value_comm(const desfire_sim_state_t *st, const desfire_em_file_t *f,
                                   bool creditonly, uint8_t *comm) {

    uint16_t r = f->rights;
    bool keyed = false;
    bool ok;

    if (creditonly) {
        ok = desfire_sim_right_ok(st, DESFIRE_SIM_AR_RW(r), &keyed);
    } else {
        bool a = desfire_sim_right_ok(st, DESFIRE_SIM_AR_READ(r), &keyed);
        bool b = desfire_sim_right_ok(st, DESFIRE_SIM_AR_WRITE(r), &keyed);
        bool c = desfire_sim_right_ok(st, DESFIRE_SIM_AR_RW(r), &keyed);
        ok = (a || b || c);
    }

    if (ok == false) {
        return false;
    }

    if ((creditonly == false) && (f->flags & DESFIRE_EM_FILE_FREEGETVAL)) {
        *comm = DESFIRE_SIM_COMM_PLAIN;
        return true;
    }

    *comm = keyed ? (f->flags & DESFIRE_EM_FILE_COMM_MASK) : DESFIRE_SIM_COMM_PLAIN;
    return true;
}

// The session CMAC, taken a piece at a time.
//
// Two reasons it streams rather than taking a buffer.  The tree's cmac() draws
// its scratch from BigBuf and never hands it back, which is fine for the
// one-shot reader path it was written for but would drain the buffer a block at
// a time over a session.  And a chained read is MACed over the whole transfer,
// not per frame -- the client joins every frame and verifies once -- so the
// data is only ever seen in pieces and can be several hundred bytes in total.
//
// CMAC is CBC-MAC with the final block treated differently, so a complete block
// is only pushed through the chain once something is known to follow it.  That
// leaves between 1 and one block of data pending at all times.

static void desfire_sim_cmac_reset(desfire_sim_state_t *st) {
    st->cmac_pendlen = 0;
    memset(st->cmac_pend, 0, sizeof(st->cmac_pend));
}

static void desfire_sim_cmac_update(desfire_sim_state_t *st, const uint8_t *data, uint32_t len) {

    size_t kbs = key_block_size(&st->sesskey);
    if (kbs == 0 || kbs > sizeof(st->cmac_pend)) {
        return;
    }

    while (len > 0) {

        // Being here with a full block held means more data follows it, so it
        // is not the last block and can go through the chain now.  Flushing at
        // the top rather than the bottom is what makes a second call safe: the
        // previous one returns with a full block pending whenever the data it
        // was given filled one exactly, and consuming that first is the only
        // way this loop makes progress.
        if (st->cmac_pendlen == kbs) {
            mifare_cypher_blocks_chained(NULL, &st->sesskey, st->iv, st->cmac_pend, kbs, MCD_SEND, MCO_ENCYPHER);
            st->cmac_pendlen = 0;
        }

        uint32_t room = kbs - st->cmac_pendlen;
        uint32_t n = (len < room) ? len : room;

        memcpy(st->cmac_pend + st->cmac_pendlen, data, n);
        st->cmac_pendlen += n;
        data += n;
        len -= n;
    }
}

static void desfire_sim_cmac_final(desfire_sim_state_t *st, uint8_t *mac) {

    size_t kbs = key_block_size(&st->sesskey);
    if (kbs == 0 || kbs > sizeof(st->cmac_pend)) {
        return;
    }

    // a message that is a whole number of blocks takes the first subkey, one
    // that has to be padded takes the second
    if (st->cmac_pendlen == kbs) {
        xor(st->cmac_pend, st->sesskey.cmac_sk1, kbs);
    } else {
        st->cmac_pend[st->cmac_pendlen++] = 0x80;
        while (st->cmac_pendlen < kbs) {
            st->cmac_pend[st->cmac_pendlen++] = 0x00;
        }
        xor(st->cmac_pend, st->sesskey.cmac_sk2, kbs);
    }

    mifare_cypher_blocks_chained(NULL, &st->sesskey, st->iv, st->cmac_pend, kbs, MCD_SEND, MCO_ENCYPHER);
    memcpy(mac, st->iv, kbs);
    desfire_sim_cmac_reset(st);
}

// The session CMAC runs over every command and every response, in order, so it
// has to be taken even when neither side puts it on the wire -- skipping one
// leaves the two IVs apart and every later MAC is wrong.  This is the command
// half: `cmd` followed by its parameters, exactly as they arrived.
static void desfire_sim_cmac_command(desfire_sim_state_t *st, uint8_t cmd, const uint8_t *in, uint16_t inlen) {

    if (st->authenticated == false) {
        return;
    }

    uint8_t mac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    desfire_sim_cmac_reset(st);
    desfire_sim_cmac_update(st, &cmd, 1);
    desfire_sim_cmac_update(st, in, inlen);
    desfire_sim_cmac_final(st, mac);
}

// The response half: the CMAC covers the payload followed by the status byte,
// and its first 8 bytes are appended to the answer.  An EV1 session MACs the
// response even for a plain transfer, which is why this is not conditional on
// the file's communication mode.
static uint16_t desfire_sim_maced(desfire_sim_state_t *st, uint8_t *out, uint8_t status,
                                  const uint8_t *data, uint16_t len) {

    if (st->authenticated == false) {
        return desfire_sim_payload(out, status, data, len);
    }

    uint8_t mac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    desfire_sim_cmac_reset(st);
    desfire_sim_cmac_update(st, data, len);
    desfire_sim_cmac_update(st, &status, 1);
    desfire_sim_cmac_final(st, mac);

    out[0] = status;
    if (len) {
        memcpy(out + 1, data, len);
    }
    memcpy(out + 1 + len, mac, DESFIRE_CMAC_LENGTH);
    return len + 1 + DESFIRE_CMAC_LENGTH;
}

// A fully enciphered response: plaintext, CRC32 over plaintext and the status
// byte, then zero padding to the block size, all encrypted under the session
// key with the running IV.
static uint16_t desfire_sim_enciphered(desfire_sim_state_t *st, uint8_t *out, uint8_t status,
                                       const uint8_t *data, uint16_t len) {

    size_t kbs = key_block_size(&st->sesskey);
    if (kbs == 0) {
        return desfire_sim_payload(out, status, data, len);
    }

    uint8_t buf[DESFIRE_SIM_MAX_RESP] = {0};
    size_t padded = padded_data_length(len + 4, kbs);
    if (padded + 1 > sizeof(buf)) {
        return desfire_sim_status(out, MFDES_E_LENGTH);
    }

    // the CRC is taken over the plaintext with the status byte appended, but
    // only the plaintext and the CRC itself are sent
    uint8_t crcbuf[DESFIRE_SIM_MAX_RESP] = {0};
    if (len) {
        memcpy(crcbuf, data, len);
    }
    crcbuf[len] = status;
    crc32_append(crcbuf, len + 1);

    if (len) {
        memcpy(buf, data, len);
    }
    memcpy(buf + len, crcbuf + len + 1, 4);

    out[0] = status;
    desfire_sim_crypt(&st->sesskey, buf, out + 1, padded, st->iv, true);
    return padded + 1;
}

// One frame of a chained answer.
//
// Intermediate frames carry no MAC.  The client joins every frame of a transfer
// and verifies a single CMAC over the lot, taken against the status byte of the
// last frame, so the data feeds the running CMAC as it goes out and only the
// final frame carries the result.
static uint16_t desfire_sim_chained(desfire_sim_state_t *st, uint8_t *out, bool more,
                                    const uint8_t *data, uint16_t len) {

    if (st->authenticated == false) {
        return desfire_sim_payload(out, more ? MFDES_ADDITIONAL_FRAME : MFDES_S_OPERATION_OK, data, len);
    }

    desfire_sim_cmac_update(st, data, len);

    if (more) {
        return desfire_sim_payload(out, MFDES_ADDITIONAL_FRAME, data, len);
    }

    uint8_t status = MFDES_S_OPERATION_OK;
    uint8_t mac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    desfire_sim_cmac_update(st, &status, 1);
    desfire_sim_cmac_final(st, mac);

    out[0] = status;
    if (len) {
        memcpy(out + 1, data, len);
    }
    memcpy(out + 1 + len, mac, DESFIRE_CMAC_LENGTH);
    return len + 1 + DESFIRE_CMAC_LENGTH;
}

// Wrap one answer in whatever the transfer's communication mode calls for.
static uint16_t desfire_sim_respond(desfire_sim_state_t *st, uint8_t *out, uint8_t status,
                                    const uint8_t *data, uint16_t len, uint8_t comm) {

    if (st->authenticated && comm == DESFIRE_SIM_COMM_FULL) {
        return desfire_sim_enciphered(st, out, status, data, len);
    }

    // plain and MACed are the same on the response side of an EV1 session
    return desfire_sim_maced(st, out, status, data, len);
}

// ------------------------------------------------ the reader's secure messaging

// How many leading bytes of a command's parameters are the header, the part an
// enciphered command leaves in the clear.  Same table the client keeps.
static uint8_t desfire_sim_hdrlen(uint8_t cmd) {

    switch (cmd) {
        case MFDES_WRITE_DATA:
        case MFDES_WRITE_DATA2:
        case MFDES_WRITE_RECORD:
        case MFDES_WRITE_RECORD2:
            return 7;               // file number, 3 byte offset, 3 byte length
        case MFDES_UPDATE_RECORD:
        case MFDES_UPDATE_RECORD2:
            return 10;              // and a 3 byte record number on top
        case MFDES_CREDIT:
        case MFDES_DEBIT:
        case MFDES_LIMITED_CREDIT:
        case MFDES_GET_VALUE:
        case MFDES_CHANGE_FILE_SETTINGS:
        case MFDES_CHANGE_KEY:
        case MFDES_CHANGE_CONFIGURATION:
            return 1;               // file, key or option number only
        default:
            return 0;
    }
}

// Commands the reader puts a MAC on the wire for, when the transfer is MACed.
// Everything else calculates the MAC to move the IV along and sends nothing.
static bool desfire_sim_cmd_macs_request(uint8_t cmd) {

    switch (cmd) {
        case MFDES_WRITE_DATA:
        case MFDES_WRITE_DATA2:
        case MFDES_WRITE_RECORD:
        case MFDES_WRITE_RECORD2:
        case MFDES_UPDATE_RECORD:
        case MFDES_UPDATE_RECORD2:
        case MFDES_CREDIT:
        case MFDES_DEBIT:
        case MFDES_LIMITED_CREDIT:
            return true;
        default:
            return false;
    }
}

// Commands that carry data the reader secured, so they unwrap it themselves
// rather than going through the blanket command CMAC.
static bool desfire_sim_cmd_is_write(uint8_t cmd) {
    return (desfire_sim_cmd_macs_request(cmd));
}

// The writes gather across frames; ChangeFileSettings arrives whole but is
// enciphered, and either way the command's own handler does the unwrapping and
// moves the IV along, so the blanket CMAC has to keep its hands off.
static bool desfire_sim_cmd_unwraps_own(uint8_t cmd) {
    return (desfire_sim_cmd_is_write(cmd) ||
            cmd == MFDES_CHANGE_FILE_SETTINGS ||
            cmd == MFDES_CHANGE_KEY_SETTINGS ||
            cmd == MFDES_CHANGE_CONFIGURATION ||
            cmd == MFDES_CHANGE_KEY);
}

// Take the reader's secure messaging off a gathered command.
//
// `buf`/`len` is the command's parameters as they arrived, header included and
// with whatever the transfer's mode added.  On success the plain parameters are
// left in place and *len is trimmed to them.  The session IV moves on either
// way -- that is the point of calculating a MAC nobody transmits.
static bool desfire_sim_unwrap(desfire_sim_state_t *st, uint8_t cmd, uint8_t comm,
                               uint8_t *buf, uint16_t *len) {

    uint8_t hdrlen = desfire_sim_hdrlen(cmd);

    if (st->authenticated == false) {
        // no session, so nothing was added and nothing can be checked
        return (comm != DESFIRE_SIM_COMM_FULL);
    }

    if (comm == DESFIRE_SIM_COMM_FULL) {

        size_t kbs = key_block_size(&st->sesskey);
        if (kbs == 0 || *len < hdrlen) {
            return false;
        }

        uint16_t enclen = *len - hdrlen;
        if (enclen == 0 || (enclen % kbs) != 0) {
            return false;
        }

        // the header travels in the clear, the rest is one CBC run
        desfire_sim_crypt(&st->sesskey, buf + hdrlen, buf + hdrlen, enclen, st->iv, false);

        // CRC32 covers the command byte, the header and the plain data, and
        // sits directly behind the data with zero padding after it.  The data
        // length is not transmitted, so it is found by trying each candidate.
        for (uint16_t datalen = 0; datalen + 4 <= enclen; datalen++) {

            uint8_t crcbuf[DESFIRE_SIM_WRITE_MAX + 8] = {0};
            uint16_t n = 0;
            crcbuf[n++] = cmd;
            memcpy(crcbuf + n, buf, hdrlen);
            n += hdrlen;
            memcpy(crcbuf + n, buf + hdrlen, datalen);
            n += datalen;

            uint8_t want[4] = {0};
            crc32_ex(crcbuf, n, want);

            if (memcmp(want, buf + hdrlen + datalen, 4) == 0) {
                *len = hdrlen + datalen;
                return true;
            }
        }

        return false;
    }

    if (comm == DESFIRE_SIM_COMM_MACED && desfire_sim_cmd_macs_request(cmd)) {

        if (*len < DESFIRE_CMAC_LENGTH) {
            return false;
        }
        uint16_t plainlen = *len - DESFIRE_CMAC_LENGTH;

        uint8_t mac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
        desfire_sim_cmac_reset(st);
        desfire_sim_cmac_update(st, &cmd, 1);
        desfire_sim_cmac_update(st, buf, plainlen);
        desfire_sim_cmac_final(st, mac);

        if (memcmp(mac, buf + plainlen, DESFIRE_CMAC_LENGTH) != 0) {
            return false;
        }

        *len = plainlen;
        return true;
    }

    // plain inside a session: the MAC is calculated and thrown away, only so
    // the next one starts from the right IV
    uint8_t mac[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    desfire_sim_cmac_reset(st);
    desfire_sim_cmac_update(st, &cmd, 1);
    desfire_sim_cmac_update(st, buf, *len);
    desfire_sim_cmac_final(st, mac);
    return true;
}

// ------------------------------------------------------------------- files


// Find a live file by its file number within the selected application.
static const desfire_em_file_t *desfire_sim_find_file(const desfire_sim_state_t *st, uint8_t fileno) {

    for (uint16_t i = 0; i < st->hdr->filecount; i++) {

        const desfire_em_file_t *f = &st->files[i];
        if (f->app != st->selected || f->num != fileno) {
            continue;
        }
        return (f->flags & DESFIRE_EM_FILE_DELETED) ? NULL : f;
    }
    return NULL;
}

static int16_t desfire_sim_file_index(const desfire_sim_state_t *st, const desfire_em_file_t *f) {
    return (int16_t)(f - st->files);
}

// How much file data one frame carries.  The native answer is a status byte,
// the payload, and up to a CMAC or a block of padding behind it, and the whole
// thing has to fit DESFIRE_SIM_MAX_RESP.
#define DESFIRE_SIM_READ_CHUNK  96

// Hand out the next slice of a file read, chaining with 0xAF while more is
// left.  Shared by the first frame and every continuation.
static uint16_t desfire_sim_read_chunk(desfire_sim_state_t *st, uint8_t *out) {

    const desfire_em_file_t *f = &st->files[st->chain_file];
    const uint8_t *data = st->base + f->dataoff + st->chain_base;

    uint32_t left = st->chain_end - st->chain_off;
    uint32_t n = (left > DESFIRE_SIM_READ_CHUNK) ? DESFIRE_SIM_READ_CHUNK : left;

    uint32_t at = st->chain_off;
    st->chain_off += n;

    bool more = (st->chain_off < st->chain_end);
    if (more == false) {
        st->chain_cmd = 0;
        st->chain_step = 0;
        st->chain_file = -1;
    }

    if (st->chain_comm != DESFIRE_SIM_COMM_FULL) {
        return desfire_sim_chained(st, out, more, data + at, n);
    }

    // An enciphered read is one CBC run over the file data, a CRC32 behind it
    // and zero padding, split across frames with the init vector carried from
    // one to the next -- "if the commands are queued due to a very long data
    // stream, the init vector for the decipherment is always updated" (M134034 7.3.7).
    uint8_t plain[DESFIRE_SIM_READ_CHUNK] = {0};

    for (uint32_t i = 0; i < n; i++) {

        uint32_t p = at + i;

        if (p < st->chain_datalen) {
            plain[i] = data[p];
        } else if (p < st->chain_datalen + 4) {
            plain[i] = st->chain_crc[p - st->chain_datalen];
        } else {
            plain[i] = 0x00;
        }
    }

    out[0] = more ? MFDES_ADDITIONAL_FRAME : MFDES_S_OPERATION_OK;
    desfire_sim_crypt(&st->sesskey, plain, out + 1, n, st->iv, true);
    return n + 1;
}

// Set up a data or record read and answer its first frame.  `unit` is 1 for a
// data file and the record size for a record file, so offset and length are
// counted in whatever the command counts in.
static uint16_t desfire_sim_read_start(desfire_sim_state_t *st, const desfire_em_file_t *f,
                                       uint32_t off, uint32_t len, uint32_t unit,
                                       uint32_t avail, uint8_t comm, uint8_t *out) {

    // A file whose contents were never read holds reserved space and nothing
    // meaningful.  "8 bytes of 00" and "we could not read 8 bytes" are
    // different facts, so this answers an error rather than zeros.
    if (f->flags & DESFIRE_EM_FILE_UNKNOWN) {
        return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
    }

    if (off > avail) {
        return desfire_sim_status(out, MFDES_E_BOUNDARY);
    }

    // zero length means "to the end", EV1 9.5.1
    if (len == 0) {
        len = avail - off;
    }

    if (off + len > avail) {
        return desfire_sim_status(out, MFDES_E_BOUNDARY);
    }

    st->chain_cmd = MFDES_READ_DATA;
    st->chain_file = desfire_sim_file_index(st, f);
    st->chain_base = off * unit;
    st->chain_datalen = len * unit;
    st->chain_off = 0;
    st->chain_comm = comm;

    // the command CMAC has already been taken and its result discarded, so the
    // running state starts empty for the response half
    desfire_sim_cmac_reset(st);

    if (st->chain_base + st->chain_datalen > f->datalen) {
        st->chain_datalen = (f->datalen > st->chain_base) ? (f->datalen - st->chain_base) : 0;
    }

    st->chain_end = st->chain_datalen;

    if (comm == DESFIRE_SIM_COMM_FULL) {

        size_t kbs = key_block_size(&st->sesskey);
        if (kbs == 0) {
            return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
        }

        // The CRC32 covers the data and the status byte the last frame will
        // carry, so it is taken now and fed out with the rest of the stream.
        const uint8_t *data = st->base + f->dataoff + st->chain_base;

        crc_t crc;
        crc_init_ref(&crc, 32, DESFIRE_CRC32_POLY, 0xFFFFFFFF, 0, false, false);

        for (uint32_t i = 0; i < st->chain_datalen; i++) {
            crc_update(&crc, data[i], 8);
        }
        crc_update(&crc, MFDES_S_OPERATION_OK, 8);

        uint32_t v = crc_finish(&crc);
        st->chain_crc[0] = v & 0xFF;
        st->chain_crc[1] = (v >> 8) & 0xFF;
        st->chain_crc[2] = (v >> 16) & 0xFF;
        st->chain_crc[3] = (v >> 24) & 0xFF;

        st->chain_end = padded_data_length(st->chain_datalen + 4, kbs);
    }

    return desfire_sim_read_chunk(st, out);
}

// --------------------------------------------------------------- the writes

// Emulator memory is what the image lives in, and a write changes it in place
// so `hf mfdes esave` afterwards shows what the reader did.  The parsed view is
// const because almost everything only reads it; this is the one way back.
static uint8_t *desfire_sim_wbase(void) {
    return BigBuf_get_EM_addr();
}

// Where a file's writes land.  Standard data files write straight through.
// Backup data, value and record files are covered by CommitTransaction, so
// writes go to the shadow region and only move across on commit -- EV1 9.5.
static uint16_t desfire_sim_write_region(const desfire_em_file_t *f) {
    if (f->type == 0x00 || f->shadow_off == 0) {
        return f->dataoff;
    }
    return f->shadow_off;
}

static bool desfire_sim_file_is_backed(const desfire_em_file_t *f) {
    return (f->type != 0x00 && f->shadow_off != 0);
}

// Start a transaction on a file the first time it is written, so that an abort
// has something to discard and a commit something to move.
static void desfire_sim_mark_dirty(desfire_sim_state_t *st, const desfire_em_file_t *f) {

    if (desfire_sim_file_is_backed(f) == false || (f->flags & DESFIRE_EM_FILE_DIRTY)) {
        return;
    }

    desfire_em_file_t *w = (desfire_em_file_t *)f;
    uint8_t *base = desfire_sim_wbase();

    // the shadow starts as a copy, so a partial write leaves the rest of the
    // file as it was rather than as zeros
    memcpy(base + f->shadow_off, base + f->dataoff, f->datalen);
    w->flags |= DESFIRE_EM_FILE_DIRTY;
}

// CommitTransaction: every dirty file's shadow becomes the committed data.
static void desfire_sim_commit(desfire_sim_state_t *st) {

    uint8_t *base = desfire_sim_wbase();

    for (uint16_t i = 0; i < st->hdr->filecount; i++) {

        desfire_em_file_t *f = (desfire_em_file_t *)&st->files[i];
        if (f->app != st->selected || (f->flags & DESFIRE_EM_FILE_DIRTY) == 0) {
            continue;
        }

        memcpy(base + f->dataoff, base + f->shadow_off, f->datalen);
        f->flags &= ~DESFIRE_EM_FILE_DIRTY;
    }
}

// AbortTransaction: the shadows are dropped and nothing moves.
static void desfire_sim_abort(desfire_sim_state_t *st) {

    for (uint16_t i = 0; i < st->hdr->filecount; i++) {
        desfire_em_file_t *f = (desfire_em_file_t *)&st->files[i];
        if (f->app == st->selected) {
            f->flags &= ~DESFIRE_EM_FILE_DIRTY;
        }
    }
}

// The value a value file currently holds, taking an uncommitted change into
// account -- a Debit followed by GetValue in the same transaction reads back
// the new value, EV1 9.5.6.
static uint32_t desfire_sim_value_get(const desfire_sim_state_t *st, const desfire_em_file_t *f) {
    return f->u.value.value;
}

static void desfire_sim_value_set(desfire_sim_state_t *st, const desfire_em_file_t *f, uint32_t v) {
    desfire_em_file_t *w = (desfire_em_file_t *)f;
    desfire_sim_mark_dirty(st, f);
    w->u.value.value = v;
}

// One GetDFNames record: AID, ISO file id, DF name.  Applications without a DF
// name are not sent back at all (M134034 9.4.4), so this walks past them.
//
// Returns the length written, or 0 when there are no more records.  `next` is
// the application index to resume from, `more` says whether another follows.
static uint16_t desfire_sim_dfname_record(const desfire_sim_state_t *st, uint8_t from,
                                          uint8_t *buf, uint8_t *next, bool *more) {

    const desfire_em_hdr_t *hdr = st->hdr;
    *more = false;

    for (uint8_t i = from; i < hdr->appcount; i++) {

        const desfire_em_app_t *a = &st->apps[i];
        if ((a->flags & DESFIRE_EM_APP_DELETED) || a->dfnamelen == 0) {
            continue;
        }

        uint8_t dfnamelen = a->dfnamelen;
        if (dfnamelen > sizeof(a->dfname)) {
            dfnamelen = sizeof(a->dfname);
        }

        memcpy(buf, a->aid, 3);
        uint16_t n = 3;
        buf[n++] = a->isofid & 0xFF;
        buf[n++] = (a->isofid >> 8) & 0xFF;
        memcpy(buf + n, a->dfname, dfnamelen);
        n += dfnamelen;

        for (uint8_t j = i + 1; j < hdr->appcount; j++) {
            if ((st->apps[j].flags & DESFIRE_EM_APP_DELETED) == 0 && st->apps[j].dfnamelen) {
                *more = true;
                break;
            }
        }

        *next = i + 1;
        return n;
    }

    *next = hdr->appcount;
    return 0;
}

// ----------------------------------------------------------------- key change

// Key length for an algorithm.  A single DES key is carried and stored as its
// 16 byte doubled form, which is how the reader sends it too.
static uint8_t desfire_sim_keylen(uint8_t algo) {
    return (algo == T_3K3DES) ? 24 : 16;
}

// For everything but AES the key version lives in the low bit of each of the
// first eight key bytes -- the DES parity bits, which the cipher ignores.
static uint8_t desfire_sim_key_version(uint8_t algo, const uint8_t *key, uint8_t sent) {

    if (algo == T_AES) {
        return sent;            // AES carries the version as its own byte
    }

    uint8_t ver = 0;
    for (uint8_t i = 0; i < 8; i++) {
        ver |= (key[i] & 1) << (7 - i);
    }
    return ver;
}

// Find a key entry to write to, whether or not we hold its current value.
static desfire_em_key_t *desfire_sim_key_slot(desfire_sim_state_t *st, uint8_t app, uint8_t keyno) {

    for (uint16_t i = 0; i < st->hdr->keycount; i++) {
        if (st->keys[i].app == app && st->keys[i].num == keyno) {
            return (desfire_em_key_t *)&st->keys[i];
        }
    }
    return NULL;
}

// ------------------------------------------------------------ file creation

// Bytes the committed region of a file occupies, before any shadow.  The same
// accounting eload uses, so an image a reader has added files to still agrees
// with itself.
static uint32_t desfire_sim_file_extent(uint8_t type, uint32_t size,
                                        uint32_t recsize, uint32_t maxrec) {

    switch (type) {
        case 0x00:
        case 0x01:
            return size;
        case 0x02:
            // the payload is a 4 byte value, but it is allocated and shadowed
            // like anything else, so it gets a whole granule
            return DESFIRE_EM_GRANULE;
        case 0x03:
        case 0x04:
            // the declared extent, not the records that happen to exist, so
            // WriteRecord never has to grow anything
            return recsize * maxrec;
        default:
            return 0;
    }
}

// CommitTransaction covers everything but a standard data file, and what it
// covers needs a shadow region to write into -- EV1 9.6.10.
static bool desfire_sim_type_has_shadow(uint8_t type) {
    return (type == 0x01 || type == 0x02 || type == 0x03 || type == 0x04);
}

// Add a file to the selected application.
//
// The file table sits between the application table and the key table, so a new
// entry goes in where the key table starts and the keys move up by one entry.
// The file's data is taken off the other end, from the region growing down.
//
// Returns a DESFire status byte.
static uint8_t desfire_sim_file_create(desfire_sim_state_t *st, uint8_t fileno, uint8_t type,
                                       uint8_t comm, uint16_t rights, uint16_t isofid,
                                       uint32_t size, uint32_t recsize, uint32_t maxrec,
                                       uint32_t lower, uint32_t upper, uint32_t value,
                                       uint8_t options) {

    uint8_t *base = desfire_sim_wbase();
    desfire_em_hdr_t *hdr = (desfire_em_hdr_t *)base;

    if (st->selected == 0) {
        return MFDES_E_PERMISSION_DENIED;
    }

    if (fileno > 0x1F) {
        return MFDES_E_PARAMETER_ERROR;
    }

    if (hdr->filecount >= DESFIRE_EM_MAX_FILES) {
        return MFDES_E_OUT_OF_EEPROM;
    }

    if (desfire_sim_find_file(st, fileno) != NULL) {
        return MFDES_E_DUPLICATE;
    }

    uint32_t extent = DESFIRE_EM_ROUNDUP(desfire_sim_file_extent(type, size, recsize, maxrec));
    if (extent == 0) {
        return MFDES_E_PARAMETER_ERROR;
    }

    uint32_t reserve = desfire_sim_type_has_shadow(type) ? (extent * 2) : extent;

    if ((uint32_t)hdr->reserved + reserve > hdr->cardsize) {
        return MFDES_E_OUT_OF_EEPROM;
    }

    // the tables grow up and the file data grows down, and an allocation only
    // has to leave the two apart -- here both move at once
    uint32_t grow = sizeof(desfire_em_file_t);
    if ((uint32_t)hdr->tables_end + grow + reserve > hdr->data_start) {
        return MFDES_E_OUT_OF_EEPROM;
    }

    // open a gap where the key table starts
    uint16_t at = hdr->key_off;
    memmove(base + at + grow, base + at, hdr->tables_end - at);

    desfire_em_file_t *f = (desfire_em_file_t *)(base + at);
    memset(f, 0, sizeof(*f));
    f->app = st->selected;
    f->num = fileno;
    f->type = type;
    f->flags = comm & DESFIRE_EM_FILE_COMM_MASK;
    f->rights = rights;
    f->isofid = isofid;

    hdr->key_off += grow;
    hdr->tables_end += grow;

    // and take the data off the far end
    hdr->data_start -= reserve;
    hdr->reserved += reserve;

    f->dataoff = hdr->data_start;
    f->datalen = extent;
    f->shadow_off = desfire_sim_type_has_shadow(type) ? (hdr->data_start + extent) : 0;

    // a new file reads back as zeros, which is a fact about it rather than a
    // gap in the dump, so it is not marked unknown
    memset(base + hdr->data_start, 0, reserve);

    switch (type) {
        case 0x00:
        case 0x01:
            f->u.data.size = size;
            break;
        case 0x02:
            f->u.value.lower = lower;
            f->u.value.upper = upper;
            f->u.value.value = value;
            if (options & 0x01) {
                f->flags |= DESFIRE_EM_FILE_LIMCREDIT;
            }
            if (options & 0x02) {
                f->flags |= DESFIRE_EM_FILE_FREEGETVAL;
            }
            break;
        case 0x03:
        case 0x04:
            f->u.record.recordsize = recsize;
            f->u.record.maxrecords = maxrec;
            f->u.record.currecords = 0;
            break;
        default:
            break;
    }

    hdr->filecount++;

    // the key table moved, so the parsed view has to be taken again
    int selected = st->selected;
    desfire_sim_load(st);
    st->selected = selected;
    return MFDES_S_OPERATION_OK;
}

// ------------------------------------------------------- applications

// Room the card charges for an application: the application itself plus its
// keys, rounded to a granule.  The same accounting eload uses, so an image the
// reader has added to still agrees with itself.
static uint16_t desfire_sim_app_cost(uint8_t numkeys, uint8_t keytype) {

    uint8_t keylen;
    switch (keytype) {
        case T_3K3DES:
            keylen = 24;
            break;
        case T_DES:
        case T_3DES:
        case T_AES:
        default:
            keylen = 16;
            break;
    }

    return DESFIRE_EM_ROUNDUP(DESFIRE_EM_APP_OVERHEAD + (numkeys * keylen));
}

// Add an application to the image.
//
// The tables sit head to tail -- applications, then files, then keys -- so a new
// application entry goes in at the end of the application table, which is where
// the file table currently starts, and everything above it moves up by one
// entry.  The new application's keys then go on the end of the key table.
//
// Returns a DESFire status byte.
static uint8_t desfire_sim_app_create(desfire_sim_state_t *st, uint32_t aid, uint8_t keysettings,
                                      uint8_t numkeysraw, uint16_t isofid,
                                      const uint8_t *dfname, uint8_t dfnamelen) {

    uint8_t *base = desfire_sim_wbase();
    desfire_em_hdr_t *hdr = (desfire_em_hdr_t *)base;

    if (hdr->appcount >= DESFIRE_EM_MAX_APPS) {
        return MFDES_E_OUT_OF_EEPROM;
    }

    uint8_t numkeys = numkeysraw & 0x0F;
    if (numkeys > DESFIRE_EM_MAX_KEYS) {
        return MFDES_E_PARAMETER_ERROR;
    }

    // bits 6-7 of the key settings pick the cipher for the whole application
    uint8_t keytype;
    switch ((numkeysraw >> 6) & 0x03) {
        case 0x01:
            keytype = T_3K3DES;
            break;
        case 0x02:
            keytype = T_AES;
            break;
        case 0x00:
            keytype = T_3DES;
            break;
        default:
            return MFDES_E_PARAMETER_ERROR;
    }

    uint16_t cost = desfire_sim_app_cost(numkeys, keytype);
    if ((uint32_t)hdr->reserved + cost > hdr->cardsize) {
        return MFDES_E_OUT_OF_EEPROM;
    }

    // the tables have to stay clear of the file data growing down at them
    uint32_t grow = sizeof(desfire_em_app_t) + ((uint32_t)numkeys * sizeof(desfire_em_key_t));
    if ((uint32_t)hdr->tables_end + grow > hdr->data_start) {
        return MFDES_E_OUT_OF_EEPROM;
    }

    // open a gap where the file table starts, and put the new entry in it
    uint16_t at = hdr->file_off;
    memmove(base + at + sizeof(desfire_em_app_t), base + at, hdr->tables_end - at);

    desfire_em_app_t *a = (desfire_em_app_t *)(base + at);
    memset(a, 0, sizeof(*a));
    a->aid[0] = aid & 0xFF;
    a->aid[1] = (aid >> 8) & 0xFF;
    a->aid[2] = (aid >> 16) & 0xFF;
    a->keysettings = keysettings;
    a->numkeysraw = numkeysraw;
    a->keytype = keytype;
    a->isofid = isofid;

    if (numkeysraw & 0x20) {
        a->flags |= DESFIRE_EM_APP_ISOFIDS;
    }

    if (dfnamelen > sizeof(a->dfname)) {
        dfnamelen = sizeof(a->dfname);
    }
    if (dfnamelen) {
        memcpy(a->dfname, dfname, dfnamelen);
    }
    a->dfnamelen = dfnamelen;

    hdr->file_off += sizeof(desfire_em_app_t);
    hdr->key_off += sizeof(desfire_em_app_t);
    hdr->tables_end += sizeof(desfire_em_app_t);

    // the application's keys go on the end of the key table, all zero, which is
    // what a card gives a new application
    uint8_t appidx = hdr->appcount;
    desfire_em_key_t *k = (desfire_em_key_t *)(base + hdr->tables_end);

    for (uint8_t i = 0; i < numkeys; i++) {
        memset(&k[i], 0, sizeof(desfire_em_key_t));
        k[i].app = appidx;
        k[i].num = i;
        k[i].flags = DESFIRE_EM_KEY_PRESENT | DESFIRE_EM_KEY_VERKNOWN;
    }

    hdr->tables_end += numkeys * sizeof(desfire_em_key_t);
    hdr->keycount += numkeys;
    hdr->appcount++;
    hdr->reserved += cost;

    // the tables moved, so the parsed view of them has to be taken again
    int selected = st->selected;
    desfire_sim_load(st);
    st->selected = selected;
    return MFDES_S_OPERATION_OK;
}

// FormatPICC: every application and every file goes, and the memory they held
// comes back.  The PICC master key and its settings are explicitly untouched
// (M134034 9.4.6), and so is the card identity, so what is left is the same
// card with nothing on it.
//
// Everywhere else a delete only sets a tombstone, because a real card does not
// hand the memory back either.  This is the one command that reclaims, and here
// that means rebuilding the tables around the surviving PICC entry and putting
// both frontiers back where an empty card has them.
static void desfire_sim_format(desfire_sim_state_t *st) {

    uint8_t *base = desfire_sim_wbase();
    desfire_em_hdr_t *hdr = (desfire_em_hdr_t *)base;

    uint16_t oldkeys = hdr->keycount;

    // With no applications but the PICC and no files at all, the key table
    // starts directly behind the one application entry.
    uint16_t newoff = hdr->app_off + sizeof(desfire_em_app_t);
    desfire_em_key_t *dst = (desfire_em_key_t *)(base + newoff);

    // Only the PICC's own keys survive, compacted to the front of the new
    // table.  Each one moves to an address at or below the one it came from --
    // the table start only ever moves down and the write index never runs ahead
    // of the read index -- so copying forward cannot clobber a key not yet read.
    uint8_t keepcount = 0;
    for (uint16_t i = 0; i < oldkeys; i++) {

        if (st->keys[i].app != 0) {
            continue;
        }

        memmove(&dst[keepcount], &st->keys[i], sizeof(desfire_em_key_t));
        keepcount++;
    }

    hdr->appcount = 1;
    hdr->filecount = 0;
    hdr->keycount = keepcount;

    hdr->file_off = newoff;         // empty, so the key table starts here too
    hdr->key_off = newoff;
    hdr->tables_end = newoff + (keepcount * sizeof(desfire_em_key_t));

    hdr->data_start = hdr->size;
    hdr->reserved = 0;

    // the tables moved, so the parsed view of them has to be taken again
    desfire_sim_load(st);
}

// Act on a write once every frame of it has arrived.  `buf`/`len` are the plain
// parameters, secure messaging already stripped.
static uint16_t desfire_sim_write_apply(desfire_sim_state_t *st, uint8_t cmd,
                                        uint8_t *buf, uint16_t len, uint8_t comm, uint8_t *out) {

    const desfire_em_file_t *f = desfire_sim_find_file(st, buf[0]);
    if (f == NULL) {
        return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
    }

    uint8_t *base = desfire_sim_wbase();

    switch (cmd) {

        case MFDES_WRITE_DATA:
        case MFDES_WRITE_DATA2: {

            if (f->type != 0x00 && f->type != 0x01) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint32_t off = buf[1] | (buf[2] << 8) | (buf[3] << 16);
            uint32_t n = buf[4] | (buf[5] << 8) | (buf[6] << 16);

            if (len < 7 + n) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }
            if (off + n > f->u.data.size || off + n > f->datalen) {
                return desfire_sim_status(out, MFDES_E_BOUNDARY);
            }

            desfire_sim_mark_dirty(st, f);
            memcpy(base + desfire_sim_write_region(f) + off, buf + 7, n);

            // contents are meaningful now even if the dump never read them
            ((desfire_em_file_t *)f)->flags &= ~DESFIRE_EM_FILE_UNKNOWN;
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_WRITE_RECORD:
        case MFDES_WRITE_RECORD2: {

            if (f->type != 0x03 && f->type != 0x04) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint32_t off = buf[1] | (buf[2] << 8) | (buf[3] << 16);
            uint32_t n = buf[4] | (buf[5] << 8) | (buf[6] << 16);
            uint32_t rs = f->u.record.recordsize;

            if (rs == 0 || len < 7 + n || off + n > rs) {
                return desfire_sim_status(out, MFDES_E_BOUNDARY);
            }

            // a linear file is full once it holds maxrecords; a cyclic one
            // overwrites the oldest instead -- EV1 9.5.9
            uint32_t cur = f->u.record.currecords;
            uint32_t max = f->u.record.maxrecords;

            if (f->type == 0x03 && cur >= max) {
                return desfire_sim_status(out, MFDES_E_BOUNDARY);
            }

            uint32_t slot = (cur < max) ? cur : (cur % max);
            if ((slot + 1) * rs > f->datalen) {
                return desfire_sim_status(out, MFDES_E_BOUNDARY);
            }

            desfire_sim_mark_dirty(st, f);
            memcpy(base + desfire_sim_write_region(f) + (slot * rs) + off, buf + 7, n);

            if (cur < max) {
                ((desfire_em_file_t *)f)->u.record.currecords = cur + 1;
            }
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_UPDATE_RECORD:
        case MFDES_UPDATE_RECORD2: {

            if (f->type != 0x03 && f->type != 0x04) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint32_t rec = buf[1] | (buf[2] << 8) | (buf[3] << 16);
            uint32_t off = buf[4] | (buf[5] << 8) | (buf[6] << 16);
            uint32_t n = buf[7] | (buf[8] << 8) | (buf[9] << 16);
            uint32_t rs = f->u.record.recordsize;

            if (rs == 0 || len < 10 + n || off + n > rs || rec >= f->u.record.currecords) {
                return desfire_sim_status(out, MFDES_E_BOUNDARY);
            }
            if ((rec + 1) * rs > f->datalen) {
                return desfire_sim_status(out, MFDES_E_BOUNDARY);
            }

            desfire_sim_mark_dirty(st, f);
            memcpy(base + desfire_sim_write_region(f) + (rec * rs) + off, buf + 10, n);
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_CREDIT:
        case MFDES_DEBIT:
        case MFDES_LIMITED_CREDIT: {

            if (f->type != 0x02 || len < 5) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint32_t delta = buf[1] | (buf[2] << 8) | (buf[3] << 16) | ((uint32_t)buf[4] << 24);
            uint32_t v = desfire_sim_value_get(st, f);

            if (cmd == MFDES_DEBIT) {
                if (delta > v || (v - delta) < f->u.value.lower) {
                    return desfire_sim_status(out, MFDES_E_BOUNDARY);
                }
                v -= delta;
            } else {
                if (delta > f->u.value.upper || (v + delta) > f->u.value.upper) {
                    return desfire_sim_status(out, MFDES_E_BOUNDARY);
                }
                v += delta;
            }

            desfire_sim_value_set(st, f, v);
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        default:
            return desfire_sim_status(out, MFDES_E_ILLEGAL_COMMAND_CODE);
    }
}

// Gather one frame of a write.  A write is secured as a whole, so nothing is
// acted on until the reader stops chaining -- the MAC covers every byte of it
// and an enciphered write carries a single CRC32 at the end.
static uint16_t desfire_sim_write_gather(desfire_sim_state_t *st, uint8_t cmd,
                                         const uint8_t *in, uint16_t inlen, uint8_t *out) {

    if (st->wcmd == 0) {
        st->wcmd = cmd;
        st->wlen = 0;
    }

    if ((uint32_t)st->wlen + inlen > sizeof(st->wbuf)) {
        st->wcmd = 0;
        st->wlen = 0;
        return desfire_sim_status(out, MFDES_E_LENGTH);
    }

    memcpy(st->wbuf + st->wlen, in, inlen);
    st->wlen += inlen;

    // The reader chains by sending its own 0xAF frames; the card only answers
    // 0xAF to ask for more.  A full frame means more is probably coming, so
    // this asks for it and acts when a short frame arrives.
    if (inlen >= DESFIRE_SIM_WRITE_FRAME) {
        return desfire_sim_status(out, MFDES_ADDITIONAL_FRAME);
    }

    uint8_t wcmd = st->wcmd;
    uint16_t wlen = st->wlen;
    st->wcmd = 0;
    st->wlen = 0;

    if (wlen < 1) {
        return desfire_sim_status(out, MFDES_E_LENGTH);
    }

    const desfire_em_file_t *f = desfire_sim_find_file(st, st->wbuf[0]);
    if (f == NULL) {
        return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
    }

    uint8_t comm = DESFIRE_SIM_COMM_PLAIN;
    bool ok = (f->type == 0x02)
              ? desfire_sim_value_comm(st, f, (wcmd == MFDES_CREDIT), &comm)
              : desfire_sim_eff_comm(st, f, true, &comm);

    if (ok == false) {
        return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
    }

    if (desfire_sim_unwrap(st, wcmd, comm, st->wbuf, &wlen) == false) {
        desfire_sim_auth_clear(st);
        return desfire_sim_status(out, MFDES_E_INTEGRITY_ERROR);
    }

    return desfire_sim_write_apply(st, wcmd, st->wbuf, wlen, comm, out);
}

// Dispatch one DESFire command. `cmd` is the command byte, `in`/`inlen` the
// parameters after it. Writes the answer to `out` and returns its length.
static uint16_t desfire_sim_command(desfire_sim_state_t *st, uint8_t cmd, const uint8_t *in, uint16_t inlen, uint8_t *out) {

    const desfire_em_hdr_t *hdr = st->hdr;

    // an additional frame only means anything while a command is being chained
    // or an authentication is half done
    if (cmd == MFDES_ADDITIONAL_FRAME && st->chain_cmd == 0 && st->auth_cmd == 0) {
        return desfire_sim_status(out, MFDES_E_ILLEGAL_COMMAND_CODE);
    }

    if (cmd != MFDES_ADDITIONAL_FRAME) {
        st->chain_cmd = 0;
        st->chain_step = 0;
        st->chain_file = -1;
        if (desfire_sim_cmd_is_write(cmd) == false) {
            st->wcmd = 0;
            st->wlen = 0;
        }

        // a command arriving mid handshake abandons it
        if (cmd != MFDES_AUTHENTICATE && cmd != MFDES_AUTHENTICATE_ISO && cmd != MFDES_AUTHENTICATE_AES) {
            st->auth_cmd = 0;
        }
    }

    // The session CMAC covers every command and response in order, so it is
    // taken here for all of them, before the command is acted on.  The
    // authentication handshake is the exception -- it is what establishes the
    // session key, so it runs outside the chain.
    // 0xAF is not a command in its own right, it continues one, and a chained
    // transfer is secured as a single message -- the reader joins every frame
    // and checks one MAC over the lot.  MACing the continuation would reset the
    // running calculation halfway through and leave the last frame's MAC wrong,
    // so it is left to the auth, read and write paths that own the chain.
    if (cmd != MFDES_AUTHENTICATE && cmd != MFDES_AUTHENTICATE_ISO &&
            cmd != MFDES_AUTHENTICATE_AES && cmd != MFDES_ADDITIONAL_FRAME &&
            st->auth_cmd == 0 && desfire_sim_cmd_unwraps_own(cmd) == false && st->wcmd == 0) {
        desfire_sim_cmac_command(st, cmd, in, inlen);
    }

    switch (cmd) {

        case MFDES_GET_VERSION: {
            // three frames: hardware, software, then production. The first two
            // are answered with ADDITIONAL_FRAME so the reader asks again.
            st->chain_cmd = MFDES_GET_VERSION;
            st->chain_step = 1;
            desfire_sim_cmac_reset(st);
            return desfire_sim_chained(st, out, true, hdr->versionhw, hdr->versionhwlen);
        }

        case MFDES_ADDITIONAL_FRAME: {

            if (st->auth_cmd != 0) {
                return desfire_sim_auth_finish(st, in, inlen, out);
            }

            if (st->chain_cmd == MFDES_GET_VERSION) {

                if (st->chain_step == 1) {
                    st->chain_step = 2;
                    return desfire_sim_chained(st, out, true, hdr->versionsw, hdr->versionswlen);
                }

                st->chain_cmd = 0;
                st->chain_step = 0;
                return desfire_sim_chained(st, out, false, hdr->versionprod, hdr->versionprodlen);
            }

            if (st->wcmd != 0) {
                return desfire_sim_write_gather(st, st->wcmd, in, inlen, out);
            }

            if (st->chain_cmd == MFDES_READ_DATA && st->chain_file >= 0) {
                return desfire_sim_read_chunk(st, out);
            }

            if (st->chain_cmd == MFDES_GET_DF_NAMES) {

                uint8_t buf[DESFIRE_SIM_MAX_RESP] = {0};
                uint8_t next = st->chain_step;
                bool more = false;
                uint16_t n = desfire_sim_dfname_record(st, st->chain_step, buf, &next, &more);

                if (n == 0) {
                    st->chain_cmd = 0;
                    st->chain_step = 0;
                    return desfire_sim_status(out, MFDES_S_OPERATION_OK);
                }

                if (more) {
                    st->chain_step = next;
                    return desfire_sim_chained(st, out, true, buf, n);
                }

                st->chain_cmd = 0;
                st->chain_step = 0;
                return desfire_sim_chained(st, out, false, buf, n);
            }

            return desfire_sim_status(out, MFDES_E_ILLEGAL_COMMAND_CODE);
        }

        case MFDES_AUTHENTICATE:
        case MFDES_AUTHENTICATE_ISO:
        case MFDES_AUTHENTICATE_AES:
            return desfire_sim_auth_start(st, cmd, in, inlen, out);

        case MFDES_GET_DF_NAMES: {
            // PICC level only (M134034 9.4.4), one application per frame
            if (st->selected != 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint8_t buf[DESFIRE_SIM_MAX_RESP] = {0};
            uint8_t next = 1;
            bool more = false;
            uint16_t n = desfire_sim_dfname_record(st, 1, buf, &next, &more);
            if (n == 0) {
                return desfire_sim_status(out, MFDES_S_OPERATION_OK);
            }

            desfire_sim_cmac_reset(st);

            if (more) {
                st->chain_cmd = MFDES_GET_DF_NAMES;
                st->chain_step = next;
                return desfire_sim_chained(st, out, true, buf, n);
            }
            return desfire_sim_chained(st, out, false, buf, n);
        }

        case MFDES_GET_ISOFILE_IDS: {
            // application level: the ISO file ids of the files that have one.
            // Value and transaction MAC files never carry one.
            if (st->selected == 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint8_t buf[DESFIRE_SIM_MAX_RESP] = {0};
            uint16_t n = 0;
            for (uint16_t i = 0; i < hdr->filecount && (n + 2) <= sizeof(buf); i++) {

                const desfire_em_file_t *f = &st->files[i];
                if (f->app != st->selected || (f->flags & DESFIRE_EM_FILE_DELETED)) {
                    continue;
                }
                if (f->type == 0x02 || f->type == 0x05 || f->isofid == 0) {
                    continue;
                }

                buf[n++] = f->isofid & 0xFF;
                buf[n++] = (f->isofid >> 8) & 0xFF;
            }

            // "If there is no ISO File EF, only an error code can be returned"
            if (n == 0) {
                return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
            }
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, buf, n);
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
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, buf, n);
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

            // "each SelectApplication command invalidates the current
            // authentication status" -- M134034 9.4.5
            desfire_sim_auth_clear(st);
            return desfire_sim_status(out, MFDES_S_OPERATION_OK);
        }

        case MFDES_GET_FREE_MEMORY: {
            // what the card has left, not what emulator memory has left. Three
            // bytes, LSB first.
            uint32_t freemem = (hdr->cardsize > hdr->reserved) ? (hdr->cardsize - hdr->reserved) : 0;
            uint8_t buf[3] = { freemem & 0xFF, (freemem >> 8) & 0xFF, (freemem >> 16) & 0xFF };
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, buf, sizeof(buf));
        }

        case MFDES_CHANGE_CONFIGURATION: {

            // "Master key authentication on card level needs to be performed
            // prior to the SetConfiguration command" -- M134034 9.4.9
            if (st->authenticated == false || st->selected != 0 || st->auth_keyno != 0) {
                return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
            }

            if (inlen < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            // the option byte travels in the clear, the data behind it does not
            uint8_t buf[DESFIRE_SIM_WRITE_MAX] = {0};
            if (inlen > sizeof(buf)) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            memcpy(buf, in, inlen);
            uint16_t len = inlen;

            if (desfire_sim_unwrap(st, cmd, DESFIRE_SIM_COMM_FULL, buf, &len) == false) {
                desfire_sim_auth_clear(st);
                return desfire_sim_status(out, MFDES_E_INTEGRITY_ERROR);
            }

            if (len < 2) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            desfire_em_hdr_t *w = (desfire_em_hdr_t *)hdr;

            switch (buf[0]) {

                case 0x00: {
                    // the configuration byte.  Both bits it defines are one way
                    // on a card -- "cannot be reset" -- so they are only ever
                    // set here, never cleared.
                    w->flags |= (buf[1] & (DESFIRE_EM_PICC_NO_FORMAT | DESFIRE_EM_PICC_RANDOM_UID));
                    break;
                }

                case 0x02: {
                    // the user defined ATS, TL first and without the CRC the
                    // card appends.  The spec checks its length and nothing
                    // else, so neither does this.
                    uint16_t n = len - 1;
                    if (n == 0 || n > sizeof(w->ats)) {
                        return desfire_sim_status(out, MFDES_E_LENGTH);
                    }

                    memset(w->ats, 0, sizeof(w->ats));
                    memcpy(w->ats, buf + 1, n);
                    w->atslen = n;
                    break;
                }

                case 0x01:
                // the default key new applications are created with.  Storing
                // it needs two fields the card image does not have, and adding
                // them moves every table in it, so this is refused rather than
                // silently ignored -- a reader that sets a default key and then
                // finds new applications keyed with zeros is worse off than one
                // told the option is not there.
                default:
                    return desfire_sim_status(out, MFDES_E_PARAMETER_ERROR);
            }

            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_READSIG: {

            // one byte selects which signature, and EV1 only has the one
            if (inlen < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            if (in[0] != 0x00) {
                return desfire_sim_status(out, MFDES_E_PARAMETER_ERROR);
            }

            // An originality signature is not an EV1 feature.  It is absent
            // from M134034 entirely, the client only asks EV2 and later for one,
            // and a genuine EV1 answers 91 1C to this command -- measured on
            // MF3ICD81 UID 04 26 85 12 A2 56 80, which answers GetVersion in the
            // same breath.  So a card image of that generation says the same,
            // whatever the image happens to carry.
            if (hdr->generation == DESFIRE_EM_GEN_D40 ||
                    hdr->generation == DESFIRE_EM_GEN_EV1 ||
                    hdr->generation == DESFIRE_EM_GEN_UNKNOWN) {
                return desfire_sim_status(out, MFDES_E_ILLEGAL_COMMAND_CODE);
            }

            // A later card whose dump never read a signature has none to give,
            // and 56 zero bytes would be a lie a reader cannot tell from a real
            // answer.
            if (hdr->signaturelen == 0) {
                return desfire_sim_status(out, MFDES_E_ILLEGAL_COMMAND_CODE);
            }

            uint8_t n = hdr->signaturelen;
            if (n > sizeof(hdr->signature)) {
                n = sizeof(hdr->signature);
            }

            // ReadSignature answers 0x90 rather than 0x00, and that is the byte
            // the response CMAC is taken over
            return desfire_sim_maced(st, out, MFDES_S_SIGNATURE, hdr->signature, n);
        }

        case MFDES_GET_KEY_VERSION: {

            if (inlen < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            uint8_t keyno = in[0] & 0x3F;
            const desfire_em_app_t *app = &st->apps[st->selected];

            // "If AID = 0x00 is selected, the command returns the version of the
            // PICC master key and therefore only KeyNo = 0x00 is valid" --
            // M134034 9.3.7
            if (st->selected == 0) {
                if (keyno != 0) {
                    return desfire_sim_status(out, MFDES_E_NO_SUCH_KEY);
                }
            } else if (keyno >= (app->numkeysraw & 0x0F)) {
                return desfire_sim_status(out, MFDES_E_NO_SUCH_KEY);
            }

            const desfire_em_key_t *k = desfire_sim_key_slot(st, st->selected, keyno);
            if (k == NULL) {
                return desfire_sim_status(out, MFDES_E_NO_SUCH_KEY);
            }

            // A key version is readable without knowing the key, which is why
            // the image tracks the two apart.  A version the dump never read
            // comes back as 0, which is what a default key carries anyway.
            uint8_t ver = k->ver;
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, &ver, 1);
        }

        case MFDES_GET_KEY_SETTINGS: {
            const desfire_em_app_t *a = &st->apps[st->selected];
            uint8_t buf[2] = { a->keysettings, a->numkeysraw };
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, buf, sizeof(buf));
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
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, buf, n);
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

                return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, buf, n);
            }

            return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
        }

        case MFDES_READ_DATA:
        case MFDES_READ_DATA2: {

            // fileno, then a 3 byte offset and a 3 byte length
            if (inlen < 7) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            const desfire_em_file_t *f = desfire_sim_find_file(st, in[0]);
            if (f == NULL) {
                return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
            }

            if (f->type != 0x00 && f->type != 0x01) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint8_t comm = DESFIRE_SIM_COMM_PLAIN;
            if (desfire_sim_eff_comm(st, f, false, &comm) == false) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint32_t off = in[1] | (in[2] << 8) | (in[3] << 16);
            uint32_t len = in[4] | (in[5] << 8) | (in[6] << 16);

            return desfire_sim_read_start(st, f, off, len, 1, f->u.data.size, comm, out);
        }

        case MFDES_READ_RECORDS:
        case MFDES_READ_RECORDS2: {

            if (inlen < 7) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            const desfire_em_file_t *f = desfire_sim_find_file(st, in[0]);
            if (f == NULL) {
                return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
            }

            if (f->type != 0x03 && f->type != 0x04) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint8_t comm = DESFIRE_SIM_COMM_PLAIN;
            if (desfire_sim_eff_comm(st, f, false, &comm) == false) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint32_t off = in[1] | (in[2] << 8) | (in[3] << 16);
            uint32_t num = in[4] | (in[5] << 8) | (in[6] << 16);

            // offset counts back from the newest record, so record 0 is the one
            // written last -- EV1 9.5.8
            if (f->u.record.recordsize == 0) {
                return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
            }

            return desfire_sim_read_start(st, f, off, num, f->u.record.recordsize,
                                          f->u.record.currecords, comm, out);
        }

        case MFDES_GET_VALUE: {

            if (inlen < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            const desfire_em_file_t *f = desfire_sim_find_file(st, in[0]);
            if (f == NULL) {
                return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
            }

            if (f->type != 0x02) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint8_t comm = DESFIRE_SIM_COMM_PLAIN;
            if (desfire_sim_value_comm(st, f, false, &comm) == false) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint32_t v = f->u.value.value;
            uint8_t buf[4] = { v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF };
            return desfire_sim_respond(st, out, MFDES_S_OPERATION_OK, buf, sizeof(buf), comm);
        }

        case MFDES_WRITE_DATA:
        case MFDES_WRITE_DATA2:
        case MFDES_WRITE_RECORD:
        case MFDES_WRITE_RECORD2:
        case MFDES_UPDATE_RECORD:
        case MFDES_UPDATE_RECORD2:
        case MFDES_CREDIT:
        case MFDES_DEBIT:
        case MFDES_LIMITED_CREDIT:
            return desfire_sim_write_gather(st, cmd, in, inlen, out);

        case MFDES_CREATE_STD_DATA_FILE:
        case MFDES_CREATE_BACKUP_DATA_FILE:
        case MFDES_CREATE_VALUE_FILE:
        case MFDES_CREATE_LINEAR_RECORD_FILE:
        case MFDES_CREATE_CYCLIC_RECORD_FILE: {

            if (st->selected == 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            const desfire_em_app_t *app = &st->apps[st->selected];

            // application key settings bit 2 clear means create and delete need
            // the application master key (M134034 9.3.4)
            if ((app->keysettings & 0x04) == 0) {
                if (st->authenticated == false || st->auth_keyno != 0) {
                    return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
                }
            }

            // the ISO file id is only on the wire when the application was
            // created with ISO file ids enabled
            bool isofids = (app->flags & DESFIRE_EM_APP_ISOFIDS) != 0;
            uint8_t type;
            uint8_t need;

            switch (cmd) {
                case MFDES_CREATE_STD_DATA_FILE:
                    type = 0x00;
                    need = isofids ? 9 : 7;
                    break;
                case MFDES_CREATE_BACKUP_DATA_FILE:
                    type = 0x01;
                    need = isofids ? 9 : 7;
                    break;
                case MFDES_CREATE_VALUE_FILE:
                    type = 0x02;
                    need = 17;      // never carries an ISO file id
                    break;
                case MFDES_CREATE_LINEAR_RECORD_FILE:
                    type = 0x03;
                    need = isofids ? 12 : 10;
                    break;
                default:
                    type = 0x04;
                    need = isofids ? 12 : 10;
                    break;
            }

            // every one of these is fixed length, so a frame that is not
            // exactly the expected size is rejected rather than parsed from the
            // wrong offset -- a reader that sends an ISO file id to an
            // application that does not use them lands here
            if (inlen != need) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            uint8_t fileno = in[0];
            uint16_t isofid = 0;
            const uint8_t *p = in + 1;

            if (isofids && type != 0x02) {
                isofid = p[0] | (p[1] << 8);
                p += 2;
            }

            uint8_t comm = p[0];
            uint16_t rights = p[1] | (p[2] << 8);
            p += 3;

            uint32_t size = 0, recsize = 0, maxrec = 0;
            uint32_t lower = 0, upper = 0, value = 0;
            uint8_t options = 0;

            if (type == 0x00 || type == 0x01) {

                size = p[0] | (p[1] << 8) | (p[2] << 16);

            } else if (type == 0x02) {

                lower = p[0] | (p[1] << 8) | (p[2] << 16) | ((uint32_t)p[3] << 24);
                upper = p[4] | (p[5] << 8) | (p[6] << 16) | ((uint32_t)p[7] << 24);
                value = p[8] | (p[9] << 8) | (p[10] << 16) | ((uint32_t)p[11] << 24);
                options = p[12];

                // "The upper limit has to be higher than the lower limit,
                // otherwise an error message would be sent by the PICC and thus
                // the file would not be created" -- M134034 9.5.7, and the
                // initial value has to sit between the two
                if ((int32_t)upper <= (int32_t)lower ||
                        (int32_t)value < (int32_t)lower || (int32_t)value > (int32_t)upper) {
                    return desfire_sim_status(out, MFDES_E_PARAMETER_ERROR);
                }

            } else {

                recsize = p[0] | (p[1] << 8) | (p[2] << 16);
                maxrec = p[3] | (p[4] << 8) | (p[5] << 16);

                if (recsize == 0 || maxrec == 0) {
                    return desfire_sim_status(out, MFDES_E_PARAMETER_ERROR);
                }
            }

            uint8_t res = desfire_sim_file_create(st, fileno, type, comm, rights, isofid,
                                                  size, recsize, maxrec, lower, upper, value, options);
            if (res != MFDES_S_OPERATION_OK) {
                return desfire_sim_status(out, res);
            }
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_CHANGE_KEY_SETTINGS: {

            // "Additionally a successful preceding authentication with the
            // master key is required (PICC master key if AID = 0x00, else with
            // application master key)" -- M134034 9.3.4
            if (st->authenticated == false || st->auth_keyno != 0) {
                return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
            }

            const desfire_em_app_t *app = &st->apps[st->selected];

            // "This command only succeeds if the configuration changeable bit
            // of the current key settings was not cleared before".  Clearing it
            // is one way, which is the point of it.
            if ((app->keysettings & 0x08) == 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            // one byte of new settings, enciphered with a CRC32 behind it, the
            // same shape ChangeKey uses and nothing in the clear
            uint8_t buf[DESFIRE_SIM_WRITE_MAX] = {0};
            if (inlen == 0 || inlen > sizeof(buf)) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            memcpy(buf, in, inlen);
            uint16_t len = inlen;

            if (desfire_sim_unwrap(st, cmd, DESFIRE_SIM_COMM_FULL, buf, &len) == false) {
                desfire_sim_auth_clear(st);
                return desfire_sim_status(out, MFDES_E_INTEGRITY_ERROR);
            }

            if (len < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            ((desfire_em_app_t *)app)->keysettings = buf[0];
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_CHANGE_KEY: {

            if (inlen < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            if (st->authenticated == false) {
                return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
            }

            uint8_t keyno = in[0] & 0x3F;
            const desfire_em_app_t *app = &st->apps[st->selected];
            uint8_t algo = app->keytype;

            // At PICC level the top two bits of the key number choose the
            // algorithm the new master key is to be, since there is no
            // application creation to fix it -- M134034 9.3.6.  Inside an
            // application the key type cannot change after creation.
            if (st->selected == 0) {

                if (keyno != 0) {
                    return desfire_sim_status(out, MFDES_E_PARAMETER_ERROR);
                }

                switch ((in[0] >> 6) & 0x03) {
                    case 0x01:
                        algo = T_3K3DES;
                        break;
                    case 0x02:
                        algo = T_AES;
                        break;
                    default:
                        algo = T_3DES;
                        break;
                }

            } else if (keyno >= (app->numkeysraw & 0x0F)) {
                return desfire_sim_status(out, MFDES_E_NO_SUCH_KEY);
            }

            // Which key had to be authenticated: the master key changes only
            // with the master key and only while it is still changeable, and
            // everything else is governed by the change-key nibble of the
            // application's key settings (M134034 9.3.4 and 9.3.6).
            uint8_t ck = (app->keysettings >> 4) & 0x0F;

            if (keyno == 0) {

                if ((app->keysettings & 0x01) == 0) {
                    return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
                }
                if (st->auth_keyno != 0) {
                    return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
                }

            } else if (ck == 0x0F) {

                // every key but the master key is frozen
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);

            } else if (ck == 0x0E) {

                // free: a key is changed by whoever authenticated with it
                if (st->auth_keyno != keyno) {
                    return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
                }

            } else if (st->auth_keyno != ck) {
                return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
            }

            desfire_em_key_t *slot = desfire_sim_key_slot(st, st->selected, keyno);
            if (slot == NULL) {
                return desfire_sim_status(out, MFDES_E_NO_SUCH_KEY);
            }

            // The reader enciphers the key data under the session key.  Its
            // shape is fixed, so the length is known rather than searched for:
            // the key, an AES version byte, the CRC32 over command, key number
            // and that lot, and -- only when the key being changed is not the
            // one the session was opened with -- a CRC32 of the new key on top.
            uint8_t keylen = desfire_sim_keylen(algo);
            bool xored = (keyno != st->auth_keyno);

            uint16_t plainlen = keylen + ((algo == T_AES) ? 1 : 0) + 4 + (xored ? 4 : 0);

            size_t kbs = key_block_size(&st->sesskey);
            if (kbs == 0) {
                return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
            }

            uint16_t enclen = inlen - 1;
            if (enclen != padded_data_length(plainlen, kbs)) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            uint8_t buf[DESFIRE_SIM_WRITE_MAX] = {0};
            if (enclen > sizeof(buf)) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            desfire_sim_crypt(&st->sesskey, in + 1, buf, enclen, st->iv, false);

            // the CRC32 covers the command byte, the key number as it arrived,
            // and the plaintext up to but not including the CRC itself
            uint16_t upto = keylen + ((algo == T_AES) ? 1 : 0);

            uint8_t crcbuf[DESFIRE_SIM_WRITE_MAX + 8] = {0};
            crcbuf[0] = cmd;
            crcbuf[1] = in[0];
            memcpy(crcbuf + 2, buf, upto);

            uint8_t want[4] = {0};
            crc32_ex(crcbuf, upto + 2, want);

            if (memcmp(want, buf + upto, 4) != 0) {
                desfire_sim_auth_clear(st);
                return desfire_sim_status(out, MFDES_E_INTEGRITY_ERROR);
            }

            uint8_t newkey[DESFIRE_MAX_KEY_SIZE] = {0};
            memcpy(newkey, buf, keylen);

            if (xored) {

                // what arrived is the new key XORed with the current one, so the
                // card needs to hold the current one to recover it
                if ((slot->flags & DESFIRE_EM_KEY_PRESENT) == 0) {
                    return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
                }

                for (uint8_t i = 0; i < keylen; i++) {
                    newkey[i] ^= slot->key[i];
                }

                // and a CRC32 of the new key alone proves the XOR came apart
                uint8_t want2[4] = {0};
                crc32_ex(newkey, keylen, want2);

                if (memcmp(want2, buf + upto + 4, 4) != 0) {
                    desfire_sim_auth_clear(st);
                    return desfire_sim_status(out, MFDES_E_INTEGRITY_ERROR);
                }
            }

            memset(slot->key, 0, sizeof(slot->key));
            memcpy(slot->key, newkey, keylen);
            slot->ver = desfire_sim_key_version(algo, newkey, (algo == T_AES) ? buf[keylen] : 0);
            slot->flags |= DESFIRE_EM_KEY_PRESENT | DESFIRE_EM_KEY_VERKNOWN;

            // changing the PICC master key can change its algorithm with it
            if (st->selected == 0 && algo != app->keytype) {
                desfire_em_app_t *w = (desfire_em_app_t *)app;
                w->keytype = algo;
                w->numkeysraw = (w->numkeysraw & 0x3F) |
                                ((algo == T_AES) ? 0x80 : ((algo == T_3K3DES) ? 0x40 : 0x00));
            }

            // "After a successful change of the key used to reach the current
            // authentication status, this authentication is invalidated"
            // -- M134034 9.3.6.  The answer to this one still carries its MAC,
            // so the session is dropped after it is built.
            if (xored == false) {
                uint16_t n = desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
                desfire_sim_auth_clear(st);
                return n;
            }

            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_CHANGE_FILE_SETTINGS: {

            if (inlen < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            if (st->selected == 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            const desfire_em_file_t *f = desfire_sim_find_file(st, in[0]);
            if (f == NULL) {
                return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
            }

            uint8_t change = DESFIRE_SIM_AR_CHANGE(f->rights);

            // "This change only succeeds if the current Access Rights for
            // Change Access Rights is different from never" -- M134034 9.5.4
            if (change == DESFIRE_SIM_AR_DENY) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            // "However, if the ChangeAccessRights Access Rights is set with the
            // value free, no security mechanism is necessary and therefore the
            // data is sent as plain text (5 byte overall length)."  Otherwise it
            // is enciphered under the key that right names.
            uint8_t comm;
            if (change == DESFIRE_SIM_AR_FREE) {
                comm = DESFIRE_SIM_COMM_PLAIN;
            } else {
                if (st->authenticated == false || st->auth_keyno != change) {
                    return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
                }
                comm = DESFIRE_SIM_COMM_FULL;
            }

            uint8_t buf[DESFIRE_SIM_WRITE_MAX] = {0};
            if (inlen > sizeof(buf)) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            memcpy(buf, in, inlen);
            uint16_t len = inlen;

            if (desfire_sim_unwrap(st, cmd, comm, buf, &len) == false) {
                desfire_sim_auth_clear(st);
                return desfire_sim_status(out, MFDES_E_INTEGRITY_ERROR);
            }

            // file number, the new communication settings, then the new rights
            if (len < 4) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            desfire_em_file_t *w = (desfire_em_file_t *)f;
            w->flags = (w->flags & ~DESFIRE_EM_FILE_COMM_MASK) | (buf[1] & DESFIRE_EM_FILE_COMM_MASK);
            w->rights = buf[2] | (buf[3] << 8);

            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_DELETE_FILE: {

            if (inlen < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            if (st->selected == 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            const desfire_em_app_t *app = &st->apps[st->selected];
            if ((app->keysettings & 0x04) == 0) {
                if (st->authenticated == false || st->auth_keyno != 0) {
                    return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
                }
            }

            const desfire_em_file_t *f = desfire_sim_find_file(st, in[0]);
            if (f == NULL) {
                return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
            }

            // a tombstone, like DeleteApplication: the memory stays spent and
            // only FormatPICC hands it back
            ((desfire_em_file_t *)f)->flags |= DESFIRE_EM_FILE_DELETED;
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_CREATE_APPLICATION: {

            // "This command requires that the currently selected AID is
            // 0x00 00 00 which references the card level" -- M134034 9.4.1
            if (st->selected != 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            // AID, KeySettings1, KeySettings2, then optionally a 2 byte ISO
            // file id and a DF name of up to 16 bytes
            if (inlen < 5) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            // PICC key settings bit 2 clear means create needs the PICC master
            // key; set means it is free (M134034 9.3.4)
            const desfire_em_app_t *picc = &st->apps[0];
            if ((picc->keysettings & 0x04) == 0) {
                if (st->authenticated == false || st->auth_keyno != 0) {
                    return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
                }
            }

            uint32_t aid = in[0] | (in[1] << 8) | (in[2] << 16);
            if (aid == 0x000000) {
                // reserved as the reference to the PICC itself
                return desfire_sim_status(out, MFDES_E_PARAMETER_ERROR);
            }

            if (desfire_sim_find_app(st, aid) >= 0) {
                return desfire_sim_status(out, MFDES_E_DUPLICATE);
            }

            uint16_t isofid = 0;
            const uint8_t *dfname = NULL;
            uint8_t dfnamelen = 0;

            if (inlen >= 7) {
                isofid = in[5] | (in[6] << 8);
                dfname = in + 7;
                dfnamelen = inlen - 7;
            }

            uint8_t res = desfire_sim_app_create(st, aid, in[3], in[4], isofid, dfname, dfnamelen);
            if (res != MFDES_S_OPERATION_OK) {
                return desfire_sim_status(out, res);
            }
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_DELETE_APPLICATION: {

            if (inlen < 3) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            uint32_t aid = in[0] | (in[1] << 8) | (in[2] << 16);
            if (aid == 0x000000) {
                return desfire_sim_status(out, MFDES_E_PARAMETER_ERROR);
            }

            int idx = desfire_sim_find_app(st, aid);
            if (idx < 0) {
                return desfire_sim_status(out, MFDES_E_APPLICATION_NOT_FOUND);
            }

            // Either the PICC master key, or -- when the PICC leaves create and
            // delete free -- the application's own master key, in which case
            // that application has to be the selected and authenticated one
            // (M134034 9.3.4, footnote to bit 2).
            const desfire_em_app_t *picc = &st->apps[0];
            bool bypicc = (st->authenticated && st->selected == 0 && st->auth_keyno == 0);
            bool byapp = (st->authenticated && st->selected == idx && st->auth_keyno == 0 &&
                          (picc->keysettings & 0x04));

            if (bypicc == false && byapp == false) {
                return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
            }

            // A tombstone, not a compaction: the memory stays spent, which is
            // what a real card does -- only FormatPICC hands it back.
            desfire_em_app_t *a = (desfire_em_app_t *)&st->apps[idx];
            a->flags |= DESFIRE_EM_APP_DELETED;

            for (uint16_t i = 0; i < hdr->filecount; i++) {
                if (st->files[i].app == idx) {
                    ((desfire_em_file_t *)&st->files[i])->flags |= DESFIRE_EM_FILE_DELETED;
                }
            }

            // deleting the application you are sitting in drops you back to the
            // PICC, and the session with it
            if (st->selected == idx) {
                st->selected = 0;
                desfire_sim_auth_clear(st);
                return desfire_sim_status(out, MFDES_S_OPERATION_OK);
            }

            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_FORMAT_PICC: {

            // "This command always requires a preceding authentication with the
            // PICC master key" -- M134034 9.4.6.  Unlike create and delete it is
            // not relaxed by the free create/delete key setting, so this checks
            // the session rather than the application's key settings.
            if (st->authenticated == false || st->selected != 0 || st->auth_keyno != 0) {
                return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
            }

            // SetConfiguration can switch this command off for good
            if (hdr->flags & DESFIRE_EM_PICC_NO_FORMAT) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            desfire_sim_format(st);
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_COMMIT_TRANSACTION: {

            if (st->selected == 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }
            desfire_sim_commit(st);
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_ABORT_TRANSACTION: {

            if (st->selected == 0) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }
            desfire_sim_abort(st);
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_CLEAR_RECORD_FILE: {

            if (inlen < 1) {
                return desfire_sim_status(out, MFDES_E_LENGTH);
            }

            const desfire_em_file_t *f = desfire_sim_find_file(st, in[0]);
            if (f == NULL) {
                return desfire_sim_status(out, MFDES_E_FILE_NOT_FOUND);
            }
            if (f->type != 0x03 && f->type != 0x04) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            uint8_t comm = DESFIRE_SIM_COMM_PLAIN;
            if (desfire_sim_eff_comm(st, f, true, &comm) == false) {
                return desfire_sim_status(out, MFDES_E_PERMISSION_DENIED);
            }

            // the records only go once the transaction is committed
            desfire_sim_mark_dirty(st, f);
            ((desfire_em_file_t *)f)->u.record.currecords = 0;
            return desfire_sim_maced(st, out, MFDES_S_OPERATION_OK, NULL, 0);
        }

        case MFDES_GET_UID: {

            // The real card answers the UID enciphered under the session key,
            // so this needs an authenticated session and nothing else.
            if (st->authenticated == false) {
                return desfire_sim_status(out, MFDES_E_AUTHENTICATION_ERROR);
            }

            uint8_t uidlen = hdr->uidlen;
            if (uidlen > sizeof(hdr->uid)) {
                uidlen = sizeof(hdr->uid);
            }

            return desfire_sim_enciphered(st, out, MFDES_S_OPERATION_OK, hdr->uid, uidlen);
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

// The three random id bytes, drawn when a simulation starts.
static uint8_t s_sim_randomid[3];

static void desfire_sim_identity(uint8_t *uid, uint8_t *uidlen, uint8_t *atqa, uint8_t *sak, uint8_t *ats, uint8_t *atslen) {

    if (s_ready == false) {
        return;
    }

    const desfire_em_hdr_t *hdr = s_st.hdr;

    // With random ID switched on, anticollision shows a 4 byte id whose first
    // byte is the 0x08 random tag and whose other three are the random number,
    // and a single cascade level is all that is used (M134034 6.5).  The real
    // UID is then only reachable through GetCardUID, which is what that command
    // is for.  A card draws the number at RF reset; the nearest thing here is
    // the start of a simulation, since that is when the answers are built.
    bool randomid = (hdr->flags & DESFIRE_EM_PICC_RANDOM_UID) != 0;

    if (uid) {
        if (randomid) {
            uid[0] = 0x08;
            uid[1] = s_sim_randomid[0];
            uid[2] = s_sim_randomid[1];
            uid[3] = s_sim_randomid[2];
        } else if (hdr->uidlen <= sizeof(hdr->uid)) {
            memcpy(uid, hdr->uid, hdr->uidlen);
        }
    }

    if (uidlen) {
        *uidlen = randomid ? 4 : hdr->uidlen;
    }

    if (atqa) {
        atqa[0] = hdr->atqa[0];
        atqa[1] = hdr->atqa[1];

        // the UID size bits of ATQA byte 0 have to follow the id actually shown
        if (randomid) {
            atqa[0] &= ~0xC0;
        }
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
    s_st.chain_file = -1;
    desfire_sim_auth_clear(&s_st);
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

// ISO/IEC 14443-3 activation states. A real PICC only answers what its current
// state allows: after a HALT it hears WUPA but not REQA, it will not start
// cascade 2 before cascade 1 finished, and nothing at the 14443-4 layer is
// legal until RATS has been answered.
typedef enum {
    DESF_NOFIELD = 0,   // unpowered
    DESF_IDLE,          // powered, answers REQA and WUPA
    DESF_READY1,        // cascade level 1 in progress
    DESF_READY2,        // cascade level 2 in progress
    DESF_ACTIVE,        // selected, SAK sent, waiting for RATS
    DESF_ISO4,          // RATS answered, 14443-4 layer open
    DESF_HALTED         // answers WUPA only
} desfire_sim_pstate_t;

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

    // A card draws its random id at RF reset; a simulation draws it here, which
    // is the moment the anticollision answers are built.
    uint32_t seed = GetTickCount();
    s_sim_randomid[0] = (seed >> 16) & 0xFF;
    s_sim_randomid[1] = (seed >> 8) & 0xFF;
    s_sim_randomid[2] = seed & 0xFF;

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
        case 4:
            // a random id is 4 bytes and uses a single cascade level
            flags |= FLAG_4B_UID_IN_DATA;
            break;
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

    // Field state. A DESFire is passively powered, so when the field goes away
    // it loses the selected application, the authentication and anything a
    // transaction had not committed.
    //
    // EmGetCmd() samples the field while it listens rather than before it, so
    // there is no window where the simulation has stopped listening -- an
    // ANTICOLL arrives a few hundred microseconds after our ATQA and a single
    // RSSI conversion is long enough to miss it. This is the same call the
    // MIFARE Classic simulation uses.
    bool field_on = true;
    desfire_sim_pstate_t pstate = DESF_IDLE;
    uint32_t idle_counter = 0;

    for (;;) {

        WDT_HIT();

        // Watch for the client asking us to stop, in this loop rather than
        // relying on the one inside EmGetCmd(). With no field EmGetCmd()
        // returns "field off" after 4 ms, which is long before its own check
        // fires at 3 * 4000 iterations -- so a simulation sitting in front of
        // no reader would never see CMD_BREAK_LOOP, and the device would stay
        // in this loop after the client had gone. Same shape as Mifare1ksim.
        if (idle_counter >= 1000) {
            idle_counter = 0;
            if (data_available()) {
                retval = PM3_EOPABORTED;
                break;
            }
        } else {
            idle_counter++;
        }

        if (BUTTON_PRESS()) {
            retval = PM3_EOPABORTED;
            break;
        }

        uint16_t len = 0;
        int res = EmGetCmd(receivedCmd, sizeof(receivedCmd), &len, receivedCmdPar);

        if (res == 2) {
            // the reader took its field away, so the PICC lost power
            if (field_on) {
                field_on = false;
                pstate = DESF_NOFIELD;
                desfire_sim_reset();
                LED_A_OFF();
                if (g_dbglevel >= DBG_EXTENDED) {
                    DbpString("DESFire sim: field lost, PICC powered down");
                }
            }
            continue;

        } else if (res == 1) {

            if (g_dbglevel >= DBG_EXTENDED) {
                Dbprintf("Button pressed");
            }
            retval = PM3_EOPABORTED;
            break;
        }

        if (field_on == false) {
            field_on = true;
            pstate = DESF_IDLE;
            LED_A_ON();
        }

        if (len == 0) {
            continue;
        }

        cmdcount++;

        // ---- ISO/IEC 14443-3 activation ----
        //
        // Answer first, then do the bookkeeping. The frame delay time for a
        // REQA/WUPA answer is fixed by the standard at 1172 or 1236 carrier
        // periods and a reader rejects anything else, so nothing may sit
        // between receiving the frame and sending the precompiled reply --
        // clearing the session alone costs enough to miss the window. This is
        // the shape Mifare1ksim uses.
        //
        // Each frame is also only honoured in the state that allows it, so a
        // half finished cascade is never answered as though it had completed.

        // REQA and WUPA are 7 bit frames. WUPA wakes a halted card, REQA does
        // not -- that distinction is the whole point of having two of them.
        if (len == 1 && (receivedCmd[0] == ISO14443A_CMD_WUPA ||
                         (receivedCmd[0] == ISO14443A_CMD_REQA && pstate != DESF_HALTED))) {

            EmSendPrecompiledCmd(&responses[RESP_INDEX_ATQA]);
            desfire_sim_reset();        // a fresh activation reselects the PICC
            pstate = DESF_READY1;
            continue;
        }

        if (len == 2 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && receivedCmd[1] == 0x20
                && pstate == DESF_READY1) {
            EmSendPrecompiledCmd(&responses[RESP_INDEX_UIDC1]);
            continue;
        }

        if (len == 9 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT && receivedCmd[1] == 0x70
                && pstate == DESF_READY1) {

            // a card only answers a SELECT that carries its own UID
            if (memcmp(receivedCmd + 2, responses[RESP_INDEX_UIDC1].response, 4) != 0) {
                continue;
            }
            EmSendPrecompiledCmd(&responses[RESP_INDEX_SAKC1]);
            // a 7 or 10 byte UID needs another cascade level, a 4 byte one is done
            pstate = (uidlen > 4) ? DESF_READY2 : DESF_ACTIVE;
            continue;
        }

        if (len == 2 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && receivedCmd[1] == 0x20
                && pstate == DESF_READY2) {
            EmSendPrecompiledCmd(&responses[RESP_INDEX_UIDC2]);
            continue;
        }

        if (len == 9 && receivedCmd[0] == ISO14443A_CMD_ANTICOLL_OR_SELECT_2 && receivedCmd[1] == 0x70
                && pstate == DESF_READY2) {

            if (memcmp(receivedCmd + 2, responses[RESP_INDEX_UIDC2].response, 4) != 0) {
                continue;
            }
            EmSendPrecompiledCmd(&responses[RESP_INDEX_SAKC2]);
            pstate = DESF_ACTIVE;
            continue;
        }

        if (len == 4 && receivedCmd[0] == ISO14443A_CMD_RATS && pstate == DESF_ACTIVE) {
            EmSendPrecompiledCmd(&responses[RESP_INDEX_ATS]);
            pstate = DESF_ISO4;
            continue;
        }

        if (receivedCmd[0] == ISO14443A_CMD_PPS && pstate == DESF_ISO4) {
            EmSendPrecompiledCmd(&responses[RESP_INDEX_PPS]);
            continue;
        }

        if (len == 4 && receivedCmd[0] == ISO14443A_CMD_HALT) {
            desfire_sim_reset();
            pstate = DESF_HALTED;
            continue;                   // a halted tag says nothing
        }

        if (pstate != DESF_ISO4) {
            // nothing below here is legal until RATS has been answered
            if (g_dbglevel >= DBG_EXTENDED) {
                Dbprintf("DESFire sim: frame ignored in state %u, %d bytes", pstate, len);
            }
            continue;
        }

        // ---- ISO/IEC 14443-4 ----
        if ((receivedCmd[0] & PCB_TYPE_MASK) == PCB_TYPE_S) {

            if (receivedCmd[0] == PCB_S_DESELECT) {
                uint8_t r[3] = { PCB_S_DESELECT, 0, 0 };
                AddCrc14A(r, 1);
                EmSendCmd(r, sizeof(r));
                desfire_sim_reset();
                pstate = DESF_ACTIVE;   // out of 14443-4, RATS would be needed again
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
    }

    if (g_dbglevel >= DBG_ERROR) {
        Dbprintf("Emulator stopped. Trace length: %d", BigBuf_get_traceLen());
    }
    if (g_dbglevel >= DBG_EXTENDED) {
        Dbprintf("-[ commands received %u ]-", cmdcount);
    }

    switch_off();
    set_tracing(false);
    BigBuf_free_keep_EM();

    reply_ng(CMD_HF_DESFIRE_SIMULATE, retval, NULL, 0);
}
