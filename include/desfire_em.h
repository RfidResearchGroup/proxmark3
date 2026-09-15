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
// DESFire card image, as it lives in emulator memory.
//
// The client packs a desfire_dump_t (see client/src/fileutils.h, and
// doc/mfdes_dump_format.md for the json it comes from) into this layout and
// uploads it with eload.  The device simulation reads it, and writes back into
// it -- a reader that writes to the simulated card changes this image, so an
// esave afterwards shows what the reader did.  That is the difference between
// an emulator and a replay rig.
//
// Layout, inside the CARD_MEMORY_SIZE region:
//
//      0   +---------------------------+
//          |  desfire_em_hdr_t         |   fixed
//          +---------------------------+
//          |  desfire_em_app_t   []    |   appcount entries
//          |  desfire_em_file_t  []    |   filecount entries   grows up
//          |  desfire_em_key_t   []    |   keycount entries
//   tables_end
//          |                           |
//          |  ..... free .....         |   <- the emulated card's free memory
//          |                           |
//   data_start
//          |  file data regions        |   grows down
//    size  +---------------------------+
//
// Two frontiers rather than fixed-size tables: a card with three files spends a
// few hundred bytes, not the worst case.  Tables append as the reader creates
// applications and files; a data region is reserved when a file is created and
// never moves afterwards, so WriteData and WriteRecord are pure writes.  The
// only allocation check anywhere is tables_end < data_start, and the space
// between them is what GetFreeMem reports -- so the simulated card fills up and
// refuses with OUT_OF_EEPROM the way a real one does.
//
// Nothing here knows how big emulator memory is.  The device reports that to the
// client in capabilities_t, and a platform with more of it holds a bigger card
// with no change to this format.
//-----------------------------------------------------------------------------

#ifndef __DESFIRE_EM_H
#define __DESFIRE_EM_H

#include "common.h"
#include "desfire.h"

#define DESFIRE_EM_MAGIC            0x31534544  // "DES1", little endian
#define DESFIRE_EM_LAYOUT_VERSION   1

// Allocation granule.  A genuine DESFire rounds NV consumption to 32 bytes:
// measured on a DESFire EV2 2K, a 1 byte file costs 32 and a 33 byte file costs
// 64.  Rounding the same way keeps GetFreeMem card-shaped.  Note the rounding is
// invisible to a reader otherwise -- GetFileSettings reports the size the file
// was created with, also measured.
// PICC configuration, set by SetConfiguration option 0x00 and kept in hdr.flags.
// Both are one way on a card -- "cannot be reset" -- and the bit positions are
// the config byte's own, so the byte is stored as it arrives.
#define DESFIRE_EM_PICC_NO_FORMAT   (1 << 0)    // FormatPICC refused from here on
#define DESFIRE_EM_PICC_RANDOM_UID  (1 << 1)    // anticollision shows a random id

#define DESFIRE_EM_GRANULE          32
#define DESFIRE_EM_ROUNDUP(x)       (((x) + (DESFIRE_EM_GRANULE - 1)) & ~(DESFIRE_EM_GRANULE - 1))

// NV an application costs before its keys.  Measured on a DESFire EV2 2K: an
// application with one key costs 96 bytes, with fourteen keys 352.  64 plus the
// key material reproduces the first exactly and the second about 18% low, which
// is close enough for a free-memory figure that only has to look card-shaped --
// see the note on not reproducing NXP's allocator, below.
#define DESFIRE_EM_APP_OVERHEAD     64

// EV1 hard limits.  28 applications is the PICC's own, reported as COUNT_ERROR
// 0xCE; 32 files and 14 keys follow the file/key number ranges 0x00..0x1F and
// 0x00..0x0D.  These bound the tables; what actually fits is decided by the
// frontiers, not by these.
#define DESFIRE_EM_MAX_APPS         28
#define DESFIRE_EM_MAX_FILES        32
#define DESFIRE_EM_MAX_KEYS         DESFIRE_MAX_KEY_COUNT

// Which generation the image impersonates.  The simulation answers a different
// command set for each, so it is stored rather than re-derived from the version
// bytes at run time.  Identification bytes are versionhw[3] and [4]: EV1 is
// 01 00, EV2 12 00 or 42 00, EV2 XL 22 00, EV3 33 00, DuoX A0 00.
typedef enum {
    DESFIRE_EM_GEN_UNKNOWN = 0,
    DESFIRE_EM_GEN_D40     = 1,
    DESFIRE_EM_GEN_EV1     = 2,
    DESFIRE_EM_GEN_EV2     = 3,
    DESFIRE_EM_GEN_EV3     = 4,
    DESFIRE_EM_GEN_LIGHT   = 5,
    DESFIRE_EM_GEN_DUOX    = 6,
} desfire_em_gen_t;

typedef struct {
    uint32_t magic;             // DESFIRE_EM_MAGIC
    uint8_t  layout;            // DESFIRE_EM_LAYOUT_VERSION
    uint8_t  generation;        // desfire_em_gen_t
    uint8_t  flags;             // desfire_em_picc_flags_t
    uint8_t  rfu0;

    // card identity, straight from the dump
    uint8_t  uid[10];
    uint8_t  uidlen;
    uint8_t  atqa[2];
    uint8_t  sak;
    uint8_t  atslen;
    uint8_t  ats[20];

    // GetVersion answers over three chained frames and they are not the same
    // shape across generations, so each is kept raw
    uint8_t  versionhw[7];
    uint8_t  versionhwlen;
    uint8_t  versionsw[7];
    uint8_t  versionswlen;
    uint8_t  versionprod[14];
    uint8_t  versionprodlen;

    uint8_t  signature[56];     // NXP originality signature
    uint8_t  signaturelen;
    uint8_t  rfu1;

    // app[0] is the PICC, AID 000000.  It holds the PICC master key settings and
    // keys and never has files, the same way the json format stores it.
    uint8_t  appcount;
    uint8_t  filecount;
    uint8_t  keycount;
    uint8_t  rfu2;

    uint16_t app_off;           // byte offsets from the start of the image
    uint16_t file_off;
    uint16_t key_off;

    // the two frontiers.  tables grow up to tables_end, file data down from
    // data_start, and an allocation only has to leave them apart
    uint16_t tables_end;
    uint16_t data_start;
    uint16_t size;              // bytes of emulator memory this image may use

    // Two different limits, and a reader must only ever see the first.
    //
    // cardsize is the NV the emulated card claims to have, so GetFreeMem
    // answers cardsize - reserved and CreateFile refuses with OUT_OF_EEPROM
    // once that runs out.  Without it a card impersonating a 2K part would
    // report several kB free, which no 2K part does.
    //
    // size is what emulator memory physically holds, and is the harder limit
    // of the two.  It is never visible to a reader.
    uint16_t cardsize;
    uint16_t reserved;          // NV the card has spent, against cardsize
} PACKED desfire_em_hdr_t;

// ---------------------------------------------------------------- application

#define DESFIRE_EM_APP_DELETED      (1 << 0)    // tombstone, see below
#define DESFIRE_EM_APP_AUTHED       (1 << 1)    // dump ran authenticated here
#define DESFIRE_EM_APP_ISOFIDS      (1 << 2)    // application uses ISO file ids

typedef struct {
    uint8_t  aid[3];
    uint8_t  flags;
    uint8_t  keysettings;
    uint8_t  numkeysraw;        // key type in bits 6-7, iso-fid flag bit 5, count 0-4
    uint16_t isofid;            // 0 = none
    uint8_t  dfname[16];
    uint8_t  dfnamelen;
    uint8_t  keytype;           // DesfireCryptoAlgorithm, one per application
} PACKED desfire_em_app_t;

// ----------------------------------------------------------------------- file

// flags bits 0-1 carry the raw 2-bit file communication mode, not a
// DesfireCommunicationMode.  Use DesfireFileCommModeToCommMode() to convert.
#define DESFIRE_EM_FILE_COMM_MASK   0x03
#define DESFIRE_EM_FILE_UNKNOWN     (1 << 2)    // contents were never read, see below
#define DESFIRE_EM_FILE_LIMCREDIT   (1 << 3)    // value file, LimitedCredit enabled
#define DESFIRE_EM_FILE_FREEGETVAL  (1 << 4)    // value file, free GetValue
#define DESFIRE_EM_FILE_DELETED     (1 << 5)    // tombstone
#define DESFIRE_EM_FILE_DIRTY       (1 << 6)    // uncommitted writes live in the shadow

typedef struct {
    uint8_t  app;               // index into the application table
    uint8_t  num;               // file number 0x00..0x1F
    uint8_t  type;              // raw file type byte, 0x00..0x04 for EV1
    uint8_t  flags;
    uint16_t isofid;            // 0 = none
    uint16_t rights;            // raw access rights word

    uint16_t dataoff;           // offset of the committed region
    uint16_t datalen;           // bytes reserved for it

    // CommitTransaction covers backup data, value and record files; a standard
    // data file writes straight through.  For the three that are covered,
    // shadow_off is a second region of datalen bytes that writes land in until
    // CommitTransaction swaps them, or AbortTransaction discards them.  Zero
    // for standard data files.
    uint16_t shadow_off;

    union {
        struct {                // 0x00 standard, 0x01 backup
            uint32_t size;      // as created, NOT rounded -- GetFileSettings
        } data;                 // reports this verbatim, measured
        struct {                // 0x02 value
            uint32_t lower;
            uint32_t upper;
            uint32_t value;
        } value;
        struct {                // 0x03 linear, 0x04 cyclic
            uint32_t recordsize;
            uint32_t maxrecords;    // as created.  A cyclic file stores one
            uint32_t currecords;    // fewer than this, the backup mechanism
        } record;                   // consumes one -- EV1 spec 9.5.9
    } u;
} PACKED desfire_em_file_t;

// ------------------------------------------------------------------------ key

// The key algorithm is the application's, so it is not repeated here.  A key
// version is readable without knowing the key, so the two are tracked apart: a
// version with no value is the normal shape for a key that was found but never
// recovered, and the simulation must refuse an authentication against it rather
// than authenticate with zeros.
#define DESFIRE_EM_KEY_PRESENT      (1 << 0)    // we hold the key value
#define DESFIRE_EM_KEY_VERKNOWN     (1 << 1)    // we read the key version

typedef struct {
    uint8_t  app;               // index into the application table
    uint8_t  num;               // key number
    uint8_t  flags;
    uint8_t  ver;
    uint8_t  key[DESFIRE_MAX_KEY_SIZE];
} PACKED desfire_em_key_t;

//-----------------------------------------------------------------------------
// Notes for whoever implements against this
//
// Tombstones, not compaction.  DeleteFile and DeleteApplication set a flag and
// leave the space stranded.  That is not a shortcut: a genuine card does not
// give the memory back either.  Measured on a DESFire EV2 2K -- 2080 bytes free
// with zero applications before an experiment, 2560 after FormatPICC.  Only
// FormatPICC reclaims, and here that is resetting both frontiers.
//
// The unknown flag.  A file whose contents could not be read carries
// DESFIRE_EM_FILE_UNKNOWN and its region is reserved but meaningless.  The
// simulation must answer an error for it, never zeros.  "8 bytes of 00" and "we
// could not read 8 bytes" are different facts and a card image that confuses
// them lies to the reader.
//
// Reservation at CreateFile, in granules:
//      standard        DESFIRE_EM_ROUNDUP(size)
//      backup          DESFIRE_EM_ROUNDUP(size) twice, data and shadow
//      value           one granule twice
//      record          DESFIRE_EM_ROUNDUP(recordsize * maxrecords) twice
// Reserve the full declared extent, not just the records that exist, so
// WriteRecord never has to grow anything.  The json stores only the records
// that exist; eload expands, esave compacts.
//
// This deliberately does not reproduce NXP's own allocator.  It is undocumented
// and the numbers do not fit a simple model -- a declared 1024 byte record file
// costs 1088 on real silicon, neither 1x nor 2x.  What matters is that
// GetFreeMem is self-consistent and shrinks as the reader writes.
//
// Card capacity.  The GetVersion storage size byte codes 2^(n>>1) bytes, but
// that understates what the part actually hands out: a DESFire EV2 2K reports
// storage 0x16, 2048 bytes, and 2560 bytes free when formatted -- measured.  So
// the nominal figure is a floor, not the capacity, and cardsize is set to
// whichever is larger of the nominal figure and what the image already holds.
// A dump taken from a real card therefore always fits the card it came from.
//
// Response timing.  Everything from SelectApplication onward sits behind the
// ISO14443-4 frame waiting time, which the EV1 ATS sets to FWI 8, 77.33 ms --
// about 3.7 million ARM cycles at MCK.  A software AES block is well under a
// microsecond of that, so responses are computed on demand from this image
// rather than precompiled.  The pre-RATS layer is the opposite: ATQA, SAK and
// ATS have no such slack and must be precompiled, as the 14a simulation already
// does.
//-----------------------------------------------------------------------------

#endif // __DESFIRE_EM_H
