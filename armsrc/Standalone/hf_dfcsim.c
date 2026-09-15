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

#include "standalone.h"

#include "BigBuf.h"
#include "appmain.h"
#include "dbprint.h"
#include "desfiresim.h"
#include "dfc_credential.h"
#include "dfc_der.h"
#include "dfc_port_pm3.h"
#include "fpga_loader.h"
#include "gpio_apis.h"
#include "iso14443a.h"
#include "proxmark3_arm.h"
#include "spiffs.h"
#include "util.h"
#include "wdt_apis.h"

#include <string.h>

#define DFC_FILE "hf_dfcsim.dfcb"
#define DFC_TEMP "hf_dfcsim.tmp"
#define DFC_BACKUP "hf_dfcsim.bak"

static bool load_credential(void) {
    if (!exists_in_spiffs(DFC_FILE)) {
        Dbprintf(_RED_("Missing %s"), DFC_FILE);
        return false;
    }
    uint32_t length = size_in_spiffs(DFC_FILE);
    if (length == 0 || length > BigBuf_get_EM_size()) {
        Dbprintf(_RED_("Invalid %s size: %u"), DFC_FILE, length);
        return false;
    }
    uint8_t *memory = BigBuf_get_EM_addr();
    if (memory == NULL) {
        DbpString(_RED_("Not enough emulator memory for DFCB"));
        return false;
    }
    memset(memory, 0, BigBuf_get_EM_size());
    rdv40_spiffs_read_as_filetype(DFC_FILE, memory, length, RDV40_SPIFFS_SAFETY_SAFE);
    if (dfc_der_length(memory, length) != length) {
        Dbprintf(_RED_("Invalid DFCB encoding in %s"), DFC_FILE);
        return false;
    }
    return true;
}

static bool remove_if_present(const char *filename) {
    return !exists_in_spiffs(filename) ||
           rdv40_spiffs_remove(filename, RDV40_SPIFFS_SAFETY_SAFE) == 0;
}

static bool save_credential(void) {
    uint8_t *memory = BigBuf_get_EM_addr();
    size_t length = dfc_der_length(memory, BigBuf_get_EM_size());
    if (length == 0) return false;

    if (!remove_if_present(DFC_TEMP)) return false;
    if (rdv40_spiffs_write(DFC_TEMP, memory, length, RDV40_SPIFFS_SAFETY_SAFE) != 0) return false;
    if (!remove_if_present(DFC_BACKUP)) return false;
    if (exists_in_spiffs(DFC_FILE) &&
            rdv40_spiffs_rename(DFC_FILE, DFC_BACKUP, RDV40_SPIFFS_SAFETY_SAFE) != 0) {
        return false;
    }
    if (rdv40_spiffs_rename(DFC_TEMP, DFC_FILE, RDV40_SPIFFS_SAFETY_SAFE) != 0) {
        if (exists_in_spiffs(DFC_BACKUP)) {
            rdv40_spiffs_rename(DFC_BACKUP, DFC_FILE, RDV40_SPIFFS_SAFETY_SAFE);
        }
        return false;
    }
    return remove_if_present(DFC_BACKUP);
}

static bool create_credential(void) {
    DfcCredential *credential = (DfcCredential *)BigBuf_calloc(sizeof(*credential));
    if (credential == NULL) return false;
    dfc_pm3_random_clear();
    dfc_credential_init_factory(credential);
#if DFC_ENABLE_GENERATION_EV3
    credential->card.generation = DfcGenerationEv3;
#elif DFC_ENABLE_GENERATION_EV2
    credential->card.generation = DfcGenerationEv2;
#endif
    size_t length = 0;
    DfcDerStatus status = dfc_der_encode(
                             credential, BigBuf_get_EM_addr(), BigBuf_get_EM_size(), &length);
    memset(credential, 0, sizeof(*credential));
    BigBuf_free_keep_EM();
    if (status != DfcDerOk || !save_credential()) {
        DbpString(_RED_("Could not create factory credential"));
        return false;
    }
    Dbprintf("Created factory credential in %s", DFC_FILE);
    return true;
}

void ModInfo(void) {
    DbpString("  HF DESFire DFCB simulator");
}

void RunMod(void) {
    StandAloneMode();

    // A client-started standalone run may inherit allocated emulator memory.
    // Release it before FPGA decompression; the DFCB is reloaded from SPIFFS.
    BigBuf_free();
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    BigBuf_Clear_ext(false);
    BigBuf_get_EM_addr();
    rdv40_spiffs_lazy_mount();

    bool loaded = exists_in_spiffs(DFC_FILE) ? load_credential() : create_credential();
    if (!loaded || !desfire_sim_init()) {
        rdv40_spiffs_lazy_unmount();
        BigBuf_Clear_ext(false);
        BigBuf_free();
        SpinErr(5, 200, 2);
        return;
    }

    Dbprintf(_YELLOW_("DESFire standalone simulator started"));
    Dbprintf("Hold the button for 500 ms, or connect over USB, to save and exit");
    for (;;) {
        uint16_t flags = 0;
        FLAG_SET_UID_IN_EMUL(flags);
        SimulateIso14443aTag(3, flags, NULL, 0);
        if (data_available() || BUTTON_HELD(500) == BUTTON_HOLD) break;
        while (BUTTON_PRESS()) WDT_HIT();
    }

    if (save_credential()) {
        Dbprintf(_GREEN_("Saved %s"), DFC_FILE);
    } else {
        Dbprintf(_RED_("Could not save %s"), DFC_FILE);
        SpinErr(5, 200, 2);
    }
    desfire_sim_deinit(false);
    rdv40_spiffs_lazy_unmount();
}
