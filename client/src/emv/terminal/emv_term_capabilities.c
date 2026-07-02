//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_capabilities.h"
#include "cmdparser.h"
#include "comms.h"
#include "ui.h"

int emv_term_capabilities_print(void) {
    PrintAndLogEx(INFO, "--- EMV terminal capabilities ---");

    if (IfPm3Present()) {
        if (g_pm3_capabilities.is_rdv4) {
            PrintAndLogEx(INFO, "Device: PM3 RDV4");
        } else {
            PrintAndLogEx(INFO, "Device: PM3GENERIC (connected)");
        }
        if (IfPm3Flash()) {
            PrintAndLogEx(INFO, "Flash: yes");
        } else {
            PrintAndLogEx(INFO, "Flash: no / not queried");
        }
    } else {
        PrintAndLogEx(INFO, "Device: offline / no PM3 (static build flags)");
    }

    PrintAndLogEx(INFO, "ISO14443-A: %s", IfPm3Iso14443a() ? "yes" : "no (offline)");
    PrintAndLogEx(INFO, "ISO14443-B: %s", IfPm3Iso14443b() ? "yes" : "no (offline)");
    PrintAndLogEx(INFO, "Smartcard mod: %s", IfPm3Smartcard() ? "yes" : "no");
    PrintAndLogEx(INFO, "Recommended: emv terminal run -j --profile auto");
    PrintAndLogEx(INFO, "Mock replay: emv terminal replay mock_apdu.json --from-phase cvm");
    return PM3_SUCCESS;
}
