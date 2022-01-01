/**
 * Matt Moran (@DarkMatterMatt), 2021
 * -----------------------------------------------------------------------------
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * -----------------------------------------------------------------------------
 * High frequency GALLAGHER tag commands.
 * MIFARE DESFire, AIDs 2081F4-2F81F4
 */
#ifndef CMDHFGALLAGHER_H__
#define CMDHFGALLAGHER_H__

#include "common.h"

int CmdHFGallagher(const char *Cmd);

#define HF_GALLAGHER_RETURN_IF_ERROR(res) if (res != PM3_SUCCESS) { return res; }
#define HF_GALLAGHER_FAIL_IF_ERROR(res, verbose, reason) if (res != PM3_SUCCESS) { if (verbose) PrintAndLogEx(ERR, reason " Error code %d", res); DropField(); return res; }

#endif
