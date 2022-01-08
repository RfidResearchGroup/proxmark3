/**
 * Matt Moran (@DarkMatterMatt), 2021
 * -----------------------------------------------------------------------------
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * -----------------------------------------------------------------------------
 * High frequency GALLAGHER tag commands.
 * MIFARE DESFire, AIDs 2081F4-2F81F4
 */
#ifndef CMDHFGALLAGHER_H__
#define CMDHFGALLAGHER_H__

#include "common.h"
#include <stdint.h>

int CmdHFGallagher(const char *cmd);

/**
 * @brief Create Gallagher Application Master Key by diversifying
 * the MIFARE Site Key with card UID, key number, and application ID.
 *
 * @param sitekey MIFARE Site Key (16 bytes).
 * @param uid Card unique ID (4 or 7 bytes).
 * @param uidLen Length of UID.
 * @param keyNum Key number (0 <= keyNum <= 2).
 * @param aid Application ID (0x2?81F4 where 0 <= ? <= B).
 * @param keyOut Buffer to copy the diversified key into (must be 16 bytes).
 * @return PM3_SUCCESS if successful, PM3_EINVARG if an argument is invalid.
 */
int hfgal_diversify_key(uint8_t *site_key, uint8_t *uid, uint8_t uid_len,
                        uint8_t key_num, uint32_t aid, uint8_t *key_output);

// Return error
#define HFGAL_RET_ERR(err, ...)  { PrintAndLogEx(ERR, __VA_ARGS__); return err; }

// HF GALlagher RETurn IF ERRor
#define HFGAL_RET_IF_ERR(res)                          if (res != PM3_SUCCESS) {                                               return res; }
#define HFGAL_RET_IF_ERR_WITH_MSG(res, ...)            if (res != PM3_SUCCESS) {              PrintAndLogEx(ERR, __VA_ARGS__); return res; }
#define HFGAL_RET_IF_ERR_MAYBE_MSG(res, verbose, ...)  if (res != PM3_SUCCESS) { if (verbose) PrintAndLogEx(ERR, __VA_ARGS__); return res; }

// The response code when an invalid key is used for authentication
// Returned in /client/src/mifare/desfirecore.c, line 1185 (if DesfireExchangeEx fails)
#define HFGAL_AUTH_FAIL 7

#endif
