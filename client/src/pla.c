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
// Polling Loop Annotations (PLA) and Enhanced Contactless Polling (ECP) utilities
//-----------------------------------------------------------------------------

#include "pla.h"
#include <string.h>
#include <stdlib.h>
#include "ui.h"
#include "util.h"
#include "fileutils.h"

// Load ecplist.json file
json_t *pla_load_ecplist(void) {
    json_error_t error;
    char *path;

    int res = searchFile(&path, RESOURCES_SUBDIR, "ecplist", ".json", false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Cannot find ecplist.json");
        return NULL;
    }

    json_t *root = json_load_file(path, 0, &error);
    free(path);

    if (!root) {
        PrintAndLogEx(ERR, "json error on line %d: %s", error.line, error.text);
        return NULL;
    }

    if (!json_is_array(root)) {
        PrintAndLogEx(ERR, "Invalid ecplist.json format. Root must be an array.");
        json_decref(root);
        return NULL;
    }

    return root;
}

// Search ecplist for an entry matching the given type, subtype and/or key
json_t *pla_search_ecplist_by_key(json_t *root, const char *type, const char *subtype, const char *key) {
    size_t index;
    json_t *entry;

    json_array_foreach(root, index, entry) {
        // If type filter is specified, check if entry has matching type
        if (type != NULL) {
            json_t *type_obj = json_object_get(entry, "type");
            if (!type_obj) {
                continue; // Skip entries without type field
            }

            bool type_matched = false;
            if (json_is_string(type_obj)) {
                const char *type_str = json_string_value(type_obj);
                if (type_str && strcmp(type_str, type) == 0) {
                    type_matched = true;
                }
            } else if (json_is_array(type_obj)) {
                size_t type_index;
                json_t *type_value;
                json_array_foreach(type_obj, type_index, type_value) {
                    const char *type_str = json_string_value(type_value);
                    if (type_str && strcmp(type_str, type) == 0) {
                        type_matched = true;
                        break;
                    }
                }
            }

            if (!type_matched) {
                continue; // Type doesn't match
            }
        } else {
            // If no type filter, skip entries that have a type field
            if (json_object_get(entry, "type")) {
                continue;
            }
        }

        bool key_matched = (key == NULL); // If no key specified, consider it matched
        bool subtype_matched = (subtype == NULL); // If no subtype specified, consider it matched

        // Check if the subtype matches the "subtype" field (string or array)
        if (subtype != NULL) {
            json_t *subtype_obj = json_object_get(entry, "subtype");
            if (subtype_obj) {
                if (json_is_string(subtype_obj)) {
                    const char *subtype_str = json_string_value(subtype_obj);
                    if (subtype_str && strcmp(subtype_str, subtype) == 0) {
                        subtype_matched = true;
                    }
                } else if (json_is_array(subtype_obj)) {
                    size_t subtype_index;
                    json_t *subtype_value;
                    json_array_foreach(subtype_obj, subtype_index, subtype_value) {
                        const char *subtype_str = json_string_value(subtype_value);
                        if (subtype_str && strcmp(subtype_str, subtype) == 0) {
                            subtype_matched = true;
                            break;
                        }
                    }
                }
            }
        }

        // Check if the key matches the "key" field (string or array)
        if (key != NULL) {
            json_t *key_obj = json_object_get(entry, "key");
            if (key_obj) {
                if (json_is_string(key_obj)) {
                    const char *key_str = json_string_value(key_obj);
                    if (key_str && strcmp(key_str, key) == 0) {
                        key_matched = true;
                    }
                } else if (json_is_array(key_obj)) {
                    size_t key_index;
                    json_t *key_value;
                    json_array_foreach(key_obj, key_index, key_value) {
                        const char *key_str = json_string_value(key_value);
                        if (key_str && strcmp(key_str, key) == 0) {
                            key_matched = true;
                            break;
                        }
                    }
                }
            }
        }

        // Entry must match both key and subtype criteria (if specified)
        if (key_matched && subtype_matched) {
            return entry;
        }
    }

    return NULL; // Not found
}

// Parse ECP (Enhanced Contactless Polling) subcommands
// Returns the length of the generated frame (without CRC), or -1 on error
int pla_parse_ecp_subcommand(const char *cmd, uint8_t *frame, size_t frame_size) {
    if (cmd == NULL || frame == NULL || frame_size < 22) {
        return -1;
    }

    // Make a mutable copy of the command and replace dots/colons with spaces
    char *cmd_copy = strdup(cmd);
    if (!cmd_copy) {
        return -1;
    }

    for (char *p_char = cmd_copy; *p_char != '\0'; p_char++) {
        if (*p_char == '.' || *p_char == ':') {
            *p_char = ' ';
        }
    }

    // Load ecplist.json
    json_t *ecplist = pla_load_ecplist();
    if (!ecplist) {
        PrintAndLogEx(ERR, "Failed to load ecplist.json");
        free(cmd_copy);
        return -1;
    }

    // Skip "ecp" prefix and any whitespace
    const char *p = cmd_copy;
    if (strncmp(p, "ecp", 3) == 0) {
        p += 3;
    }
    while (*p == ' ' || *p == '\t') {
        p++;
    }

    int result = -1;
    const char *type = NULL;
    const char *search_term = p;

    // Check if first term is a type ("transit" or "access")
    if (strncmp(p, "transit", 7) == 0) {
        type = "transit";
        p += 7;
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        search_term = p;

        // If second term provided, search by key in transit entries
        if (*p != '\0') {
            json_t *entry = pla_search_ecplist_by_key(ecplist, type, NULL, search_term);
            if (entry) {
                // Found matching entry, use its value
                json_t *value_obj = json_object_get(entry, "value");
                if (value_obj) {
                    const char *hex_str = json_string_value(value_obj);
                    if (hex_str) {
                        size_t hex_len = strlen(hex_str);
                        if (hex_len % 2 == 0 && hex_len <= frame_size * 2) {
                            for (size_t i = 0; i < hex_len / 2; i++) {
                                sscanf(hex_str + i * 2, "%2hhx", &frame[i]);
                            }
                            result = hex_len / 2;
                        }
                    }
                }
            }

            // If not found, try interpreting as hex TCI
            if (result == -1) {
                char *endptr;
                uint32_t tci = strtoul(search_term, &endptr, 16);
                if (search_term != endptr) {
                    // Build frame: 6a02c801000300{tci as 3 bytes}0000000000
                    frame[0] = 0x6a;
                    frame[1] = 0x02;
                    frame[2] = 0xc8;
                    frame[3] = 0x01;
                    frame[4] = 0x00;
                    frame[5] = (tci >> 16) & 0xff;
                    frame[6] = (tci >> 8) & 0xff;
                    frame[7] = tci & 0xff;
                    frame[8] = 0x00;
                    frame[9] = 0x00;
                    frame[10] = 0x00;
                    frame[11] = 0x00;
                    frame[12] = 0x00;
                    result = 13;
                } else {
                    PrintAndLogEx(ERR, "Unknown transit key or invalid TCI: %s", search_term);
                }
            }
        } else {
            PrintAndLogEx(ERR, "Transit type requires a key or TCI value");
        }

    } else if (strncmp(p, "access", 6) == 0) {
        type = "access";
        p += 6;
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        // Parse second term
        const char *second_term = p;

        // Skip to end of second term
        while (*p != '\0' && *p != ' ' && *p != '\t') {
            p++;
        }

        // Extract second term
        size_t second_term_len = p - second_term;
        char *second = NULL;
        if (second_term_len > 0) {
            second = str_ndup(second_term, second_term_len);
        }

        // Skip whitespace
        while (*p == ' ' || *p == '\t') {
            p++;
        }

        // Parse third term if present
        const char *third_term = p;
        char *third = NULL;
        if (*p != '\0') {
            // Skip to end of third term
            while (*p != '\0' && *p != ' ' && *p != '\t') {
                p++;
            }
            size_t third_term_len = p - third_term;
            if (third_term_len > 0) {
                third = str_ndup(third_term, third_term_len);
            }
        }

        // Default TCI is 02ffff if not provided
        uint32_t tci = 0x02ffff;

        // If terms provided, try to parse them
        if (second != NULL && *second != '\0') {
            json_t *entry = NULL;

            if (third != NULL && *third != '\0') {
                // Two terms: second is subtype, third is key
                entry = pla_search_ecplist_by_key(ecplist, type, second, third);
            } else {
                // One term: try as subtype first, then as key
                entry = pla_search_ecplist_by_key(ecplist, type, second, NULL);

                if (!entry) {
                    entry = pla_search_ecplist_by_key(ecplist, type, NULL, second);
                }
            }

            if (entry) {
                // Found matching entry, use its value
                json_t *value_obj = json_object_get(entry, "value");
                if (value_obj) {
                    const char *hex_str = json_string_value(value_obj);
                    if (hex_str) {
                        size_t hex_len = strlen(hex_str);
                        if (hex_len % 2 == 0 && hex_len <= frame_size * 2) {
                            for (size_t i = 0; i < hex_len / 2; i++) {
                                sscanf(hex_str + i * 2, "%2hhx", &frame[i]);
                            }
                            result = hex_len / 2;
                        }
                    }
                }
            }

            // If not found and no third term, try interpreting second term as hex TCI
            if (result == -1 && third == NULL) {
                char *endptr;
                tci = strtoul(second, &endptr, 16);
                if (second == endptr) {
                    PrintAndLogEx(ERR, "Unknown access subtype/key or invalid TCI: %s", second);
                    free(second);
                    if (third) free(third);
                    json_decref(ecplist);
                    free(cmd_copy);
                    return -1;
                }
            } else if (result == -1 && third != NULL) {
                PrintAndLogEx(ERR, "No matching access entry for subtype '%s' and key '%s'", second, third);
                free(second);
                free(third);
                json_decref(ecplist);
                free(cmd_copy);
                return -1;
            }
        }

        if (second) {
            free(second);
        }
        if (third) {
            free(third);
        }

        // Build frame with TCI if we didn't find a matching entry
        if (result == -1) {
            // Build frame: 6a02c30200{tci as 3 bytes}
            frame[0] = 0x6a;
            frame[1] = 0x02;
            frame[2] = 0xc3;
            frame[3] = 0x02;
            frame[4] = 0x00;
            frame[5] = (tci >> 16) & 0xff;
            frame[6] = (tci >> 8) & 0xff;
            frame[7] = tci & 0xff;
            result = 8;
        }

    } else {
        // No type specified, search for entries without type field by key
        json_t *entry = pla_search_ecplist_by_key(ecplist, search_term, NULL, NULL);
        if (entry) {
            json_t *value_obj = json_object_get(entry, "value");
            if (value_obj) {
                const char *hex_str = json_string_value(value_obj);
                if (hex_str) {
                    size_t hex_len = strlen(hex_str);
                    if (hex_len % 2 == 0 && hex_len <= frame_size * 2) {
                        for (size_t i = 0; i < hex_len / 2; i++) {
                            sscanf(hex_str + i * 2, "%2hhx", &frame[i]);
                        }
                        result = hex_len / 2;
                    }
                }
            }
        } else {
            PrintAndLogEx(ERR, "Unknown ECP type: %s", search_term);
            PrintAndLogEx(HINT, "Available types: access, transit, vasorpay, vasandpay, vasonly, payonly, gymkit, identity, aidrop");
        }
    }

    json_decref(ecplist);
    free(cmd_copy);
    return result;
}
