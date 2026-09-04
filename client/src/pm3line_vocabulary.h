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
// Line editor auto complete vocabulary, built at runtime from the live
// command tree so it can never drift from what "help" shows.
//-----------------------------------------------------------------------------

#ifndef PM3LINE_VOCABULARY_H__
#define PM3LINE_VOCABULARY_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cmdparser.h"   // CMD_WALK_MAX_DEPTH

typedef struct vocabulary_s {
    // full command line, e.g. "hf mf dump" or "script run foo.lua"
    char *name;
    // IsAvailable predicates of the command and of every category on the way
    // down to it, in tree order. All of them must hold for the command to be
    // listed by "help", so the same rule is applied for completion.
    uint8_t depth;
    bool (*is_available[CMD_WALK_MAX_DEPTH])(void);
} vocabulary_t;

// (Re)build the vocabulary from the command tree and the script directories.
// Called automatically on first use.
void pm3line_vocabulary_build(void);

// Release the vocabulary.
void pm3line_vocabulary_free(void);

// Get the vocabulary, building it if needed.
// Returns the entries and stores their number in *count.
const vocabulary_t *pm3line_vocabulary_get(size_t *count);

// Evaluate the availability predicates of an entry, right now.
bool pm3line_vocabulary_is_available(const vocabulary_t *entry);

#ifdef __cplusplus
}
#endif

#endif // PM3LINE_VOCABULARY_H__
