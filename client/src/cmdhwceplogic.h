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
// CEP bus logic logger: fetch/decode/render helpers used by cmdhwcep.c's
// `hw cep logic` command table. See cmdhwceplogic.c.
//-----------------------------------------------------------------------------

#ifndef CMDHWCEPLOGIC_H__
#define CMDHWCEPLOGIC_H__

#include "common.h"
#include "pm3_cmd.h" // cep_logic_status_t, cep_logic_entry_t

// skip_idle only matters for CEP_LOGIC_ACTION_START - pass false otherwise.
int cep_logic_ctrl(uint8_t action, bool skip_idle, cep_logic_status_t *out);
void cep_logic_print_status(const cep_logic_status_t *st);

// Pulls the whole trace via repeated CMD_CEP_LOGIC_FETCH calls. *out is
// malloc'd (caller frees); *n_out is how many entries landed in it.
int cep_logic_fetch_all(cep_logic_entry_t **out, uint32_t *n_out);

void cep_logic_print_table(const cep_logic_entry_t *e, uint32_t n);
void cep_logic_write_vcd(const char *fn, const cep_logic_entry_t *e, uint32_t n);

#endif
