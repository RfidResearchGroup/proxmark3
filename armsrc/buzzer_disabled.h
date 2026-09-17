//-----------------------------------------------------------------------------
// Copyright (C) sww 2017.4.6
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

#ifndef __BUZZER_H
#define __BUZZER_H

#include "common.h"

#define n_2_7khz        185
#define note_1          956
#define note_2          851
#define note_3          758
#define note_4          715
#define note_5          638
#define note_6          568
#define note_7          506
#define note_8          0

void Ring_BEE_ONCE(uint16_t music_note);
void Ring_BEE_TIME(uint16_t music_note, uint16_t count);
void ring_2_7khz(uint16_t count);
void Ring_ALL(uint16_t count);
void Ring_Little_Star(uint16_t count);

#endif
