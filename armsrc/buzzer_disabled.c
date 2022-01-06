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

#include "buzzer_disabled.h"

void Ring_BEE_ONCE(uint16_t music_note) {
    BEE_ON();
    SpinDelayUs(music_note);
    BEE_OFF();
    SpinDelayUs(music_note);
}

void ring_2_7khz(uint16_t count) {
    Ring_BEE_TIME(n_2_7khz, count);
}

void Ring_BEE_TIME(uint16_t music_note, uint16_t count) {
    for (uint16_t i = 0 ; i < count; i++)
        Ring_BEE_ONCE(music_note);
    SpinDelay(9);
}

void Ring_ALL(uint16_t count) {
    Ring_BEE_TIME(note_1, count);
    Ring_BEE_TIME(note_2, count);
    Ring_BEE_TIME(note_3, count);
    Ring_BEE_TIME(note_4, count);
    Ring_BEE_TIME(note_5, count);
    Ring_BEE_TIME(note_6, count);
    Ring_BEE_TIME(note_7, count);
    SpinDelay(10);
}

void Ring_Little_Star(uint16_t count) {
    Ring_BEE_TIME(note_1, count);
    Ring_BEE_TIME(note_1, count);
    Ring_BEE_TIME(note_5, count);
    Ring_BEE_TIME(note_5, count);
    Ring_BEE_TIME(note_6, count);
    Ring_BEE_TIME(note_6, count);
    Ring_BEE_TIME(note_5, 2 * count);
    LED_A_ON();
    /*
    Ring_BEE_TIME(note_4,count);
    Ring_BEE_TIME(note_4,count);
    Ring_BEE_TIME(note_3,count);
    Ring_BEE_TIME(note_3,count);
    Ring_BEE_TIME(note_2,count);
    Ring_BEE_TIME(note_2,count);
    Ring_BEE_TIME(note_1,2*count);
    LED_A_OFF();

    Ring_BEE_TIME(note_5,count);
    Ring_BEE_TIME(note_5,count);
    Ring_BEE_TIME(note_4,count);
    Ring_BEE_TIME(note_4,count);
    Ring_BEE_TIME(note_3,count);
    Ring_BEE_TIME(note_3,count);
    Ring_BEE_TIME(note_2,2*count);
    LED_A_ON();

    Ring_BEE_TIME(note_5,count);
    Ring_BEE_TIME(note_5,count);
    Ring_BEE_TIME(note_4,count);
    Ring_BEE_TIME(note_4,count);
    Ring_BEE_TIME(note_3,count);
    Ring_BEE_TIME(note_3,count);
    Ring_BEE_TIME(note_2,2*count);
    LED_A_OFF();

    Ring_BEE_TIME(note_1,count);
    Ring_BEE_TIME(note_1,count);
    Ring_BEE_TIME(note_5,count);
    Ring_BEE_TIME(note_5,count);
    Ring_BEE_TIME(note_6,count);
    Ring_BEE_TIME(note_6,count);
    Ring_BEE_TIME(note_5,2*count);
    LED_A_ON();

    Ring_BEE_TIME(note_4,count);
    Ring_BEE_TIME(note_4,count);
    Ring_BEE_TIME(note_3,count);
    Ring_BEE_TIME(note_3,count);
    Ring_BEE_TIME(note_2,count);
    Ring_BEE_TIME(note_2,count);
    Ring_BEE_TIME(note_1,2*count);
    LED_B_ON();
    */
}
