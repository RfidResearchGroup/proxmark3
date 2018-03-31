/*******
--by sww.2017.4.6
*******/

#ifndef __BUZZER_H
#define __BUZZER_H

#include <stdarg.h>
#include "proxmark3.h"
#include "apps.h"
#include "util.h"

#define n_2_7khz        185
#define note_1          956
#define note_2          851
#define note_3          758
#define note_4          715
#define note_5          638
#define note_6          568
#define note_7          506
#define note_8          0

extern void Ring_BEE_ONCE(uint16_t music_note);
extern void Ring_BEE_TIME(uint16_t music_note,uint16_t count);
extern void ring_2_7khz(uint16_t count);
extern void Ring_ALL(uint16_t count);
extern void Ring_Little_Star(uint16_t count);

#endif





















