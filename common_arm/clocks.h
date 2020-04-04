#ifndef _CLOCKS_H_
#define _CLOCKS_H_

#include "common.h"
#include "at91sam7s512.h"

void mck_from_pll_to_slck(void);
void mck_from_slck_to_pll(void);

#endif // _CLOCKS_H_
