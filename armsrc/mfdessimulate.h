

#ifndef __MFDESSIM_H
#define __MFDESSIM_H

#include "iso14443a.h"

void SimulateMfDesfireEv1(uint8_t tagType, uint16_t flags, uint8_t *uid, uint8_t *enc_key, int purpose);

#endif /* __MFDESSIM_H */
