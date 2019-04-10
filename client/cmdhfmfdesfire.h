#ifndef __MFDESFIRE_AD_H
#define __MFDESFIRE_AD_H

#include "cmdhfmf.h"
#include "util.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"

int CmdHF14AMfDESAuth(const char *Cmd);
int CmdHFMFDesfire(const char *Cmd);
int CmdHelp(const char *Cmd);

#endif
