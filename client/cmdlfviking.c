#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include "graph.h"
#include "cmdparser.h"
#include "cmddata.h"
#include "cmdmain.h"
#include "cmdlf.h"
#include "cmdlfviking.h"
#include "lfdemod.h"
static int CmdHelp(const char *Cmd);
int CmdVikingDemod(const char *Cmd)
{
    uint8_t id[4];
    if (param_gethex(Cmd,0,id,8) == 1)
    {
        PrintAndLog("Usage: lf viking demod <CardID 8 bytes of hex number>");
        return 0;
    }
    UsbCommand c = {CMD_ACQUIRE_RAW_ADC_SAMPLES_125K, {false,0,0}};
    SendCommand(&c);
    WaitForResponse(CMD_ACK,NULL);
    getSamples("40000",true);
    // try to demod AMViking
    return AMVikingDemod(id);
}
int CmdVikingClone(const char *Cmd)
{
    uint32_t b1,b2;
    // get the tag number 64 bits (8 bytes) in hex
    uint8_t id[8];
    if (param_gethex(Cmd,0,id,16) == 1)
    {
        PrintAndLog("Usage: lf viking clone <Card ID 16 bytes of hex number>");
        return 0;
    }
    b1 = bytes_to_num(id,sizeof(uint32_t));
    b2 = bytes_to_num(id + sizeof(uint32_t),sizeof(uint32_t));
    UsbCommand c = {CMD_VIKING_CLONE_TAG,{b1,b2}};
    SendCommand(&c);   
    return 0;
}

static command_t CommandTable[] =
{
    {"help", CmdHelp, 1, "This help"},
    {"demod",CmdVikingDemod ,1, "<8 digits tag id> -- Extract tag data"},
    {"clone", CmdVikingClone, 1, "<16 digits card data>  clone viking tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFViking(const char *Cmd)
{
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd)
{
    CmdsHelp(CommandTable);
    return 0;
}
