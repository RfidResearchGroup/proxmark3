//-----------------------------------------------------------------------------
// Peter Fillmore 2015 
// Many authors, whom made it possible
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// various EMV related functions.
//-----------------------------------------------------------------------------
#include <stdarg.h>
#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"

#include "BigBuf.h"

#include "iso14443crc.h"
#include "iso14443a.h"
#include "emvutil.h"
#include "emvdataels.h" //EMV data elements 
#include "emvtags.h" //EMV card structure

#define DUMP(varname) Dbprintf("%s=", #varname);

int EMV_DBGLEVEL = EMV_DBG_ALL;
//uint8_t PCB = 0x00; //track Protocol Control Byte externally

//util functions
//print detected tag name over the serial link
int emv_printtag(uint8_t* selected_tag, emvtags* inputcard, uint8_t* outputstring, uint8_t* outputlen)
{
    //search tag list and print the match
    //get the value of the tag 
    uint8_t tagvalue[255];
    uint8_t tagvaluelen; 
    emv_lookuptag(selected_tag, inputcard, tagvalue, &tagvaluelen);
    //loop through selected tag, print the value found 
    for(int i=0; i<(sizeof(EMV_TAG_LIST)/sizeof(EMV_TAG_LIST[0])); i++){
        if(!memcmp(selected_tag, EMV_TAG_LIST[i].tag, 2)){
            memcpy(outputstring, EMV_TAG_LIST[i].description, strlen(EMV_TAG_LIST[i].description));
            memcpy(outputstring+(strlen(EMV_TAG_LIST[i].description)), "=", 1);
            memcpy(outputstring+(strlen(EMV_TAG_LIST[i].description))+1, tagvalue, tagvaluelen);
            *outputlen = strlen(EMV_TAG_LIST[i].description) + 1 + tagvaluelen; 
            break;
        }
    }  
    return 0;
}

//returns the value of the emv tag in the supplied emvtags structure
int emv_lookuptag(uint8_t* tag, emvtags *currentcard, uint8_t* outputval, uint8_t* outputvallen)
{
    //loop through tag and return the appropriate value
    uint8_t returnedtag[255]; 
    uint8_t returnedlength; 
    memset(returnedtag, 0x00, sizeof(returnedtag)); 
    if(!memcmp(tag, "\x4F\x00",2)){
         memcpy(&returnedtag, currentcard->tag_4F,  currentcard->tag_4F_len);
         returnedlength = currentcard->tag_4F_len; goto exitfunction;}
    else if(!memcmp(tag, "\x50\x00",2)){
         memcpy(&returnedtag, currentcard->tag_50,  currentcard->tag_50_len);
         returnedlength = currentcard->tag_50_len; goto exitfunction;}    
    else if(!memcmp(tag, "\x56\x00",2)){
         memcpy(&returnedtag, currentcard->tag_56,  currentcard->tag_56_len);
         returnedlength = currentcard->tag_56_len; goto exitfunction;}
    else if(!memcmp(tag, "\x57\x00",2)){
         memcpy(&returnedtag, currentcard->tag_57,  currentcard->tag_57_len);
         returnedlength = currentcard->tag_57_len; goto exitfunction;}
    else if(!memcmp(tag, "\x5A\x00",2)){
         memcpy(&returnedtag, currentcard->tag_5A,  currentcard->tag_5A_len);
         returnedlength = currentcard->tag_5A_len; goto exitfunction;}
    else if(!memcmp(tag, "\x82\x00",2)){
         memcpy(&returnedtag, currentcard->tag_82,  sizeof(currentcard->tag_82));
         returnedlength = sizeof(currentcard->tag_82);goto exitfunction;}
    else if(!memcmp(tag, "\x84\x00",2)){
         memcpy(&returnedtag, currentcard->tag_84,  currentcard->tag_84_len);
         returnedlength = currentcard->tag_84_len; goto exitfunction;}
    else if(!memcmp(tag, "\x86\x00",2)){
         memcpy(&returnedtag, currentcard->tag_86,  currentcard->tag_86_len);
         returnedlength = currentcard->tag_86_len; goto exitfunction;}
    else if(!memcmp(tag, "\x87\x00",2)){
         memcpy(&returnedtag, currentcard->tag_87,  sizeof(currentcard->tag_87));
         returnedlength = sizeof(currentcard->tag_87);goto exitfunction;}
    else if(!memcmp(tag, "\x88\x00",2)){
         memcpy(&returnedtag, currentcard->tag_88,  currentcard->tag_50_len);
         returnedlength = sizeof(currentcard->tag_88); goto exitfunction;}
    else if(!memcmp(tag, "\x8A\x00",2)){
         memcpy(&returnedtag, currentcard->tag_8A,  sizeof(currentcard->tag_8A));
         returnedlength = sizeof(currentcard->tag_8A);goto exitfunction;}
    else if(!memcmp(tag, "\x8C\x00",2)){
         memcpy(&returnedtag, currentcard->tag_8C,  currentcard->tag_8C_len);
         returnedlength = currentcard->tag_8C_len; goto exitfunction;}
    else if(!memcmp(tag, "\x8D\x00",2)){
         memcpy(&returnedtag, currentcard->tag_8D,  currentcard->tag_8D_len);
         returnedlength = currentcard->tag_8D_len; goto exitfunction;}
    else if(!memcmp(tag, "\x8E\x00",2)){
        memcpy(&returnedtag, currentcard->tag_8E,  currentcard->tag_8E_len);
         returnedlength = currentcard->tag_8E_len; goto exitfunction;}
    else if(!memcmp(tag, "\x8F\x00",2)){
         memcpy(&returnedtag, currentcard->tag_8F,  sizeof(currentcard->tag_8F));
         returnedlength = sizeof(currentcard->tag_8F);goto exitfunction;}
    else if(!memcmp(tag, "\x90\x00",2)){
         memcpy(&returnedtag, currentcard->tag_90,  currentcard->tag_90_len);
         returnedlength = currentcard->tag_90_len; goto exitfunction;}
    else if(!memcmp(tag, "\x92\x00",2)){
         memcpy(&returnedtag, currentcard->tag_92,  currentcard->tag_92_len);
         returnedlength = currentcard->tag_92_len; goto exitfunction;}
    else if(!memcmp(tag, "\x93\x00",2)){
         memcpy(&returnedtag, currentcard->tag_93,  currentcard->tag_93_len);
         returnedlength = currentcard->tag_93_len; goto exitfunction;}
    else if(!memcmp(tag, "\x94\x00",2)){
         memcpy(&returnedtag, currentcard->tag_94,  currentcard->tag_94_len);
         returnedlength = currentcard->tag_94_len; goto exitfunction;}
    else if(!memcmp(tag, "\x95\x00",2)){
         memcpy(&returnedtag, currentcard->tag_95,  sizeof(currentcard->tag_95));
         returnedlength = sizeof(currentcard->tag_95);goto exitfunction;}
    else if(!memcmp(tag, "\x97\x00",2)){
        memcpy(&returnedtag, currentcard->tag_97,  currentcard->tag_97_len);
         returnedlength = currentcard->tag_97_len; goto exitfunction;}
    else if(!memcmp(tag, "\x98\x00",2)){
         memcpy(&returnedtag, currentcard->tag_98,  sizeof(currentcard->tag_98));
         returnedlength = sizeof(currentcard->tag_98);goto exitfunction;}
    else if(!memcmp(tag, "\x99\x00",2)){
        memcpy(&returnedtag, currentcard->tag_99,  currentcard->tag_99_len);
         returnedlength = currentcard->tag_99_len; goto exitfunction;}
    else if(!memcmp(tag, "\x9A\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9A,  sizeof(currentcard->tag_9A));
         returnedlength = sizeof(currentcard->tag_9A);goto exitfunction;}
    else if(!memcmp(tag, "\x9B\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9B,  sizeof(currentcard->tag_9B));
         returnedlength = sizeof(currentcard->tag_9B);goto exitfunction;}
    else if(!memcmp(tag, "\x9C\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9C,  sizeof(currentcard->tag_9C));
         returnedlength = sizeof(currentcard->tag_9C);goto exitfunction;}
    else if(!memcmp(tag, "\x9D\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9D,  currentcard->tag_9D_len);
         returnedlength = currentcard->tag_9D_len; goto exitfunction;}
    else if(!memcmp(tag, "\x9D\x00",2)){
         memcpy(&returnedtag, currentcard->tag_9D,  currentcard->tag_9D_len);
         returnedlength = currentcard->tag_9D_len; goto exitfunction;}
    else if(!memcmp(tag, "\xCD\x00",2)){
         memcpy(&returnedtag, currentcard->tag_CD,  sizeof(currentcard->tag_CD));
         returnedlength = sizeof(currentcard->tag_CD);goto exitfunction;}
    else if(!memcmp(tag, "\xCE\x00",2)){
         memcpy(&returnedtag, currentcard->tag_CE,  sizeof(currentcard->tag_CE));
         returnedlength = sizeof(currentcard->tag_CE);goto exitfunction;}
    else if(!memcmp(tag, "\xCF\x00",2)){
         memcpy(&returnedtag, currentcard->tag_CF,  sizeof(currentcard->tag_CF));
         returnedlength = sizeof(currentcard->tag_CF);goto exitfunction;}
    else if(!memcmp(tag, "\xD7\x00",2)){
         memcpy(&returnedtag, currentcard->tag_D7,  sizeof(currentcard->tag_D7));
         returnedlength = sizeof(currentcard->tag_D7);goto exitfunction;}
    else if(!memcmp(tag, "\xD8\x00",2)){
         memcpy(&returnedtag, currentcard->tag_D8,  sizeof(currentcard->tag_D8));
         returnedlength = sizeof(currentcard->tag_D8);goto exitfunction;}
    else if(!memcmp(tag, "\xD9\x00",2)){
    memcpy(&returnedtag, currentcard->tag_D9,  currentcard->tag_D9_len);
         returnedlength = currentcard->tag_D9_len;goto exitfunction;}
    else if(!memcmp(tag, "\xDA\x00",2)){
         memcpy(&returnedtag, currentcard->tag_DA,  sizeof(currentcard->tag_DA));
         returnedlength = sizeof(currentcard->tag_DA);goto exitfunction;}
    else if(!memcmp(tag, "\xDB\x00",2)){
         memcpy(&returnedtag, currentcard->tag_DB,  sizeof(currentcard->tag_DB));
         returnedlength = sizeof(currentcard->tag_DB);goto exitfunction;}
    else if(!memcmp(tag, "\xDC\x00",2)){
         memcpy(&returnedtag, currentcard->tag_DC,  sizeof(currentcard->tag_DC));
         returnedlength = sizeof(currentcard->tag_DC);goto exitfunction;}
    else if(!memcmp(tag, "\xDD\x00",2)){
         memcpy(&returnedtag, currentcard->tag_DD,  sizeof(currentcard->tag_DD));
         returnedlength = sizeof(currentcard->tag_DD);goto exitfunction;}
    else if(!memcmp(tag, "\xA5\x00",2)){
   memcpy(&returnedtag, currentcard->tag_A5,  currentcard->tag_A5_len);
         returnedlength = currentcard->tag_A5_len; goto exitfunction;}
    else if(!memcmp(tag, "\xAF\x00",2)){
   memcpy(&returnedtag, currentcard->tag_AF,  currentcard->tag_AF_len);
         returnedlength = currentcard->tag_AF_len; goto exitfunction;}
    if(*tag == 0x5F){ 
        if(*(tag+1) == 0x20){ 
            memcpy(&returnedtag, currentcard->tag_5F20,  currentcard->tag_5F20_len);
             returnedlength = currentcard->tag_5F20_len; goto exitfunction;}
        else if(*(tag+1) == 0x24){ 
             memcpy(&returnedtag, currentcard->tag_5F24,  sizeof(currentcard->tag_5F24));
             returnedlength = sizeof(currentcard->tag_5F24);goto exitfunction;}
        else if(*(tag+1) == 0x25){ 
             memcpy(&returnedtag, currentcard->tag_5F25,  sizeof(currentcard->tag_5F25));
             returnedlength = sizeof(currentcard->tag_5F25);goto exitfunction;}
        else if(*(tag+1) == 0x28){ 
             memcpy(&returnedtag, currentcard->tag_5F28,  sizeof(currentcard->tag_5F28));
             returnedlength = sizeof(currentcard->tag_5F28);goto exitfunction;}
        else if(*(tag+1) == 0x2A){ 
             memcpy(&returnedtag, currentcard->tag_5F2A,  sizeof(currentcard->tag_5F2A));
             returnedlength = sizeof(currentcard->tag_5F2A);goto exitfunction;}
        else if(*(tag+1) == 0x2D){ 
            memcpy(&returnedtag, currentcard->tag_5F2D,  currentcard->tag_5F2D_len);
             returnedlength = currentcard->tag_5F2D_len; goto exitfunction;}
        else if(*(tag+1) == 0x30){ 
             memcpy(&returnedtag, currentcard->tag_5F30,  sizeof(currentcard->tag_5F30));
             returnedlength = sizeof(currentcard->tag_5F30);goto exitfunction;}
        else if(*(tag+1) == 0x34){ 
             memcpy(&returnedtag, currentcard->tag_5F34,  sizeof(currentcard->tag_5F34));
             returnedlength = sizeof(currentcard->tag_5F34);goto exitfunction;}
        else if(*(tag+1) == 0x36){ 
             memcpy(&returnedtag, currentcard->tag_5F36,  sizeof(currentcard->tag_5F36));
             returnedlength = sizeof(currentcard->tag_5F36);goto exitfunction;}
        else if(*(tag+1) == 0x50){ 
            memcpy(&returnedtag, currentcard->tag_5F50,  currentcard->tag_5F50_len);
             returnedlength = currentcard->tag_5F50_len; goto exitfunction;}
        else if(*(tag+1) == 0x54){ 
            memcpy(&returnedtag, currentcard->tag_5F54,  currentcard->tag_5F54_len);
             returnedlength = currentcard->tag_5F54_len; goto exitfunction;}
        }
    if(*tag == 0x9F) {
        if(*(tag+1) == 0x01){ 
             memcpy(&returnedtag, currentcard->tag_9F01,  sizeof(currentcard->tag_9F01));
             returnedlength = sizeof(currentcard->tag_9F01);goto exitfunction;}
        else if(*(tag+1) == 0x02){ 
             memcpy(&returnedtag, currentcard->tag_9F02,  sizeof(currentcard->tag_9F02));
             returnedlength = sizeof(currentcard->tag_9F02);goto exitfunction;}
        else if(*(tag+1) == 0x03){ 
             returnedlength = sizeof(currentcard->tag_9F03);goto exitfunction;}
        else if(*(tag+1) == 0x04){ 
             memcpy(&returnedtag, currentcard->tag_9F04,  sizeof(currentcard->tag_9F04));
             returnedlength = sizeof(currentcard->tag_9F04);goto exitfunction;}
        else if(*(tag+1) == 0x05){ 
       memcpy(&returnedtag, currentcard->tag_9F05,  currentcard->tag_9F05_len);
             returnedlength = currentcard->tag_9F05_len; goto exitfunction;}
        else if(*(tag+1) == 0x06){ 
       memcpy(&returnedtag, currentcard->tag_9F06,  currentcard->tag_9F06_len);
             returnedlength = currentcard->tag_9F06_len; goto exitfunction;}
        else if(*(tag+1) == 0x07){ 
             memcpy(&returnedtag, currentcard->tag_9F07,  sizeof(currentcard->tag_9F07));
             returnedlength = sizeof(currentcard->tag_9F07);goto exitfunction;}
        else if(*(tag+1) == 0x08){ 
             memcpy(&returnedtag, currentcard->tag_9F08,  sizeof(currentcard->tag_9F08));
             returnedlength = sizeof(currentcard->tag_9F08);goto exitfunction;}
        else if(*(tag+1) == 0x09){ 
             memcpy(&returnedtag, currentcard->tag_9F09,  sizeof(currentcard->tag_9F09));
             returnedlength = sizeof(currentcard->tag_9F09);goto exitfunction;} 
        else if(*(tag+1) == 0x0B){ 
       memcpy(&returnedtag, currentcard->tag_9F0B,  currentcard->tag_9F0B_len);
             returnedlength = currentcard->tag_9F0B_len; goto exitfunction;}
        else if(*(tag+1) == 0x0D){ 
             memcpy(&returnedtag, currentcard->tag_9F0D,  sizeof(currentcard->tag_9F0D));
             returnedlength = sizeof(currentcard->tag_9F0D);goto exitfunction;}
        else if(*(tag+1) == 0x0E){ 
             memcpy(&returnedtag, currentcard->tag_9F0E,  sizeof(currentcard->tag_9F0E));
             returnedlength = sizeof(currentcard->tag_9F0E);goto exitfunction;}
        else if(*(tag+1) == 0x0F){ 
             memcpy(&returnedtag, currentcard->tag_9F0F,  sizeof(currentcard->tag_9F0F));
             returnedlength = sizeof(currentcard->tag_9F0F);goto exitfunction;}
        else if(*(tag+1) == 0x10){ 
            memcpy(&returnedtag, currentcard->tag_9F10,  currentcard->tag_9F10_len);
             returnedlength = currentcard->tag_9F10_len;goto exitfunction;}
        else if(*(tag+1) == 0x11){ 
             memcpy(&returnedtag, currentcard->tag_9F11,  sizeof(currentcard->tag_9F11));
             returnedlength = sizeof(currentcard->tag_9F11);goto exitfunction;}
        else if(*(tag+1) == 0x12){ 
             memcpy(&returnedtag, currentcard->tag_9F12,  currentcard->tag_9F12_len);
             returnedlength = currentcard->tag_9F12_len;goto exitfunction;}
        else if(*(tag+1) == 0x1A){ 
             memcpy(&returnedtag, currentcard->tag_9F1A,  sizeof(currentcard->tag_9F1A));
            goto exitfunction;}
        else if(*(tag+1) == 0x1F){ 
       memcpy(&returnedtag, currentcard->tag_9F1F,  currentcard->tag_9F1F_len);
             returnedlength = currentcard->tag_9F1F_len; goto exitfunction;}
        else if(*(tag+1) == 0x32){ 
       memcpy(&returnedtag, currentcard->tag_9F32,  currentcard->tag_9F32_len);
             returnedlength = currentcard->tag_9F32_len; goto exitfunction;}
        else if(*(tag+1) == 0x34){ 
       memcpy(&returnedtag, currentcard->tag_9F34,  sizeof(currentcard->tag_9F34));
             returnedlength = sizeof(currentcard->tag_9F34); goto exitfunction;}
else if(*(tag+1) == 0x35){ 
       memcpy(&returnedtag, currentcard->tag_9F35,  sizeof(currentcard->tag_9F35));
             returnedlength = sizeof(currentcard->tag_9F35); goto exitfunction;}
else if(*(tag+1) == 0x37){ 
             memcpy(&returnedtag, currentcard->tag_9F37,  sizeof(currentcard->tag_9F37));
             returnedlength = sizeof(currentcard->tag_9F37);goto exitfunction;}
        else if(*(tag+1) == 0x38){ 
       memcpy(&returnedtag, currentcard->tag_9F38,  currentcard->tag_9F38_len);
             returnedlength = currentcard->tag_9F38_len; goto exitfunction;}
        else if(*(tag+1) == 0x44){ 
             memcpy(&returnedtag, currentcard->tag_9F44,  sizeof(currentcard->tag_9F44));
             returnedlength = sizeof(currentcard->tag_9F44);goto exitfunction;}
        else if(*(tag+1) == 0x45){ 
             memcpy(&returnedtag, currentcard->tag_9F45,  sizeof(currentcard->tag_9F45));
             returnedlength = sizeof(currentcard->tag_9F45);goto exitfunction;}
        else if(*(tag+1) == 0x46){ 
            memcpy(&returnedtag, currentcard->tag_9F46,  currentcard->tag_9F46_len);
             returnedlength = currentcard->tag_9F46_len; goto exitfunction;}
        else if(*(tag+1) == 0x47){ 
       memcpy(&returnedtag, currentcard->tag_9F47,  currentcard->tag_9F47_len);
             returnedlength = currentcard->tag_9F47_len; goto exitfunction;}
        else if(*(tag+1) == 0x48){ 
       memcpy(&returnedtag, currentcard->tag_9F48,  currentcard->tag_9F48_len);
             returnedlength = currentcard->tag_9F48_len; goto exitfunction;}
        else if(*(tag+1) == 0x49){ 
       memcpy(&returnedtag, currentcard->tag_9F49,  currentcard->tag_9F49_len);
             returnedlength = currentcard->tag_9F49_len; goto exitfunction;}
        else if(*(tag+1) == 0x4A){ 
             memcpy(&returnedtag, currentcard->tag_9F4A,  sizeof(currentcard->tag_9F4A));
             returnedlength = sizeof(currentcard->tag_9F4A);goto exitfunction;}
        else if(*(tag+1) == 0x4B){ 
       memcpy(&returnedtag, currentcard->tag_9F4B,  currentcard->tag_9F4B_len);
             returnedlength = currentcard->tag_9F4B_len; goto exitfunction;}
        else if(*(tag+1) == 0x4C){ 
             memcpy(&returnedtag, currentcard->tag_9F4C,  sizeof(currentcard->tag_9F4C));
             returnedlength = sizeof(currentcard->tag_9F4C); goto exitfunction;}
else if(*(tag+1) == 0x60){ 
             memcpy(&returnedtag, currentcard->tag_9F60,  sizeof(currentcard->tag_9F60));
             returnedlength = sizeof(currentcard->tag_9F60);goto exitfunction;}
        else if(*(tag+1) == 0x61){ 
             memcpy(&returnedtag, currentcard->tag_9F61,  sizeof(currentcard->tag_9F61));
             returnedlength = sizeof(currentcard->tag_9F61);goto exitfunction;}
        else if(*(tag+1) == 0x62){ 
             memcpy(&returnedtag, currentcard->tag_9F62,  sizeof(currentcard->tag_9F62));
             returnedlength = sizeof(currentcard->tag_9F62);goto exitfunction;}
        else if(*(tag+1) == 0x63){ 
             memcpy(&returnedtag, currentcard->tag_9F63,  sizeof(currentcard->tag_9F63));
             returnedlength = sizeof(currentcard->tag_9F63);goto exitfunction;}
        else if(*(tag+1) == 0x64){ 
             memcpy(&returnedtag, currentcard->tag_9F64,  sizeof(currentcard->tag_9F64));
             returnedlength = sizeof(currentcard->tag_9F64);goto exitfunction;}
        else if(*(tag+1) == 0x65){ 
             memcpy(&returnedtag, currentcard->tag_9F65,  sizeof(currentcard->tag_9F65));
             returnedlength = sizeof(currentcard->tag_9F65);goto exitfunction;}
        else if(*(tag+1) == 0x66){ 
            memcpy(&returnedtag, currentcard->tag_9F66,  sizeof(currentcard->tag_9F66));
             returnedlength = sizeof(currentcard->tag_9F66);goto exitfunction;}
        else if(*(tag+1) == 0x67){ 
             memcpy(&returnedtag, currentcard->tag_9F67,  sizeof(currentcard->tag_9F67));
             returnedlength = sizeof(currentcard->tag_9F67);goto exitfunction;}
        else if(*(tag+1) == 0x68){ 
        memcpy(&returnedtag, currentcard->tag_9F68,  currentcard->tag_9F68_len);
             returnedlength = currentcard->tag_9F68_len;goto exitfunction;}
        else if(*(tag+1) == 0x69){ 
       memcpy(&returnedtag, currentcard->tag_9F69,  currentcard->tag_9F69_len);
             returnedlength = currentcard->tag_9F69_len; goto exitfunction;}
        else if(*(tag+1) == 0x6A){ 
             memcpy(&returnedtag, currentcard->tag_9F6A,  sizeof(currentcard->tag_9F6A));
             returnedlength = sizeof(currentcard->tag_9F6A);goto exitfunction;}
        else if(*(tag+1) == 0x6B){ 
       memcpy(&returnedtag, currentcard->tag_9F6B,  currentcard->tag_9F6B_len);
             returnedlength = currentcard->tag_9F6B_len; goto exitfunction;}
        else if(*(tag+1) == 0x6C){ 
             memcpy(&returnedtag, currentcard->tag_9F6C,  sizeof(currentcard->tag_9F6C));
             returnedlength = sizeof(currentcard->tag_9F6C);goto exitfunction;}
    }
    else {
        if(!memcmp(tag, "\x61\x00",2)){
       memcpy(&returnedtag, currentcard->tag_61,  currentcard->tag_61_len);
             returnedlength = currentcard->tag_61_len; goto exitfunction;}
        else if(!memcmp(tag, "\x6F\x00",2)){
       memcpy(&returnedtag, currentcard->tag_6F,  currentcard->tag_6F_len);
             returnedlength = currentcard->tag_6F_len; goto exitfunction;}
        else if(!memcmp(tag, "\xAF\x00",2)){
       memcpy(&returnedtag, currentcard->tag_AF,  currentcard->tag_AF_len);
             returnedlength = currentcard->tag_AF_len; goto exitfunction;}
        else if(!memcmp(tag, "\x70\x00",2)){
       memcpy(&returnedtag, currentcard->tag_70,  currentcard->tag_70_len);
             returnedlength = currentcard->tag_70_len; goto exitfunction;}
        else if(!memcmp(tag, "\x77\x00",2)){
       memcpy(&returnedtag, currentcard->tag_77,  currentcard->tag_77_len);
             returnedlength = currentcard->tag_77_len; goto exitfunction;}
        else if(!memcmp(tag, "\x80\x00",2)){
       memcpy(&returnedtag, currentcard->tag_80,  currentcard->tag_80_len);
             returnedlength = currentcard->tag_80_len; goto exitfunction;}
        else if(!memcmp(tag, "\xBF\x0C",2)){
       memcpy(&returnedtag, currentcard->tag_BF0C,  currentcard->tag_BF0C_len);
             returnedlength = currentcard->tag_BF0C_len; goto exitfunction;}
        else if(!memcmp(tag, "\xFF\x01",2)){ //special DF tag
       memcpy(&returnedtag, currentcard->tag_DFName,  currentcard->tag_DFName_len);
             returnedlength = currentcard->tag_DFName_len; goto exitfunction;}
    }
exitfunction:  //goto label to exit search quickly once found
    memcpy(outputval, &returnedtag, returnedlength);
    *outputvallen = returnedlength; 
    return 0;
}  

//function to 
int emv_settag(uint32_t tag, uint8_t *datain, emvtags *currentcard){
    char binarydata[255] = {0};
    //if((strlen((const char *)datain)%2) != 0){ //must be an even string
    //    return -1;
    //}
    //if(strlen((const char *)datain) > 255) {
    //    return -1;
    //} 
    uint8_t datalen = strlen((const char *)datain) / 2; //length of datain 
    for(int i=0;i<strlen((const char *)datain);i+=2){
        binarydata[i/2] |= (char)hex2int(datain[i]) << 4;
        binarydata[i/2] |= (char)hex2int(datain[i+1]);
    } 
    Dbprintf("BINARYDATA="); 
    Dbhexdump(datalen,(uint8_t *)binarydata,false);
 
    switch(tag){
        case 0x4F:
            memcpy(currentcard->tag_4F, binarydata, datalen);
            currentcard->tag_4F_len = datalen;
            break; 
        case 0x50:
            memcpy(currentcard->tag_50, binarydata, datalen);
            currentcard->tag_50_len = datalen;
            break;
        case 0x56:
            memcpy(currentcard->tag_56, binarydata, datalen);
            currentcard->tag_56_len = datalen;
            break;
        case 0x57:
            memcpy(currentcard->tag_57, binarydata, datalen);
            currentcard->tag_57_len = datalen;
            break;
        case 0x5a:
            memcpy(currentcard->tag_5A, binarydata, datalen);
            currentcard->tag_5A_len = datalen;
            break;
        case 0x61:
            memcpy(currentcard->tag_61, binarydata, datalen);
            currentcard->tag_61_len = datalen;
            break;
        case 0x6f:
            memcpy(currentcard->tag_6F, binarydata, datalen);
            currentcard->tag_6F_len = datalen;
            break;
        case 0x70:
            memcpy(currentcard->tag_70, binarydata, datalen);
            currentcard->tag_70_len = datalen;
            break;
        case 0x77:
            memcpy(currentcard->tag_77, binarydata, datalen);
            currentcard->tag_77_len = datalen;
            break;
        case 0x80:
            memcpy(currentcard->tag_80, binarydata, datalen);
            currentcard->tag_80_len = datalen;
            break;
        case 0x82:
            memcpy(currentcard->tag_82, binarydata, sizeof(currentcard->tag_82));
            break; 
        case 0x84:
            memcpy(currentcard->tag_84, binarydata, datalen);
            currentcard->tag_84_len = datalen;
            break;
        case 0x86:
            memcpy(currentcard->tag_86, binarydata, datalen);
            currentcard->tag_86_len = datalen;
            break;
        case 0x87:
            memcpy(currentcard->tag_87, binarydata, sizeof(currentcard->tag_87));
            break;
        case 0x88:
            memcpy(currentcard->tag_88, binarydata, sizeof(currentcard->tag_88));
            break;
        case 0x8a:
            memcpy(currentcard->tag_8A, binarydata, sizeof(currentcard->tag_8A));
            break;
        case 0x8c:
            memcpy(currentcard->tag_8C, binarydata, datalen);
            currentcard->tag_8C_len = datalen;
            break;
        case 0x8d:
            memcpy(currentcard->tag_8D, binarydata, datalen);
            currentcard->tag_8D_len = datalen;
            break;
        case 0x8e:
            memcpy(currentcard->tag_8E, binarydata, datalen);
            currentcard->tag_8E_len = datalen;
            break;
        case 0x8f:
            memcpy(currentcard->tag_8F, binarydata, sizeof(currentcard->tag_8F));
            break;
        case 0x90:
            memcpy(currentcard->tag_90, binarydata, datalen);
            currentcard->tag_90_len = datalen;
            break;
        case 0x91:
            memcpy(currentcard->tag_91, binarydata, datalen);
            currentcard->tag_91_len = datalen;
            break;
        case 0x92:
            memcpy(currentcard->tag_92, binarydata, datalen);
            currentcard->tag_92_len = datalen;
            break;
        case 0x93:
            memcpy(currentcard->tag_93, binarydata, datalen);
            currentcard->tag_93_len = datalen;           
            break;
        case 0x94:
            memcpy(currentcard->tag_94, binarydata, datalen);
            currentcard->tag_94_len = datalen;           
            break;
        case 0x95:
            memcpy(currentcard->tag_95, binarydata, sizeof(currentcard->tag_95));
            break;
        case 0x97:
            memcpy(currentcard->tag_97, binarydata, datalen);
            currentcard->tag_97_len = datalen;           
            break;
        case 0x98:
            memcpy(currentcard->tag_98, binarydata, sizeof(currentcard->tag_98));
            break;
        case 0x99:
            memcpy(currentcard->tag_99, binarydata, datalen);
            currentcard->tag_99_len = datalen;           
            break;
        case 0x9a:
            memcpy(currentcard->tag_9A, binarydata, sizeof(currentcard->tag_9A));
            break;
        case 0x9b:
            memcpy(currentcard->tag_9B, binarydata, sizeof(currentcard->tag_9B));
            break;
        case 0x9c:
            memcpy(currentcard->tag_9C, binarydata, sizeof(currentcard->tag_9C));
            break;
        case 0x9d:
            memcpy(currentcard->tag_9D, binarydata, datalen);
            currentcard->tag_9D_len = datalen;           
            break;
        case 0xa5:
            memcpy(currentcard->tag_A5, binarydata, datalen);
            currentcard->tag_A5_len = datalen;           
            break; 
        case 0xaf:
            memcpy(currentcard->tag_AF, binarydata, datalen);
            currentcard->tag_AF_len = datalen;           
            break; 
        case 0xcd:
            memcpy(currentcard->tag_CD, binarydata, sizeof(currentcard->tag_CD));
            break;
        case 0xce:
            memcpy(currentcard->tag_CE, binarydata, sizeof(currentcard->tag_CE));
            break;
        case 0xcf:
            memcpy(currentcard->tag_CF, binarydata, sizeof(currentcard->tag_CF));
            break;
        case 0xd7:
            memcpy(currentcard->tag_CF, binarydata, sizeof(currentcard->tag_CF));
            break;
        case 0xd8:
            memcpy(currentcard->tag_CF, binarydata, sizeof(currentcard->tag_CF));
            break;
        case 0xd9:
            break;
        case 0xda:
            memcpy(currentcard->tag_DA, binarydata, sizeof(currentcard->tag_DA));
            break;
        case 0xdb:
            memcpy(currentcard->tag_DB, binarydata, sizeof(currentcard->tag_DB));
            break;
        case 0xdc:
            memcpy(currentcard->tag_DB, binarydata, sizeof(currentcard->tag_DB));
            break;
        case 0xdd:
            memcpy(currentcard->tag_DD, binarydata, sizeof(currentcard->tag_DD));
            break;
        case 0x5f20:
            break;
        case 0x5f24:
            memcpy(currentcard->tag_5F24, binarydata, sizeof(currentcard->tag_5F24));
            break;
        case 0x5f25:
            memcpy(currentcard->tag_5F25, binarydata, sizeof(currentcard->tag_5F25));
            break;
        case 0x5f28:
            memcpy(currentcard->tag_5F28, binarydata, sizeof(currentcard->tag_5F28));
            break;
        case 0x5f2a:
            memcpy(currentcard->tag_5F2A, binarydata, sizeof(currentcard->tag_5F2A));
            break;
        case 0x5f2d:
            break;
        case 0x5f30:
            memcpy(currentcard->tag_5F30, binarydata, sizeof(currentcard->tag_5F30));
            break;
        case 0x5f34:
            memcpy(currentcard->tag_5F34, binarydata, sizeof(currentcard->tag_5F34));
            break;
        case 0x5f36:
            memcpy(currentcard->tag_5F36, binarydata, sizeof(currentcard->tag_5F36));
            break;
        case 0x5f50:
            break;
        case 0x5f54:
            memcpy(currentcard->tag_5F54, binarydata, sizeof(currentcard->tag_5F54));
            break;
        case 0x9f01:
            memcpy(currentcard->tag_9F01, binarydata, sizeof(currentcard->tag_9F01));
            break;
        case 0x9f02:
            memcpy(currentcard->tag_9F02, binarydata, sizeof(currentcard->tag_9F02));
            break;
        case 0x9f03:
            memcpy(currentcard->tag_9F03, binarydata, sizeof(currentcard->tag_9F03));
            break;
        case 0x9f04:
            memcpy(currentcard->tag_9F04, binarydata, sizeof(currentcard->tag_9F04));
            break;
        case 0x9f05:
            memcpy(currentcard->tag_9F05, binarydata, datalen);
            currentcard->tag_9F05_len = datalen;
            break;
        case 0x9f06:
            memcpy(currentcard->tag_9F06, binarydata, datalen);
            currentcard->tag_9F06_len = datalen;
            break;
        case 0x9f07:
            memcpy(currentcard->tag_9F07, binarydata, sizeof(currentcard->tag_9F07));
            break;
        case 0x9f08:
            memcpy(currentcard->tag_9F08, binarydata, sizeof(currentcard->tag_9F08));
            break;
        case 0x9f09:
            memcpy(currentcard->tag_9F09, binarydata, sizeof(currentcard->tag_9F09));
            break;
        case 0x9f0b:
            memcpy(currentcard->tag_9F0B, binarydata, sizeof(currentcard->tag_9F0B));
            break;
        case 0x9f0d:
            memcpy(currentcard->tag_9F0D, binarydata, sizeof(currentcard->tag_9F0D));
            break;
        case 0x9f0e:
            memcpy(currentcard->tag_9F0E, binarydata, sizeof(currentcard->tag_9F0E));
            break;
        case 0x9f0f:
            memcpy(currentcard->tag_9F0F, binarydata, sizeof(currentcard->tag_9F0F));
            break;
        case 0x9f10:
            memcpy(currentcard->tag_9F10, binarydata, datalen);
            currentcard->tag_9F10_len = datalen;break;
        case 0x9f11:
            memcpy(currentcard->tag_9F11, binarydata, sizeof(currentcard->tag_9F11));
            break;
        case 0x9f12:
            memcpy(currentcard->tag_9F12, binarydata, datalen);
            currentcard->tag_9F12_len = datalen;break;
        case 0x9f13:
            memcpy(currentcard->tag_9F13, binarydata, sizeof(currentcard->tag_9F13));
            break;
        case 0x9f14:
            memcpy(currentcard->tag_9F14, binarydata, sizeof(currentcard->tag_9F14));
            break;
        case 0x9f15:
            memcpy(currentcard->tag_9F15, binarydata, sizeof(currentcard->tag_9F15));
            break;
        case 0x9f16:
            memcpy(currentcard->tag_9F16, binarydata, sizeof(currentcard->tag_9F16));
            break;
        case 0x9f17:
            memcpy(currentcard->tag_9F17, binarydata, sizeof(currentcard->tag_9F17));
            break;
        case 0x9f18:
            memcpy(currentcard->tag_9F18, binarydata, sizeof(currentcard->tag_9F18));
            break;
        case 0x9f1a:
            memcpy(currentcard->tag_9F1A, binarydata, sizeof(currentcard->tag_9F1A));
            break;
        case 0x9f1b:
            memcpy(currentcard->tag_9F1B, binarydata, sizeof(currentcard->tag_9F1B));
            break;
        case 0x9f1c:
            memcpy(currentcard->tag_9F1C, binarydata, sizeof(currentcard->tag_9F1C));
            break;
        case 0x9f1d:
            memcpy(currentcard->tag_9F1D, binarydata, datalen);
            currentcard->tag_9F1D_len = datalen;break;
        case 0x9f1e:
            memcpy(currentcard->tag_9F1E, binarydata, sizeof(currentcard->tag_9F1E));
            break;
        case 0x9f1f:
            memcpy(currentcard->tag_9F1F, binarydata, datalen);
            currentcard->tag_9F1F_len = datalen;break;
        case 0x9f20:
            memcpy(currentcard->tag_9F20, binarydata, datalen);
            currentcard->tag_9F20_len = datalen;break;
        case 0x9f21:
            memcpy(currentcard->tag_9F21, binarydata, sizeof(currentcard->tag_9F21));
            break;
        case 0x9f22:
            memcpy(currentcard->tag_9F22, binarydata, sizeof(currentcard->tag_9F22));
            break;
        case 0x9f23:
            memcpy(currentcard->tag_9F23, binarydata, sizeof(currentcard->tag_9F23));
            break;
        case 0x9f26:
            memcpy(currentcard->tag_9F26, binarydata, sizeof(currentcard->tag_9F26));
            break;
        case 0x9f27:
            memcpy(currentcard->tag_9F27, binarydata, sizeof(currentcard->tag_9F27));
            break;
        case 0x9f2d:
            memcpy(currentcard->tag_9F2D, binarydata, datalen);
            currentcard->tag_9F2D_len = datalen;break;
        case 0x9f2e:
            memcpy(currentcard->tag_9F2E, binarydata, sizeof(currentcard->tag_9F2E));
            break;
        case 0x9f2f:
            memcpy(currentcard->tag_9F2F, binarydata, datalen);
            currentcard->tag_9F2F_len = datalen;break;
        case 0x9f32:
            memcpy(currentcard->tag_9F32, binarydata, datalen);
            currentcard->tag_9F32_len = datalen;break;
        case 0x9f33:
            memcpy(currentcard->tag_9F33, binarydata, sizeof(currentcard->tag_9F33));
            break;
        case 0x9f34:
            memcpy(currentcard->tag_9F34, binarydata, sizeof(currentcard->tag_9F34));
            break;
        case 0x9f35:
            memcpy(currentcard->tag_9F35, binarydata, sizeof(currentcard->tag_9F35));
            break;
        case 0x9f36:
            memcpy(currentcard->tag_9F36, binarydata, sizeof(currentcard->tag_9F36));
            break;
        case 0x9f37:
            memcpy(currentcard->tag_9F37, binarydata, sizeof(currentcard->tag_9F37));
            break;
        case 0x9f38:
            break;
        case 0x9f39:
            memcpy(currentcard->tag_9F39, binarydata, sizeof(currentcard->tag_9F39));
            break;
        case 0x9f40:
            memcpy(currentcard->tag_9F40, binarydata, sizeof(currentcard->tag_9F40));
            break;
        case 0x9f41:
            memcpy(currentcard->tag_9F41, binarydata, sizeof(currentcard->tag_9F41));
            break;
        case 0x9f42:
            memcpy(currentcard->tag_9F42, binarydata, sizeof(currentcard->tag_9F42));
            break;
        case 0x9f43:
            memcpy(currentcard->tag_9F43, binarydata, sizeof(currentcard->tag_9F43));
            break;
        case 0x9f44:
            memcpy(currentcard->tag_9F44, binarydata, sizeof(currentcard->tag_9F44));
            break;
        case 0x9f45:
            memcpy(currentcard->tag_9F45, binarydata, sizeof(currentcard->tag_9F45));
            break;
        case 0x9f46:
            memcpy(currentcard->tag_9F46, binarydata, datalen);
            currentcard->tag_9F46_len = datalen;break;
        case 0x9f47:
            memcpy(currentcard->tag_9F47, binarydata, datalen);
            currentcard->tag_9F47_len = datalen;break;
        case 0x9f48:
            memcpy(currentcard->tag_9F48, binarydata, datalen);
            currentcard->tag_9F48_len = datalen;break;
        case 0x9f49:
            memcpy(currentcard->tag_9F49, binarydata, datalen);
            currentcard->tag_9F49_len = datalen;break;
        case 0x9f4a:
            memcpy(currentcard->tag_9F4A, binarydata, sizeof(currentcard->tag_9F4A));
            break;
        case 0x9f4b:
            memcpy(currentcard->tag_9F4B, binarydata, datalen);
            currentcard->tag_9F4B_len = datalen;break;
        case 0x9f4c:
            memcpy(currentcard->tag_9F4C, binarydata, sizeof(currentcard->tag_9F4C));
            break;
        case 0x9f4d:
            memcpy(currentcard->tag_9F4D, binarydata, sizeof(currentcard->tag_9F4D));
            break;
        case 0x9f4e:
            memcpy(currentcard->tag_9F4E, binarydata, sizeof(currentcard->tag_9F4E));
            break;
        case 0x9f60:
            memcpy(currentcard->tag_9F60, binarydata, sizeof(currentcard->tag_9F60));
            break;
        case 0x9f61:
            memcpy(currentcard->tag_9F61, binarydata, sizeof(currentcard->tag_9F61));
            break;
        case 0x9f62:
            memcpy(currentcard->tag_9F62, binarydata, sizeof(currentcard->tag_9F62));
            break;
        case 0x9f63:
            memcpy(currentcard->tag_9F63, binarydata, sizeof(currentcard->tag_9F63));
            break;
        case 0x9f64:
            memcpy(currentcard->tag_9F64, binarydata, sizeof(currentcard->tag_9F64));
            break;
        case 0x9f65:
            memcpy(currentcard->tag_9F65, binarydata, sizeof(currentcard->tag_9F65));
            break;
        case 0x9f66:
            memcpy(currentcard->tag_9F66, binarydata, sizeof(currentcard->tag_9F66));
            break;
        case 0x9f67:
            memcpy(currentcard->tag_9F67, binarydata, sizeof(currentcard->tag_9F67));
            break;
        case 0x9f68:
            memcpy(currentcard->tag_9F68, binarydata, datalen);
            currentcard->tag_9F68_len = datalen;break;
        case 0x9f69:
            memcpy(currentcard->tag_9F69, binarydata, datalen);
            currentcard->tag_9F69_len = datalen;break;
        case 0x9f6a:
            memcpy(currentcard->tag_9F6A, binarydata, sizeof(currentcard->tag_9F6A));
            break;
        case 0x9f6b:
            memcpy(currentcard->tag_9F6B, binarydata, sizeof(currentcard->tag_9F6B));
            break;
        case 0x9f6c:
            memcpy(currentcard->tag_9F6C, binarydata, sizeof(currentcard->tag_9F6C));
            break;
        case 0xbf0c:
            memcpy(currentcard->tag_BF0C, binarydata, datalen);
            currentcard->tag_BF0C_len = datalen;break;
        default:
            break;
        }
    return 0; 
}

/* generates an emv template based off tag values supplied */ 
int emv_generatetemplate(uint8_t* templateval,emvtags* currentcard, uint8_t* returnedval, uint8_t* returnedlen,uint8_t numtags, ...)
{
    va_list arguments;
    uint8_t* currenttag; //value of the current tag
    uint8_t tagval[255]; //buffer to hold the extracted tag value 
    uint8_t taglen = 0; //extracted tag length 
    uint8_t bufferval[255]; 
    uint8_t counter = 0; 
    uint32_t encodedlen = 0; 
    va_start(arguments, numtags);
    for(int x=0; x<numtags; x++){
        currenttag = va_arg(arguments, uint8_t*);     
        emv_lookuptag(currenttag, currentcard, tagval, &taglen);
        encode_ber_tlv_item(currenttag, (uint8_t)strlen((const char*)currenttag), tagval, (uint32_t)taglen, bufferval+counter, &encodedlen);
        counter +=encodedlen; 
    } 
    encode_ber_tlv_item(templateval, strlen((const char*) templateval), bufferval, counter, returnedval, &encodedlen);   
    *returnedlen = encodedlen; 
    return 0;
}

//generate a valid pdol list
int emv_generateDOL(uint8_t* DOL, uint8_t DOLlen,emvtags* currentcard,uint8_t* DOLoutput, uint8_t* DOLoutputlen)
{
    if(!DOL || !currentcard || !DOLoutput) // null pointer checks
        return 1; 
    //scan through the DOL list and construct the result.
    uint8_t i = 0;
    uint8_t DOLcounter = 0; //points to the current DOL buffer location 
    uint8_t scannedtaglen = 0; //length of a scanned tag
    uint8_t scannedtag[2] = {0x00,0x00}; //buffer for the scanned tag
    uint8_t DOLoutputbuffer[255]; 
    uint8_t retrievedtagvallen; 
    
    memset(DOLoutputbuffer,0x00, 255); //clear the output buffer
    while(i < DOLlen)
    {
        //length of DOL tag 
        if((*(DOL+i) & 0x1F) == 0x1F)
            { scannedtaglen = 2;}
        else
            {scannedtaglen=1;}
        memcpy(scannedtag, DOL+i,scannedtaglen);
        //look up tag value and copy
        //Dbhexdump(2,scannedtag,false); 
        emv_lookuptag(scannedtag,currentcard,&(DOLoutputbuffer[DOLcounter]),&retrievedtagvallen);
        DOLcounter += (uint8_t)DOL[i+scannedtaglen];
        i += scannedtaglen + 1; 
        memset(scannedtag, 0x00, 2); //clear current tag 
         
    }
    memcpy(DOLoutput, DOLoutputbuffer, DOLcounter);
    *DOLoutputlen = DOLcounter; 
    return 0; 
}


//decode the tag inputted and fill in the supplied structure. clean up the cleanup_passpass function
int emv_emvtags_decode_tag(tlvtag* inputtag, emvtags* currentcard)
{
    if(!inputtag || !currentcard) {
        return 1;
    } 
    //scan decoded tag 
    if(*(inputtag->tag) == 0x5F) {
        if(*(inputtag->tag+1) == 0x20){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F20)))
            return 1; 
            memcpy(currentcard->tag_5F20, inputtag->value, inputtag->valuelength);
            currentcard->tag_5F20_len = inputtag->valuelength;
        }
        if(*(inputtag->tag+1) == 0x24){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F24)))
                return 1; 
            memcpy(currentcard->tag_5F24, inputtag->value, sizeof(currentcard->tag_5F24));}
        if(*(inputtag->tag+1) == 0x25){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F25)))
                return 1; 
            memcpy(currentcard->tag_5F25, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x28){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F28)))
                return 1; 
            memcpy(currentcard->tag_5F28, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x2A){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F2A)))
                return 1; 
            memcpy(currentcard->tag_5F2A, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x2D){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F2D)))
                return 1; 
            memcpy(currentcard->tag_5F2D, inputtag->value, inputtag->valuelength);
            currentcard->tag_5F2D_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x30){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F30)))
                return 1; 
            memcpy(currentcard->tag_5F30, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x34){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F34)))
                return 1; 
            memcpy(currentcard->tag_5F34, inputtag->value, sizeof(currentcard->tag_5F34));}
        if(*(inputtag->tag+1) == 0x36){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F36)))
                return 1; 
            memcpy(currentcard->tag_5F36, inputtag->value, sizeof(currentcard->tag_5F36));}
        if(*(inputtag->tag+1) == 0x50){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F50)))
                return 1; 
            memcpy(currentcard->tag_5F50, inputtag->value, inputtag->valuelength);
            currentcard->tag_5F50_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x54){
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_5F54)))
                return 1; 
            memcpy(currentcard->tag_5F54, inputtag->value, inputtag->valuelength);
            currentcard->tag_5F54_len = inputtag->valuelength;}
    }
    if(*(inputtag->tag) == 0x9F){
        if(*(inputtag->tag+1) == 0x01){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F01)))
            return 1; 
        memcpy(currentcard->tag_9F01, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x02){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F02)))
            return 1; 
        memcpy(currentcard->tag_9F02, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x03){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F03)))
            return 1; 
        memcpy(currentcard->tag_9F03, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x04){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F04)))
            return 1; 
        memcpy(currentcard->tag_9F04, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x05){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F05)))
            return 1; 
        memcpy(currentcard->tag_9F05, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F05_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x06){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F06)))
            return 1; 
        memcpy(currentcard->tag_9F06, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F06_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x07){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F07)))
            return 1; 
        memcpy(currentcard->tag_9F07, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x08){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F08)))
            return 1; 
        memcpy(currentcard->tag_9F08, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x09){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F09)))
            return 1; 
        memcpy(currentcard->tag_9F09, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x0B){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F0B)))
            return 1; 
        memcpy(currentcard->tag_9F0B, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F0B_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x0D){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F0D)))
            return 1; 
        memcpy(currentcard->tag_9F0D, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x0E){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F0E)))
            return 1; 
        memcpy(currentcard->tag_9F0E, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x0F){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F0F)))
            return 1; 
        memcpy(currentcard->tag_9F0F, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x11){ 
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F11)))
                return 1; 
            memcpy(currentcard->tag_9F11, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x12){ 
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F12)))
                return 1; 
            memcpy(currentcard->tag_9F12, inputtag->value, inputtag->valuelength);
            currentcard->tag_9F12_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x13){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F13)))
            return 1; 
        memcpy(currentcard->tag_9F13, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x14){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F14)))
            return 1; 
        memcpy(currentcard->tag_9F14, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x15){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F15)))
            return 1; 
        memcpy(currentcard->tag_9F15, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x16){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F16)))
            return 1; 
        memcpy(currentcard->tag_9F16, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x17){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F17)))
            return 1; 
        memcpy(currentcard->tag_9F17, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x18){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F18)))
            return 1; 
        memcpy(currentcard->tag_9F18, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1A){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1A)))
            return 1; 
        memcpy(currentcard->tag_9F1A, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1B){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1B)))
            return 1; 
        memcpy(currentcard->tag_9F1B, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1C){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1C)))
            return 1; 
        memcpy(currentcard->tag_9F1C, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1D){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1D)))
            return 1; 
        memcpy(currentcard->tag_9F1D, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F1D_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x1E){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1E)))
            return 1; 
        memcpy(currentcard->tag_9F1E, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x1F){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F1F)))
            return 1; 
        memcpy(currentcard->tag_9F1F, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F1F_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x32){ 
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F32)))
                return 1; 
            currentcard->tag_9F32_len = inputtag->valuelength; 
            memcpy(currentcard->tag_9F32, inputtag->value, inputtag->valuelength);
        }
        if(*(inputtag->tag+1) == 0x34){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F34)))
            return 1; 
        memcpy(currentcard->tag_9F34, inputtag->value, inputtag->valuelength);}
if(*(inputtag->tag+1) == 0x35){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F35)))
            return 1; 
        memcpy(currentcard->tag_9F35, inputtag->value, inputtag->valuelength);}
if(*(inputtag->tag+1) == 0x37){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F37)))
            return 1; 
        memcpy(currentcard->tag_9F37, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x38){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F38)))
            return 1; 
        memcpy(currentcard->tag_9F38, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F38_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x44){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F44)))
            return 1; 
        memcpy(currentcard->tag_9F44, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x45){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F45)))
            return 1; 
        memcpy(currentcard->tag_9F45, inputtag->value, inputtag->valuelength);}
if(*(inputtag->tag+1) == 0x46){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F46)))
            return 1; 
        memcpy(currentcard->tag_9F46, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F46_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x47){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F47)))
            return 1; 
        memcpy(currentcard->tag_9F47, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F47_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x48){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F48)))
            return 1; 
        memcpy(currentcard->tag_9F48, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F48_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x49){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F49)))
            return 1; 
        memcpy(currentcard->tag_9F49, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F49_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x4A){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F4A)))
            return 1; 
        memcpy(currentcard->tag_9F4A, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x4B){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F4B)))
            return 1; 
        memcpy(currentcard->tag_9F4B, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F4B_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x4C){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F4C)))
            return 1; 
        memcpy(currentcard->tag_9F4C, inputtag->value, inputtag->valuelength);}
if(*(inputtag->tag+1) == 0x60){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F60)))
            return 1; 
        memcpy(currentcard->tag_9F60, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x61){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F61)))
            return 1; 
        memcpy(currentcard->tag_9F61, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x62){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F62)))
            return 1; 
        memcpy(currentcard->tag_9F62, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x63){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F63)))
            return 1; 
        memcpy(currentcard->tag_9F63, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x64){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F64)))
            return 1; 
        memcpy(currentcard->tag_9F64, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x65){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F65)))
            return 1; 
        memcpy(currentcard->tag_9F65, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x66){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F66)))
            return 1; 
        memcpy(currentcard->tag_9F66, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x67){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F67)))
            return 1; 
        memcpy(currentcard->tag_9F67, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x68){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F68)))
            return 1; 
        memcpy(currentcard->tag_9F68, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F68_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x69){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F69)))
            return 1; 
        memcpy(currentcard->tag_9F69, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F69_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x6A){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F6A)))
            return 1; 
        memcpy(currentcard->tag_9F6A, inputtag->value, inputtag->valuelength);}
        if(*(inputtag->tag+1) == 0x6B){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F6B)))
            return 1; 
        memcpy(currentcard->tag_9F6B, inputtag->value, inputtag->valuelength);
        currentcard->tag_9F6B_len = inputtag->valuelength;}
        if(*(inputtag->tag+1) == 0x6C){ 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9F6C)))
            return 1; 
        memcpy(currentcard->tag_9F6C, inputtag->value, inputtag->valuelength);}
}
else 
{ 
    if(*(inputtag->tag) == 0xBF){ //BF0C 
        if(*(inputtag->tag+1) == 0x0C){ 
            if(!(inputtag->valuelength <= sizeof(currentcard->tag_BF0C)))
                return 1; 
            memcpy(currentcard->tag_BF0C, inputtag->value, inputtag->valuelength);
            currentcard->tag_BF0C_len = inputtag->valuelength;}
    }
    else if(*(inputtag->tag) == 0x4F){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_4F)))
            return 1; 
        memcpy(currentcard->tag_4F, inputtag->value, inputtag->valuelength);
        currentcard->tag_4F_len = inputtag->valuelength;}
    else if(*(inputtag->tag) == 0x50){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_50)))
            return 1; 
        memcpy(currentcard->tag_50, inputtag->value, inputtag->valuelength);
        currentcard->tag_50_len = inputtag->valuelength;
    } 
    else if(*(inputtag->tag) == 0x56){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_56)))
            return 1; 
        memcpy(currentcard->tag_56, inputtag->value, inputtag->valuelength);
        currentcard->tag_56_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x57){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_57)))
            return 1; 
        memcpy(currentcard->tag_57, inputtag->value, inputtag->valuelength);
        currentcard->tag_57_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x5A){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_5A)))
            return 1; 
        memcpy(currentcard->tag_5A, inputtag->value, inputtag->valuelength);
        currentcard->tag_5A_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x61){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_61)))
            return 1; 
        memcpy(currentcard->tag_61, inputtag->value, inputtag->valuelength);
        currentcard->tag_61_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x6F){ //BF0C 
        memcpy(currentcard->tag_6F,inputtag->value,inputtag->valuelength);}
    
    else if(*(inputtag->tag) == 0x70){ //BF0C 
        memcpy(currentcard->tag_70,inputtag->value,inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x77){ //BF0C 
        memcpy(currentcard->tag_77,inputtag->value,inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x80){ //BF0C 
        memcpy(currentcard->tag_80,inputtag->value,inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x82){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_82)))
            return 1; 
        memcpy(currentcard->tag_82, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x84){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_84)))
            return 1; 
        memcpy(currentcard->tag_84, inputtag->value, inputtag->valuelength);
        currentcard->tag_84_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x86){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_86)))
            return 1; 
        memcpy(currentcard->tag_86, inputtag->value, inputtag->valuelength);
        currentcard->tag_86_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x87){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_87)))
            return 1; 
        memcpy(currentcard->tag_87, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x88){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_88)))
            return 1; 
        memcpy(currentcard->tag_88, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x8A){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8A)))
            return 1; 
        memcpy(currentcard->tag_8A, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x8C){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8C)))
            return 1; 
        memcpy(currentcard->tag_8C, inputtag->value, inputtag->valuelength);
        currentcard->tag_8C_len = inputtag->valuelength;
    }    
    else if(*(inputtag->tag) == 0x8D){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8D)))
            return 1; 
        memcpy(currentcard->tag_8D, inputtag->value, inputtag->valuelength);
        currentcard->tag_8D_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x8E){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8E)))
            return 1; 
        memcpy(currentcard->tag_8E, inputtag->value, inputtag->valuelength);
        currentcard->tag_8E_len = inputtag->valuelength;
    }
    else if(*(inputtag->tag) == 0x8F){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_8F)))
            return 1; 
        memcpy(currentcard->tag_8F,inputtag->value,sizeof(currentcard->tag_8F));}
    else if(*(inputtag->tag) == 0x90){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_90)))
            return 1; 
        memcpy(currentcard->tag_90, inputtag->value, inputtag->valuelength);
        currentcard->tag_90_len = inputtag->valuelength;}
    else if(*(inputtag->tag) == 0x92){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_92)))
            return 1; 
        memcpy(currentcard->tag_92, inputtag->value, inputtag->valuelength);
        currentcard->tag_92_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x93){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_93)))
            return 1; 
        memcpy(currentcard->tag_93, inputtag->value, inputtag->valuelength);
        currentcard->tag_93_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x94){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_94)))
            return 1; 
        memcpy(currentcard->tag_94, inputtag->value, inputtag->valuelength);
        currentcard->tag_94_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x95){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_95)))
            return 1; 
        memcpy(currentcard->tag_95, inputtag->value, inputtag->valuelength);} 
    else if(*(inputtag->tag) == 0x97){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_97)))
            return 1; 
        memcpy(currentcard->tag_97, inputtag->value, inputtag->valuelength);
        currentcard->tag_97_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x98){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_98)))
            return 1; 
        memcpy(currentcard->tag_98, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x99){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_99)))
            return 1; 
        memcpy(currentcard->tag_99, inputtag->value, inputtag->valuelength);
        currentcard->tag_99_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0x9A){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9A)))
            return 1; 
        memcpy(currentcard->tag_9A, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x9B){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9B)))
            return 1; 
        memcpy(currentcard->tag_9B, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x9C){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9C)))
            return 1; 
        memcpy(currentcard->tag_9C, inputtag->value, inputtag->valuelength);}
    else if(*(inputtag->tag) == 0x9D){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_9D)))
            return 1; 
        memcpy(currentcard->tag_9D, inputtag->value, inputtag->valuelength);
        currentcard->tag_9D_len = inputtag->valuelength;} 
    else if(*(inputtag->tag) == 0xA5){ //BF0C 
        if(!(inputtag->valuelength <= sizeof(currentcard->tag_A5)))
            return 1; 
        memcpy(currentcard->tag_A5, inputtag->value, inputtag->valuelength);
        currentcard->tag_A5_len = inputtag->valuelength;}
   } 
   return 0;
}

int emv_decode_field(uint8_t* inputfield,uint16_t inputlength, emvtags *result)
{
    uint16_t lengthcounter=0; 
    tlvtag newtag; 
    //copy result to the testtag
    if(!result){
        return 1;
    } 
    //loop through and decode template 
    while(lengthcounter < inputlength)
    {
        //decode the tlv tag 
        decode_ber_tlv_item((inputfield+lengthcounter),&newtag);
        //write the emvtags strucutre 
        emv_emvtags_decode_tag(&newtag,result); 
        //move to next value and decode 
        lengthcounter += newtag.fieldlength-1; 
    }
    return 0;
}

int emv_select(uint8_t* AID, uint8_t AID_len, void* data)
{
    uint16_t selectCmd_len = 4 + 1 + AID_len + 1; 
    uint8_t selectCmd[selectCmd_len];
    
    selectCmd[0] = 0x00;
    selectCmd[1] = 0xA4;
    selectCmd[2] = 0x04;
    selectCmd[3] = 0x00;
    selectCmd[4] = AID_len;
    memcpy(&(selectCmd[5]), AID, AID_len);
    selectCmd[selectCmd_len-1] = 0x00;
    return iso14_apdu(selectCmd,selectCmd_len,false, 0,data);
}

//perform READ RECORD
int emv_readrecord(uint8_t recordnumber, uint8_t sfi, void* data)
{
    uint16_t readRecordCmd_len = 5; 
    uint8_t readRecordCmd[readRecordCmd_len];
    
    readRecordCmd[0] = 0x00;
    readRecordCmd[1] = 0xB2;
    readRecordCmd[2] = recordnumber;
    readRecordCmd[3] = ((sfi << 3) | 0x04);
    readRecordCmd[4] = 0x00;
    return iso14_apdu(readRecordCmd,readRecordCmd_len,false,0,data); 
}

int emv_getprocessingoptions(uint8_t* pdol, uint8_t pdol_len, void* data)
{
    uint16_t processingCmd_len = 4 + 1 + 2 + pdol_len + 1; 
    uint8_t processingCmd[processingCmd_len];
    
    processingCmd[0] = 0x80;
    processingCmd[1] = 0xA8;
    processingCmd[2] = 0x00;
    processingCmd[3] = 0x00; 
    processingCmd[4] = pdol_len + 2; 
    processingCmd[5] = 0x83; //template
    processingCmd[6] = pdol_len;
    if(pdol_len > 0){ 
        memcpy(&(processingCmd[7]), pdol, pdol_len);}
    processingCmd[processingCmd_len] = 0x00; 
    //Dbhexdump(processingCmd_len, processingCmd, false); 
    return iso14_apdu(processingCmd,processingCmd_len,false, 0, data);
}

int emv_computecryptogram(uint8_t* UDOL, uint8_t UDOL_len, void *data)
{
    uint16_t cryptogramCmd_len = 4 + 1 + UDOL_len + 1; 
    uint8_t cryptogramCmd[cryptogramCmd_len];
    
    cryptogramCmd[0] = 0x80;
    cryptogramCmd[1] = 0x2A;
    cryptogramCmd[2] = 0x8E;
    cryptogramCmd[3] = 0x80; 
    cryptogramCmd[4] = UDOL_len;
    memcpy(&(cryptogramCmd[5]), UDOL, UDOL_len);
    cryptogramCmd[cryptogramCmd_len-1] = 0x00;
 
    return iso14_apdu(cryptogramCmd,cryptogramCmd_len,false, 0,data);
}

int emv_getchallenge(void *data)
{
    uint16_t challengeCmd_len = 5; 
    uint8_t challengeCmd[challengeCmd_len];
    
    challengeCmd[0] = 0x00;
    challengeCmd[1] = 0x84;
    challengeCmd[2] = 0x00;
    challengeCmd[3] = 0x00; 
    challengeCmd[4] = 0x00;
     
    return iso14_apdu(challengeCmd,challengeCmd_len,false, 0,data);
}

int emv_loopback(uint8_t* transData , uint8_t transData_len, void *data)
{
    uint16_t loopbackCmd_len = 4 + 1 + transData_len + 1; 
    uint8_t loopbackCmd[loopbackCmd_len];
    
    loopbackCmd[0] = 0x00;
    loopbackCmd[1] = 0xEE;
    loopbackCmd[2] = 0x00;
    loopbackCmd[3] = 0x00; 
    loopbackCmd[4] = loopbackCmd_len;
    memcpy(&(loopbackCmd[5]), transData, transData_len);  
    return iso14_apdu(loopbackCmd,loopbackCmd_len,false, 0,data);
}

//generateAC
int emv_generateAC(uint8_t refcontrolparam, uint8_t* cdolinput, uint8_t cdolinputlen, void* data)
{
    uint16_t acCmd_len = 4 + 1 + cdolinputlen + 1; 
    uint8_t acCmd[acCmd_len];
    
    acCmd[0] = 0x80;
    acCmd[1] = 0xAE;
    acCmd[2] = refcontrolparam;
    acCmd[3] = 0x00; 
    acCmd[4] = cdolinputlen;
    memcpy(&(acCmd[5]), cdolinput, cdolinputlen);  
    acCmd[acCmd_len-1] = 0x00;
    Dbhexdump(acCmd_len, acCmd,false); 
    return iso14_apdu(acCmd,acCmd_len,false,0,data);
}

int emv_decodeAFL(uint8_t* AFL, uint8_t AFLlen )
{

    return 0;
}

//Print out AIP Bit meanings
int emv_decodeAIP(uint8_t* AIP)
{
    if((AIP[0] & AIP_SDA_SUPPORTED) == AIP_SDA_SUPPORTED)
        Dbprintf("SDA supported");
    if((AIP[0] & AIP_DDA_SUPPORTED) == AIP_DDA_SUPPORTED)
        Dbprintf("DDA supported");  
    if((AIP[0] & AIP_CARDHOLDER_VERIFICATION)==AIP_CARDHOLDER_VERIFICATION)
        Dbprintf("Cardholder verification is supported");  
    if((AIP[0] & AIP_TERMINAL_RISK) == AIP_TERMINAL_RISK)
        Dbprintf("Terminal risk management is to be performed");  
    if((AIP[0] & AIP_ISSUER_AUTH) == AIP_ISSUER_AUTH)
        Dbprintf("Issuer authentication is supported ");  
    if((AIP[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED)
        Dbprintf("CDA supported");  
    if((AIP[1] & AIP_CHIP_SUPPORTED) == AIP_CHIP_SUPPORTED)
        Dbprintf("Chip supported");
    if((AIP[1] & AIP_MSR_SUPPORTED) == AIP_MSR_SUPPORTED)
        Dbprintf("MSR supported"); 
    return 0;
}

int emv_decodeCVM(uint8_t* CVM, uint8_t CVMlen)
{
    uint8_t counter = 0;
    uint32_t amountX = 0;
    uint32_t amountY = 0; 
    amountX = bytes_to_num(CVM, 4);
    amountY = bytes_to_num(CVM+4, 4); 
    counter +=8;
    while(counter < CVMlen)
    {
        if((CVM[counter] & 0x40) == 0x40){
            if((CVM[counter] & 0x3F)== 0x00){
                Dbprintf("Fail CVM processing");
            }
            if((CVM[counter] & 0x3F) == 0x01){
                Dbprintf("Plaintext PIN verification performed by ICC");
            }
            if((CVM[counter] & 0x3F) == 0x02){
                Dbprintf("Enciphered PIN verified online");
            }
            if((CVM[counter] & 0x3F) == 0x03){
                Dbprintf("Plaintext PIN verification performed by ICC and signature (paper)");
            }
            if((CVM[counter] & 0x3F) == 0x04){
                Dbprintf("Enciphered PIN verification performed by ICC");
            }  
            if((CVM[counter] & 0x3F) == 0x05){
                Dbprintf("Enciphered PIN verification performed by ICC and signature (paper)");
            }  
            if((CVM[counter] & 0x3F) == 0x30){
                Dbprintf("Signature (paper)");
            }  
            if((CVM[counter] & 0x3F) == 0x40){
                Dbprintf("No CVM required");
            }
            counter +=2; 
        }
        else{
            Dbprintf("Fail cardholder verification if this CVM is unsuccessful"); 
            counter +=2; 
        }
        if(CVM[counter+1] == 0x00){
            Dbprintf("Always");}
        if(CVM[counter+1] == 0x01){
            Dbprintf("If unattended cash");}
        if(CVM[counter+1] == 0x02){
            Dbprintf("If not unattended cash and not manual cash and not purchase with cashback");}
        if(CVM[counter+1] == 0x03){
            Dbprintf("If terminal supports the CVM");}
        if(CVM[counter+1] == 0x04){
            Dbprintf("If manual cash");}
        if(CVM[counter+1] == 0x05){
            Dbprintf("If purchase with cashback");}
        if(CVM[counter+1] == 0x06){
            Dbprintf("If transaction is in the application currency and is under %lu value", amountX);}
         if(CVM[counter+1] == 0x07){
            Dbprintf("If transaction is in the application currency and is over %lu value", amountX);}
         if(CVM[counter+1] == 0x08){
            Dbprintf("If transaction is in the application currency and is under %lu value", amountY);}
         if(CVM[counter+1] == 0x09){
            Dbprintf("If transaction is in the application currency and is over %lu value", amountY);}
     }
    return 0;
}

//dump the current card to the console
void dumpCard(emvtags* currentcard){
    DUMP(currentcard->ATQA);
    Dbhexdump(sizeof(currentcard->ATQA), currentcard->ATQA, false);
    DUMP(currentcard->UID);
    Dbhexdump(currentcard->UID_len,  currentcard->UID, false);
    DUMP(currentcard->SAK1);
    Dbhexdump(1,  &currentcard->SAK1, false);
    DUMP(currentcard->SAK2);
    Dbhexdump(1,  &currentcard->SAK2, false);
    DUMP(currentcard->ATS);
    Dbhexdump(currentcard->ATS_len,  currentcard->ATS, false);
    
    DUMP(currentcard->tag_4F);
    Dbhexdump(currentcard->tag_4F_len,  currentcard->tag_4F, false);
    DUMP(currentcard->tag_50);
    Dbhexdump(currentcard->tag_50_len,  currentcard->tag_50, false);
    DUMP(currentcard->tag_56);
    Dbhexdump(currentcard->tag_56_len,  currentcard->tag_56, false);
    DUMP(currentcard->tag_57);
    Dbhexdump(currentcard->tag_57_len,  currentcard->tag_57, false);
    DUMP(currentcard->tag_5A);
    Dbhexdump(currentcard->tag_5A_len,  currentcard->tag_5A, false);
    DUMP(currentcard->tag_82);
    Dbhexdump(sizeof(currentcard->tag_82),  currentcard->tag_82, false);
    DUMP(currentcard->tag_84);
    Dbhexdump(currentcard->tag_84_len,  currentcard->tag_84, false);
    DUMP(currentcard->tag_86);
    Dbhexdump(currentcard->tag_86_len,  currentcard->tag_86, false);
    DUMP(currentcard->tag_87);
    Dbhexdump(1,  currentcard->tag_87, false);
DUMP(currentcard->tag_88);
    Dbhexdump(1,  currentcard->tag_88, false);
DUMP(currentcard->tag_8A);
    Dbhexdump(2,  currentcard->tag_8A, false); 
    DUMP(currentcard->tag_8C);
    Dbhexdump(currentcard->tag_8C_len,  currentcard->tag_8C, false);
    DUMP(currentcard->tag_8D);
    Dbhexdump(currentcard->tag_8D_len,  currentcard->tag_8D, false);
    DUMP(currentcard->tag_8E);
    Dbhexdump(currentcard->tag_8E_len,  currentcard->tag_8E, false);
    DUMP(currentcard->tag_8F);
    Dbhexdump(1,  currentcard->tag_8F, false);   
    DUMP(currentcard->tag_90);
    Dbhexdump(currentcard->tag_90_len,  currentcard->tag_90, false);
    DUMP(currentcard->tag_92);
    Dbhexdump(currentcard->tag_92_len,  currentcard->tag_92, false);
    DUMP(currentcard->tag_93);
    Dbhexdump(currentcard->tag_93_len,  currentcard->tag_93, false);
    DUMP(currentcard->tag_94);
    Dbhexdump(currentcard->tag_94_len,  currentcard->tag_94, false);
    DUMP(currentcard->tag_95);
    Dbhexdump(5,  currentcard->tag_95, false);
    DUMP(currentcard->tag_97);
    Dbhexdump(currentcard->tag_97_len,  currentcard->tag_97, false);
    DUMP(currentcard->tag_98);
    Dbhexdump(20, currentcard->tag_98, false);
    DUMP(currentcard->tag_99);
    Dbhexdump(currentcard->tag_99_len,  currentcard->tag_99, false);
    DUMP(currentcard->tag_9A);
    Dbhexdump(3,  currentcard->tag_9A, false);
    DUMP(currentcard->tag_9B);
    Dbhexdump(2,  currentcard->tag_9B, false);
    DUMP(currentcard->tag_9C);
    Dbhexdump(1,  currentcard->tag_9C, false);
    DUMP(currentcard->tag_9D);
    Dbhexdump(currentcard->tag_9D_len,  currentcard->tag_9D, false);
    DUMP(currentcard->tag_CD);
    Dbhexdump(3,  currentcard->tag_CD, false);
    DUMP(currentcard->tag_CE);
    Dbhexdump(3,  currentcard->tag_CE, false);
    DUMP(currentcard->tag_CF);
    Dbhexdump(3,  currentcard->tag_CF, false);
    DUMP(currentcard->tag_D7);
    Dbhexdump(3,  currentcard->tag_D7, false);
    DUMP(currentcard->tag_D8);
    Dbhexdump(2,  currentcard->tag_D8, false);
    DUMP(currentcard->tag_D9);
    Dbhexdump(currentcard->tag_D9_len,  currentcard->tag_D9, false);
    DUMP(currentcard->tag_DA);
    Dbhexdump(2,  currentcard->tag_DA, false);
    DUMP(currentcard->tag_DB);
    Dbhexdump(2,  currentcard->tag_DB, false);
    DUMP(currentcard->tag_DC);
    Dbhexdump(2,  currentcard->tag_DC, false);
    DUMP(currentcard->tag_DD);
    Dbhexdump(2,  currentcard->tag_DD, false);    
    DUMP(currentcard->tag_AF);
    Dbhexdump(currentcard->tag_AF_len,  currentcard->tag_AF, false);
    DUMP(currentcard->tag_5F20);
    Dbhexdump(currentcard->tag_5F20_len,  currentcard->tag_5F20, false);
    DUMP(currentcard->tag_5F24);
    Dbhexdump(3,  currentcard->tag_5F24, false);
    DUMP(currentcard->tag_5F25);
    Dbhexdump(3,  currentcard->tag_5F25, false);
    DUMP(currentcard->tag_5F28);
    Dbhexdump(2,  currentcard->tag_5F28, false);
    DUMP(currentcard->tag_5F2A);
    Dbhexdump(2,  currentcard->tag_5F2A, false);
    DUMP(currentcard->tag_5F2D);
    Dbhexdump(currentcard->tag_5F2D_len,  currentcard->tag_5F2D, false);
    DUMP(currentcard->tag_5F30);
    Dbhexdump(3,  currentcard->tag_5F30, false);
    DUMP(currentcard->tag_5F34);
    Dbhexdump(1,  currentcard->tag_5F34, false);
    DUMP(currentcard->tag_5F36);
    Dbhexdump(2,  currentcard->tag_5F36, false);    
    DUMP(currentcard->tag_5F50);
    Dbhexdump(currentcard->tag_5F50_len,  currentcard->tag_5F50, false);
    DUMP(currentcard->tag_5F54);
    Dbhexdump(currentcard->tag_5F54_len,  currentcard->tag_5F54, false);
    DUMP(currentcard->tag_9F01);
    Dbhexdump(6,  currentcard->tag_9F01, false);
    DUMP(currentcard->tag_9F02);
    Dbhexdump(6,  currentcard->tag_9F02, false);
    DUMP(currentcard->tag_9F03);
    Dbhexdump(6,  currentcard->tag_9F03, false);
    DUMP(currentcard->tag_9F04);
    Dbhexdump(4,  currentcard->tag_9F04, false);
    DUMP(currentcard->tag_9F05);
    Dbhexdump(currentcard->tag_9F05_len,  currentcard->tag_9F05, false);
    DUMP(currentcard->tag_9F06);
    Dbhexdump(currentcard->tag_9F06_len,  currentcard->tag_9F06, false);
    DUMP(currentcard->tag_9F07);
    Dbhexdump(2,  currentcard->tag_9F07, false);
    DUMP(currentcard->tag_9F08);
    Dbhexdump(2,  currentcard->tag_9F08, false);
    DUMP(currentcard->tag_9F09);
    Dbhexdump(2,  currentcard->tag_9F09, false);
    DUMP(currentcard->tag_9F0B);
    Dbhexdump(currentcard->tag_9F0B_len,  currentcard->tag_9F0B, false);
    DUMP(currentcard->tag_9F0D);
    Dbhexdump(5,  currentcard->tag_9F0D, false);
    DUMP(currentcard->tag_9F0E);
    Dbhexdump(5,  currentcard->tag_9F0E, false);
    DUMP(currentcard->tag_9F0F);
    Dbhexdump(5,  currentcard->tag_9F0F, false);
    DUMP(currentcard->tag_9F10);
    Dbhexdump(currentcard->tag_9F10_len,  currentcard->tag_9F10, false);
    DUMP(currentcard->tag_9F11);
    Dbhexdump(1,  currentcard->tag_9F11, false);
    DUMP(currentcard->tag_9F12);
    Dbhexdump(currentcard->tag_9F12_len,  currentcard->tag_9F12, false);
    DUMP(currentcard->tag_9F13);
    Dbhexdump(2,  currentcard->tag_9F13, false);
    DUMP(currentcard->tag_9F14);
    Dbhexdump(1,  currentcard->tag_9F14, false);
    DUMP(currentcard->tag_9F15);
    Dbhexdump(2,  currentcard->tag_9F15, false);
    DUMP(currentcard->tag_9F16);
    Dbhexdump(15,  currentcard->tag_9F16, false);
    DUMP(currentcard->tag_9F17);
    Dbhexdump(1,  currentcard->tag_9F17, false);
    DUMP(currentcard->tag_9F18);
    Dbhexdump(4,  currentcard->tag_9F18, false);
    DUMP(currentcard->tag_9F1A);
    Dbhexdump(2,  currentcard->tag_9F1A, false);
    DUMP(currentcard->tag_9F1B);
    Dbhexdump(4,  currentcard->tag_9F1B, false);
    DUMP(currentcard->tag_9F1C);
    Dbhexdump(8,  currentcard->tag_9F1C, false);
    DUMP(currentcard->tag_9F1D);
    Dbhexdump(currentcard->tag_9F1D_len,  currentcard->tag_9F1D, false);
    DUMP(currentcard->tag_9F1E);
    Dbhexdump(8,  currentcard->tag_9F1E, false);
    DUMP(currentcard->tag_9F1F);
    Dbhexdump(currentcard->tag_9F1F_len,  currentcard->tag_9F1F, false);
    DUMP(currentcard->tag_9F20);
    Dbhexdump(currentcard->tag_9F20_len,  currentcard->tag_9F20, false);
    DUMP(currentcard->tag_9F21);
    Dbhexdump(3,  currentcard->tag_9F1E, false);
    DUMP(currentcard->tag_9F22);
    Dbhexdump(1,  currentcard->tag_9F22, false);
    DUMP(currentcard->tag_9F23);
    Dbhexdump(1,  currentcard->tag_9F23, false);
    DUMP(currentcard->tag_9F26);
    Dbhexdump(8,  currentcard->tag_9F26, false);
    DUMP(currentcard->tag_9F27);
    Dbhexdump(1,  currentcard->tag_9F27, false);
    DUMP(currentcard->tag_9F2D);
    Dbhexdump(currentcard->tag_9F2D_len,  currentcard->tag_9F2D, false);
    DUMP(currentcard->tag_9F2E);
    Dbhexdump(3,  currentcard->tag_9F2E, false);
    DUMP(currentcard->tag_9F2F);
    Dbhexdump(currentcard->tag_9F2F_len,  currentcard->tag_9F2F, false);
    DUMP(currentcard->tag_9F32);
    Dbhexdump(currentcard->tag_9F32_len,  currentcard->tag_9F32, false);
    DUMP(currentcard->tag_9F33);
    Dbhexdump(3,  currentcard->tag_9F33, false);
    DUMP(currentcard->tag_9F34);
    Dbhexdump(3,  currentcard->tag_9F34, false);
    DUMP(currentcard->tag_9F35);
    Dbhexdump(1,  currentcard->tag_9F35, false);
    DUMP(currentcard->tag_9F36);
    Dbhexdump(2,  currentcard->tag_9F36, false);
    DUMP(currentcard->tag_9F37);
    Dbhexdump(4,  currentcard->tag_9F37, false);
    DUMP(currentcard->tag_9F38);
    Dbhexdump(currentcard->tag_9F38_len,  currentcard->tag_9F38, false);
    DUMP(currentcard->tag_9F39);
    Dbhexdump(1,  currentcard->tag_9F39, false);
    DUMP(currentcard->tag_9F39);
    Dbhexdump(1,  currentcard->tag_9F39, false);
    DUMP(currentcard->tag_9F40);
    Dbhexdump(5,  currentcard->tag_9F40, false);
    DUMP(currentcard->tag_9F41);
    Dbhexdump(4,  currentcard->tag_9F41, false);
    DUMP(currentcard->tag_9F42);
    Dbhexdump(2,  currentcard->tag_9F42, false);
    DUMP(currentcard->tag_9F43);
    Dbhexdump(4,  currentcard->tag_9F43, false);
    DUMP(currentcard->tag_9F44);
    Dbhexdump(1,  currentcard->tag_9F44, false);
    DUMP(currentcard->tag_9F45);
    Dbhexdump(2,  currentcard->tag_9F45, false);
    DUMP(currentcard->tag_9F46);
    Dbhexdump(currentcard->tag_9F46_len,  currentcard->tag_9F46, false);
    DUMP(currentcard->tag_9F47);
    Dbhexdump(currentcard->tag_9F47_len,  currentcard->tag_9F47, false);
    DUMP(currentcard->tag_9F48);
    Dbhexdump(currentcard->tag_9F48_len,  currentcard->tag_9F48, false);
    DUMP(currentcard->tag_9F49);
    Dbhexdump(currentcard->tag_9F49_len,  currentcard->tag_9F49, false);
    DUMP(currentcard->tag_9F4A);
    Dbhexdump(1,  currentcard->tag_9F4A, false); 
    DUMP(currentcard->tag_9F4B);
    Dbhexdump(currentcard->tag_9F4B_len,  currentcard->tag_9F4B, false);
    DUMP(currentcard->tag_9F4C);
    Dbhexdump(8,  currentcard->tag_9F4C, false);
    DUMP(currentcard->tag_9F4D);
    Dbhexdump(2,  currentcard->tag_9F4D, false);
    DUMP(currentcard->tag_9F4E);
    Dbhexdump(255,  currentcard->tag_9F4E, false);
    DUMP(currentcard->tag_9F60);
    Dbhexdump(2,  currentcard->tag_9F60, false);
    DUMP(currentcard->tag_9F61);
    Dbhexdump(2,  currentcard->tag_9F61, false);
    DUMP(currentcard->tag_9F62);
    Dbhexdump(6,  currentcard->tag_9F62, false);
    DUMP(currentcard->tag_9F63);
    Dbhexdump(6,  currentcard->tag_9F63, false);
    DUMP(currentcard->tag_9F64);
    Dbhexdump(1,  currentcard->tag_9F64, false);
    DUMP(currentcard->tag_9F65);
    Dbhexdump(2,  currentcard->tag_9F65, false);
    DUMP(currentcard->tag_9F66);
    Dbhexdump(2,  currentcard->tag_9F66, false);
    DUMP(currentcard->tag_9F67);
    Dbhexdump(1,  currentcard->tag_9F67, false);
    DUMP(currentcard->tag_9F68);
    Dbhexdump(currentcard->tag_9F68_len,  currentcard->tag_9F68, false);
    DUMP(currentcard->tag_9F69);
    Dbhexdump(currentcard->tag_9F69_len,  currentcard->tag_9F69, false);
    DUMP(currentcard->tag_9F6A);
    Dbhexdump(8,  currentcard->tag_9F6A, false);
    DUMP(currentcard->tag_9F6B);
    Dbhexdump(currentcard->tag_9F6B_len,  currentcard->tag_9F6B, false);
    DUMP(currentcard->tag_9F6C);
    Dbhexdump(2,  currentcard->tag_9F6C, false);
    DUMP(currentcard->tag_61);
    Dbhexdump(currentcard->tag_61_len,  currentcard->tag_61, false);
    DUMP(currentcard->tag_A5);
    Dbhexdump(currentcard->tag_A5_len,  currentcard->tag_A5, false);
    DUMP(currentcard->tag_DFNAME);
    Dbhexdump(currentcard->tag_DFNAME_len,  currentcard->tag_DFNAME, false);
    DUMP(currentcard->tag_70);
    Dbhexdump(currentcard->tag_70_len,  currentcard->tag_70, false);
    DUMP(currentcard->tag_77);
    Dbhexdump(currentcard->tag_77_len,  currentcard->tag_77, false);
    DUMP(currentcard->tag_80);
    Dbhexdump(currentcard->tag_80_len,  currentcard->tag_80, false);
    DUMP(currentcard->tag_91);
    Dbhexdump(currentcard->tag_91_len,  currentcard->tag_91, false);
    DUMP(currentcard->tag_BF0C);
    Dbhexdump(currentcard->tag_BF0C_len,  currentcard->tag_BF0C, false);
    DUMP(currentcard->tag_DFName);
    Dbhexdump(currentcard->tag_DFName_len,  currentcard->tag_DFName, false);
}


