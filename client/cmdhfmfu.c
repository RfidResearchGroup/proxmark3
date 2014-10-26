//-----------------------------------------------------------------------------
// Ultralight Code (c) 2013,2014 Midnitesnake & Andy Davies of Pentura
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE ULTRALIGHT (C) commands
//-----------------------------------------------------------------------------
#include <openssl/des.h>
#include "cmdhfmf.h"

uint8_t MAX_ULTRA_BLOCKS= 0x0f;
uint8_t MAX_ULTRAC_BLOCKS= 0x2c;
uint8_t key1_blnk_data[16] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
uint8_t key2_defa_data[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
uint8_t key3_3des_data[16] = { 0x49,0x45,0x4D,0x4B,0x41,0x45,0x52,0x42,0x21,0x4E,0x41,0x43,0x55,0x4F,0x59,0x46 };
uint8_t key4_nfc_data[16]  = { 0x42,0x52,0x45,0x41,0x4b,0x4d,0x45,0x49,0x46,0x59,0x4f,0x55,0x43,0x41,0x4e,0x21 };
uint8_t key5_ones_data[16] = { 0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01 };

static int CmdHelp(const char *Cmd);

//
//  Mifare Ultralight Write Single Block
//
int CmdHF14AMfUWrBl(const char *Cmd){
    uint8_t blockNo    = 0;
    bool chinese_card  = 0;
    uint8_t bldata[16] = {0x00};
    UsbCommand resp;
        
    if (strlen(Cmd)<3) {
        PrintAndLog("Usage:  hf mfu uwrbl <block number> <block data (8 hex symbols)> [w]");
        PrintAndLog("        sample: hf mfu uwrbl 0 01020304");
        return 0;
    }       
    blockNo = param_get8(Cmd, 0);
    if (blockNo>MAX_ULTRA_BLOCKS){
        PrintAndLog("Error: Maximum number of blocks is 15 for Ultralight Cards!");
        return 1;
    }
    if (param_gethex(Cmd, 1, bldata, 8)) {
        PrintAndLog("Block data must include 8 HEX symbols");
        return 1;
    }
    if (strchr(Cmd,'w') != 0) {
        chinese_card=1; 
    }
    switch(blockNo){
        case 0:
            if (!chinese_card){
                PrintAndLog("Access Denied");
            }else{
                PrintAndLog("--specialblock no:%02x", blockNo);
                PrintAndLog("--data: %s", sprint_hex(bldata, 4));
                UsbCommand d = {CMD_MIFAREU_WRITEBL, {blockNo}};
                memcpy(d.d.asBytes,bldata, 4);
                SendCommand(&d);
                if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
                    uint8_t isOK  = resp.arg[0] & 0xff;
                    PrintAndLog("isOk:%02x", isOK);
                } else {
                    PrintAndLog("Command execute timeout");
                }  
            }
            break;
        case 1:
	    if (!chinese_card){
	        PrintAndLog("Access Denied");
	    }else{	
	        PrintAndLog("--specialblock no:%02x", blockNo);
                PrintAndLog("--data: %s", sprint_hex(bldata, 4));
                UsbCommand d = {CMD_MIFAREU_WRITEBL, {blockNo}};
                memcpy(d.d.asBytes,bldata, 4);
                SendCommand(&d);
                if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
                    uint8_t isOK  = resp.arg[0] & 0xff;
                    PrintAndLog("isOk:%02x", isOK);
                } else {
                    PrintAndLog("Command execute timeout");
                }
	    }
	    break;
	case 2:
	    if (!chinese_card){
	        PrintAndLog("Access Denied");
	    }else{	
	        PrintAndLog("--specialblock no:%02x", blockNo);
                PrintAndLog("--data: %s", sprint_hex(bldata, 4));
                UsbCommand c = {CMD_MIFAREU_WRITEBL, {blockNo}};
                memcpy(c.d.asBytes, bldata, 4);
                SendCommand(&c);
                if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
                    uint8_t isOK  = resp.arg[0] & 0xff;
                    PrintAndLog("isOk:%02x", isOK);
                } else {
                    PrintAndLog("Command execute timeout");
                }
	    }
	    break;
	case 3:
	    PrintAndLog("--specialblock no:%02x", blockNo);
            PrintAndLog("--data: %s", sprint_hex(bldata, 4));
            UsbCommand d = {CMD_MIFAREU_WRITEBL, {blockNo}};
            memcpy(d.d.asBytes,bldata, 4);
            SendCommand(&d);
            if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
                uint8_t isOK  = resp.arg[0] & 0xff;
                PrintAndLog("isOk:%02x", isOK);
            } else {
                PrintAndLog("Command execute timeout");
            }
            break;
	default: 
	    PrintAndLog("--block no:%02x", blockNo);
	    PrintAndLog("--data: %s", sprint_hex(bldata, 4));        	
	    UsbCommand e = {CMD_MIFAREU_WRITEBL, {blockNo}};
            memcpy(e.d.asBytes,bldata, 4);
            SendCommand(&e);
        if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
            uint8_t isOK  = resp.arg[0] & 0xff;
            PrintAndLog("isOk:%02x", isOK);
        } else {
            PrintAndLog("Command execute timeout");
        }
        break;
    }
    return 0;
}

//
//  Mifare Ultralight Read Single Block
//
int CmdHF14AMfURdBl(const char *Cmd){
  
    uint8_t blockNo = 0;	
        
    if (strlen(Cmd)<1) {
        PrintAndLog("Usage:  hf mfu urdbl    <block number>");
        PrintAndLog("        sample: hfu mfu urdbl 0");
        return 0;
    }       
        
    blockNo = param_get8(Cmd, 0);
    // if (blockNo>MAX_ULTRA_BLOCKS){
       // PrintAndLog("Error: Maximum number of blocks is 15 for Ultralight Cards!");
       // return 1;
    // }
    PrintAndLog("--block no:%02x", (int)blockNo);
    UsbCommand c = {CMD_MIFAREU_READBL, {blockNo}};
    SendCommand(&c);

    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
        uint8_t isOK    = resp.arg[0] & 0xff;
        uint8_t * data  = resp.d.asBytes;

        if (isOK)
            PrintAndLog("isOk:%02x data:%s", isOK, sprint_hex(data, 4));
        else
	    PrintAndLog("isOk:%02x", isOK);
        } else {
                PrintAndLog("Command execute timeout");
        }
    return 0;
}

//
//  Mifare Ultralight Read (Dump) Card Contents
//
int CmdHF14AMfURdCard(const char *Cmd){
    int i;
    uint8_t BlockNo = 0;
    int Pages=16;
    uint8_t *lockbytes_t=NULL;
    uint8_t lockbytes[2]={0x00};
    bool bit[16]={0x00};
    bool dump=false;
    uint8_t datatemp[7]= {0x00};
        
    uint8_t isOK  = 0;
    uint8_t * data  = NULL;
    FILE *fout = NULL;

    if (strchr(Cmd,'x') != 0){
        dump=true;
        if ((fout = fopen("dump_ultralight_data.bin","wb")) == NULL) { 
            PrintAndLog("Could not create file name dumpdata.bin");
            return 1;	
        }
        PrintAndLog("Dumping Ultralight Card Data...");
    }
    PrintAndLog("Attempting to Read Ultralight... ");
    UsbCommand c = {CMD_MIFAREU_READCARD, {BlockNo, Pages}};
    SendCommand(&c);
    UsbCommand resp;

    if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
        isOK  = resp.arg[0] & 0xff;
        data  = resp.d.asBytes;
        PrintAndLog("isOk:%02x", isOK);
        if (isOK) {
		
			// UID
			memcpy( datatemp, data,3);
			memcpy( datatemp+3, data+4, 4);
			PrintAndLog("        UID :%s ", sprint_hex(datatemp, 7));
			// BBC
			// CT (cascade tag byte) 0x88 xor SN0 xor SN1 xor SN2 
			int crc0 = 0x88 ^ data[0] ^ data[1] ^data[2];
			if ( data[3] == crc0 ) {
				PrintAndLog("       BCC0 :%02x - Ok", data[3]);
			}
			else{
				PrintAndLog("       BCC0 :%02x - crc should be %02x", data[3], crc0);
			}
			
			int crc1 = data[4] ^ data[5] ^ data[6] ^data[7];
			if ( data[8] == crc1 ){
				PrintAndLog("       BCC1 :%02x - Ok", data[8]);
				}
			else{
				PrintAndLog("       BCC1 :%02x - crc should be %02x", data[8], crc1 );
			}
			
			PrintAndLog("   Internal :%s ", sprint_hex(data + 9, 1));
			
			memcpy(datatemp, data+10, 2);
			PrintAndLog("       Lock :%s - %s", sprint_hex(datatemp, 2),printBits( 2, &datatemp) );
			
			PrintAndLog(" OneTimePad :%s ", sprint_hex(data + 3*4, 4));
			PrintAndLog("");
			
            for (i = 0; i < Pages; i++) {
                switch(i){
                    case 2:
                        //process lock bytes
                        lockbytes_t=data+(i*4);
                        lockbytes[0]=lockbytes_t[2];
                        lockbytes[1]=lockbytes_t[3];
                        for(int j=0; j<16; j++){
                            bit[j]=lockbytes[j/8] & ( 1 <<(7-j%8));
                        }
                        PrintAndLog("Block %02x:%s ", i,sprint_hex(data + i * 4, 4));
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                       break; 
                    case 3: 
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[4]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 4:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[3]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 5:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[2]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 6:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[1]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 7:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[0]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 8:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[15]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 9:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[14]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 10:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[13]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 11:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[12]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 12:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[11]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 13:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[10]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 14:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[9]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 15:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[8]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                   default:
                        PrintAndLog("Block %02x:%s ", i,sprint_hex(data + i * 4, 4));
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                  }
            }
		}
    } else {                
        PrintAndLog("Command1 execute timeout");
    }
    if (dump) fclose(fout);
    return 0;
}

int CmdHF14AMfUDump(const char *Cmd){
    int i;
    uint8_t BlockNo      = 0;
    int Pages            = 16;
    uint8_t *lockbytes_t = NULL;
    uint8_t lockbytes[2] = {0x00};
    bool bit[16]         = {0x00};
    uint8_t datatemp[5]  = {0x00};
	bool dump            = true;
    uint8_t isOK         = 0;
    uint8_t * data       = NULL;
    FILE *fout;

    if ((fout = fopen("dump_ultralight_data.bin","wb")) == NULL) { 
        PrintAndLog("Could not create file name dumpdata.bin");
        return 1;	
    }
    PrintAndLog("Dumping Ultralight Card Data...");
    	
    PrintAndLog("Attempting to Read Ultralight... ");
    UsbCommand c = {CMD_MIFAREU_READCARD, {BlockNo,Pages}};
    SendCommand(&c);
    UsbCommand resp;

    if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
        isOK  = resp.arg[0] & 0xff;
        data  = resp.d.asBytes;
        PrintAndLog("isOk:%02x", isOK);
        if (isOK) 
            for (i = 0; i < Pages; i++) {
                switch(i){
                    case 2:
                        //process lock bytes
                        lockbytes_t=data+(i*4);
                        lockbytes[0]=lockbytes_t[2];
                        lockbytes[1]=lockbytes_t[3];
                        for(int j=0; j<16; j++){
                            bit[j]=lockbytes[j/8] & ( 1 <<(7-j%8));
                        }
                        PrintAndLog("Block %02x:%s ", i,sprint_hex(data + i * 4, 4));
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                       break; 
                    case 3: 
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[4]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 4:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[3]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 5:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[2]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 6:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[1]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 7:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[0]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 8:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[15]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 9:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[14]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 10:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[13]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 11:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[12]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 12:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[11]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 13:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[10]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 14:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[9]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 15:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[8]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                   default:
                        PrintAndLog("Block %02x:%s ", i,sprint_hex(data + i * 4, 4));
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                }
            }  
    } else {                
        PrintAndLog("Command1 execute timeout");
	}
    if (dump) fclose(fout);
    return 0;
}

// Needed to Authenticate to Ultralight C tags
void rol (uint8_t *data, const size_t len){
    uint8_t first = data[0];
    for (size_t i = 0; i < len-1; i++) {
        data[i] = data[i+1];
    }
    data[len-1] = first;
}

//-------------------------------------------------------------------------------
// Ultralight C Methods
//-------------------------------------------------------------------------------

//
// Ultralight C Authentication Demo {currently uses hard-coded key}
//
int CmdHF14AMfucAuth(const char *Cmd){
        
    uint8_t blockNo = 0, keyNo=0;
    uint8_t e_RndB[8] = {0x00};
    uint32_t cuid=0;
    unsigned char RndARndB[16] = {0x00};
    uint8_t key[16] = {0x00};
    DES_cblock RndA, RndB;
    DES_cblock iv[8] = {0x00};
    DES_key_schedule ks1,ks2;
    DES_cblock key1,key2;

    if (strlen(Cmd)<1) {
        PrintAndLog("Usage:  hf mfu auth k <key number>");
        PrintAndLog("        sample: hf mfu auth k 0");
        return 0;
    } 
    
    //Change key to user defined one
    if (strchr(Cmd,'k') != 0){
        //choose a key
        keyNo = param_get8(Cmd, 1);
        switch(keyNo){
            case 0:
                memcpy(key,key1_blnk_data,16);
                break;
            case 1:
                memcpy(key,key2_defa_data,16);
                break;
	    case 2:
                memcpy(key,key4_nfc_data,16);
                break;
		case 3: 
				memcpy(key,key5_ones_data,16);
                break;
            default:
                memcpy(key,key3_3des_data,16);
                break;
        }
    }else{
        memcpy(key,key3_3des_data,16);  
    }
    memcpy(key1,key,8);
    memcpy(key2,key+8,8);
    DES_set_key((DES_cblock *)key1,&ks1);
    DES_set_key((DES_cblock *)key2,&ks2);
        
    //Auth1
    UsbCommand c = {CMD_MIFAREUC_AUTH1, {blockNo}};
    SendCommand(&c);
    UsbCommand resp;
    if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
        uint8_t isOK  = resp.arg[0] & 0xff;
	        cuid  = resp.arg[1];
        uint8_t * data= resp.d.asBytes;

         if (isOK){
             PrintAndLog("enc(RndB):%s", sprint_hex(data+1, 8));
             memcpy(e_RndB,data+1,8);
	}
    } else {
        PrintAndLog("Command execute timeout");
    }
       
    //Do crypto magic
    DES_random_key(&RndA);
    DES_ede2_cbc_encrypt(e_RndB,RndB,sizeof(e_RndB),&ks1,&ks2,&iv,0);
    PrintAndLog("     RndB:%s",sprint_hex(RndB, 8));
    PrintAndLog("     RndA:%s",sprint_hex(RndA, 8));
    rol(RndB,8);
    memcpy(RndARndB,RndA,8);
    memcpy(RndARndB+8,RndB,8);
    PrintAndLog("     RA+B:%s",sprint_hex(RndARndB, 16));
    DES_ede2_cbc_encrypt(RndARndB,RndARndB,sizeof(RndARndB),&ks1,&ks2,&e_RndB,1);
    PrintAndLog("enc(RA+B):%s",sprint_hex(RndARndB, 16));

    //Auth2
    UsbCommand d = {CMD_MIFAREUC_AUTH2, {cuid}};
    memcpy(d.d.asBytes,RndARndB, 16);
    SendCommand(&d);

    UsbCommand respb;
    if (WaitForResponseTimeout(CMD_ACK,&respb,1500)) {
        uint8_t  isOK  = respb.arg[0] & 0xff;
        uint8_t * data2= respb.d.asBytes;

        if (isOK){
            PrintAndLog("enc(RndA'):%s", sprint_hex(data2+1, 8));
	}
                 
    } else {
        PrintAndLog("Command execute timeout");
    } 
    return 1;
}

//
// Ultralight C Read Single Block
//
int CmdHF14AMfUCRdBl(const char *Cmd)
{
    uint8_t blockNo = 0;
        
    if (strlen(Cmd)<1) {
        PrintAndLog("Usage:  hf mfu ucrdbl    <block number>");
        PrintAndLog("        sample: hf mfu ucrdbl 0");
        return 0;
    }       
        
    blockNo = param_get8(Cmd, 0);
    if (blockNo>MAX_ULTRAC_BLOCKS){
        PrintAndLog("Error: Maximum number of readable blocks is 44 for Ultralight Cards!");
        return 1;
    }
    PrintAndLog("--block no:%02x", (int)blockNo);

    //Read Block
    UsbCommand e = {CMD_MIFAREU_READBL, {blockNo}};
    SendCommand(&e);
    UsbCommand resp_c;
    if (WaitForResponseTimeout(CMD_ACK,&resp_c,1500)) {
        uint8_t                isOK  = resp_c.arg[0] & 0xff;
        uint8_t              * data  = resp_c.d.asBytes;
        if (isOK)
            PrintAndLog("isOk:%02x data:%s", isOK, sprint_hex(data, 4));
        else
            PrintAndLog("isOk:%02x", isOK);
        } else {
            PrintAndLog("Command execute timeout");
        }
    return 0;
}

//
// Ultralight C Read (or Dump) Card Contents
//
int CmdHF14AMfUCRdCard(const char *Cmd){
    int i;
    uint8_t BlockNo = 0;
    int Pages=44;
    uint8_t *lockbytes_t=NULL;
    uint8_t lockbytes[2]={0x00};
    uint8_t *lockbytes_t2=NULL;
    uint8_t lockbytes2[2]={0x00};
    bool bit[16]={0x00};
    bool bit2[16]={0x00};
    bool dump=false;
    uint8_t datatemp[5]={0x00};
    uint8_t isOK  = 0;
    uint8_t * data  = NULL;
    FILE *fout = NULL;

    if (strchr(Cmd,'x') != 0){
        dump=true;
        if ((fout = fopen("dump_ultralightc_data.bin","wb")) == NULL) { 
            PrintAndLog("Could not create file name dumpdata.bin");
            return 1;	
      }
      PrintAndLog("Dumping Ultralight C Card Data...");
    }
    PrintAndLog("Attempting to Read Ultralight C... ");
    UsbCommand c = {CMD_MIFAREUC_READCARD, {BlockNo, Pages}};
    SendCommand(&c);
    UsbCommand resp;

    if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
        isOK  = resp.arg[0] & 0xff;
        data  = resp.d.asBytes;
	//Pages=sizeof(data)/sizeof(data[0]);
        PrintAndLog("isOk:%02x", isOK);
        if (isOK) 
            for (i = 0; i < Pages; i++) {
                switch(i){
                    case 2:
                        //process lock bytes
                        lockbytes_t=data+(i*4);
                        lockbytes[0]=lockbytes_t[2];
                        lockbytes[1]=lockbytes_t[3];
                        for(int j=0; j<16; j++){
                            bit[j]=lockbytes[j/8] & ( 1 <<(7-j%8));
                        }
                        //might as well read bottom lockbytes too
                        lockbytes_t2=data+(40*4);
                        lockbytes2[0]=lockbytes_t2[2];
                        lockbytes2[1]=lockbytes_t2[3];
                        for(int j=0; j<16; j++){
                            bit2[j]=lockbytes2[j/8] & ( 1 <<(7-j%8));
                        }
                        PrintAndLog("Block %02x:%s ", i,sprint_hex(data + i * 4, 4));
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 3: 
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[4]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 4:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[3]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 5:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[2]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 6:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[1]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 7:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[0]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 8:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[15]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 9:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[14]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 10:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[13]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 11:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[12]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 12:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[11]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 13:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[10]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 14:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[9]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 15:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[8]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 16:
                    case 17:
                    case 18:
                    case 19:  
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[6]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 20:
                    case 21:
                    case 22:
                    case 23:  
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[5]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break; 
                    case 24:
                    case 25:
                    case 26:
                    case 27:  
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[4]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break; 		    
                    case 28:
                    case 29:
                    case 30:
                    case 31:  
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[2]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 32:
                    case 33:
                    case 34:
                    case 35:  
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[1]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break; 
                    case 36:
                    case 37:
                    case 38:
                    case 39:  
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[0]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break; 
                    case 40:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[12]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 41:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[11]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 42:
                        //auth0
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[10]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 43:  
                        //auth1
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[9]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break; 
                    default:
                        PrintAndLog("Block %02x:%s ", i,sprint_hex(data + i * 4, 4));
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;	    
                   } 
            }
      
        } else {                
            PrintAndLog("Command1 execute timeout");
        }
    if (dump) fclose(fout);
    return 0;
}

//
// Ultralight C Dump Card Contents to file
//
int CmdHF14AMfUCDump(const char *Cmd){
    int i;
    uint8_t BlockNo = 0;
    int Pages=44;
    uint8_t *lockbytes_t=NULL;
    uint8_t lockbytes[2]={0x00};
    uint8_t *lockbytes_t2=NULL;
    uint8_t lockbytes2[2]={0x00};
    bool bit[16]={0x00};
    bool bit2[16]={0x00};
    bool dump=true;
    uint8_t datatemp[5]={0x00};
        
    uint8_t isOK  = 0;
    uint8_t * data  = NULL;
    FILE *fout;

	if ((fout = fopen("dump_ultralightc_data.bin","wb")) == NULL) { 
		PrintAndLog("Could not create file name dumpdata.bin");
		return 1;	
	}
	PrintAndLog("Dumping Ultralight C Card Data...");
   PrintAndLog("Attempting to Read Ultralight C... ");
    UsbCommand c = {CMD_MIFAREU_READCARD, {BlockNo,Pages}};
    SendCommand(&c);
    UsbCommand resp;

    if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
        isOK  = resp.arg[0] & 0xff;
        data  = resp.d.asBytes;
        PrintAndLog("isOk:%02x", isOK);
        if (isOK) 
            for (i = 0; i < Pages; i++) {
                switch(i){
                    case 2:
                        //process lock bytes
                        lockbytes_t=data+(i*4);
                        lockbytes[0]=lockbytes_t[2];
                        lockbytes[1]=lockbytes_t[3];
                        for(int j=0; j<16; j++){
                            bit[j]=lockbytes[j/8] & ( 1 <<(7-j%8));

                        }
                        //might as well read bottom lockbytes too
                        lockbytes_t2=data+(40*4);
                        lockbytes2[0]=lockbytes_t2[2];
                        lockbytes2[1]=lockbytes_t2[3];
                        for(int j=0; j<16; j++){
                            bit2[j]=lockbytes2[j/8] & ( 1 <<(7-j%8));
                        }

                        PrintAndLog("Block %02x:%s ", i,sprint_hex(data + i * 4, 4));
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 3: 
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[4]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 4:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[3]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 5:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[2]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 6:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[1]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 7:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[0]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 8:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[15]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 9:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[14]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 10:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[13]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 11:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[12]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 12:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[11]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 13:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[10]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 14:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[9]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 15:
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit[8]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 16:
                    case 17:
                    case 18:
                    case 19:  
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[6]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break;
                    case 20:
                    case 21:
                    case 22:
                    case 23:  
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[5]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break; 
                    case 24:
                    case 25:
                    case 26:
                    case 27:  
                        PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[4]);
                        memcpy(datatemp,data + i * 4,4);
                        if (dump) fwrite ( datatemp, 1, 4, fout );
                        break; 		    
                   case 28:
                   case 29:
                   case 30:
                   case 31:  
                       PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[2]);
                       memcpy(datatemp,data + i * 4,4);
                       if (dump) fwrite ( datatemp, 1, 4, fout );
                       break;
                   case 32:
                   case 33:
                   case 34:
                   case 35:  
                       PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[1]);
                       memcpy(datatemp,data + i * 4,4);
                       if (dump) fwrite ( datatemp, 1, 4, fout );
                       break; 
                   case 36:
                   case 37:
                   case 38:
                   case 39:  
                       PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[0]);
                       memcpy(datatemp,data + i * 4,4);
                       if (dump) fwrite ( datatemp, 1, 4, fout );
                       break; 
                   case 40:
                       PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[12]);
                       memcpy(datatemp,data + i * 4,4);
                       if (dump) fwrite ( datatemp, 1, 4, fout );
                       break;
                   case 41:
                       PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[11]);
                       memcpy(datatemp,data + i * 4,4);
                       if (dump) fwrite ( datatemp, 1, 4, fout );
                       break;
                   case 42:
                       //auth0
                       PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[10]);
                       memcpy(datatemp,data + i * 4,4);
                       if (dump) fwrite ( datatemp, 1, 4, fout );
                       break;
                   case 43:  
                       //auth1
                       PrintAndLog("Block %02x:%s [%d]", i,sprint_hex(data + i * 4, 4),bit2[9]);
                       memcpy(datatemp,data + i * 4,4);
                       if (dump) fwrite ( datatemp, 1, 4, fout );
                       break; 
                   default:
                       PrintAndLog("Block %02x:%s ", i,sprint_hex(data + i * 4, 4));
                       memcpy(datatemp,data + i * 4,4);
                       if (dump) fwrite ( datatemp, 1, 4, fout );
                       break;	    
                   } 
            }
      
        } else {                
            PrintAndLog("Command1 execute timeout");
	}
    if (dump) fclose(fout);
    return 0;
}

//
//  Mifare Ultralight C Write Single Block
//
int CmdHF14AMfUCWrBl(const char *Cmd){
    
    uint8_t blockNo = 0;
    bool chinese_card = 0;
    uint8_t bldata[16] = {0x00};
    UsbCommand resp;
        
    if (strlen(Cmd)<3) {
        PrintAndLog("Usage:  hf mfu ucwrbl <block number> <block data (8 hex symbols)> [w]");
        PrintAndLog("        sample: hf mfu uwrbl 0 01020304");
        return 0;
    }       
    blockNo = param_get8(Cmd, 0);
    if (blockNo>(MAX_ULTRAC_BLOCKS+4)){
        PrintAndLog("Error: Maximum number of blocks is 47 for Ultralight Cards!");
        return 1;
    }
    if (param_gethex(Cmd, 1, bldata, 8)) {
        PrintAndLog("Block data must include 8 HEX symbols");
        return 1;
    }
    if (strchr(Cmd,'w') != 0) {
        chinese_card=1; 
    }
    switch(blockNo){
        case 0:
            if (!chinese_card){
                 PrintAndLog("Access Denied");  
            }else{
                PrintAndLog("--specialblock no:%02x", blockNo);
                PrintAndLog("--data: %s", sprint_hex(bldata, 4));
                UsbCommand d = {CMD_MIFAREU_WRITEBL, {blockNo}};
                memcpy(d.d.asBytes,bldata, 4);
                SendCommand(&d);
                if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
                    uint8_t isOK  = resp.arg[0] & 0xff;
                    PrintAndLog("isOk:%02x", isOK);
                } else {
                    PrintAndLog("Command execute timeout");
                }  
            }
            break;
        case 1:
            if (!chinese_card){
                PrintAndLog("Access Denied");
            }else{	
                PrintAndLog("--specialblock no:%02x", blockNo);
                PrintAndLog("--data: %s", sprint_hex(bldata, 4));
                UsbCommand d = {CMD_MIFAREU_WRITEBL, {blockNo}};
                memcpy(d.d.asBytes,bldata, 4);
                SendCommand(&d);
                if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
                    uint8_t isOK  = resp.arg[0] & 0xff;
                    PrintAndLog("isOk:%02x", isOK);
                } else {
                    PrintAndLog("Command execute timeout");
                }
           }
           break;
        case 2:
            if (!chinese_card){
                PrintAndLog("Access Denied");
            }else{	
                PrintAndLog("--specialblock no:%02x", blockNo);
                PrintAndLog("--data: %s", sprint_hex(bldata, 4));
                UsbCommand c = {CMD_MIFAREU_WRITEBL, {blockNo}};
                memcpy(c.d.asBytes, bldata, 4);
                SendCommand(&c);
                if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
                    uint8_t isOK  = resp.arg[0] & 0xff;
                    PrintAndLog("isOk:%02x", isOK);
                } else {
                    PrintAndLog("Command execute timeout");
                }
            }
            break;
        case 3:
            PrintAndLog("--specialblock no:%02x", blockNo);
            PrintAndLog("--data: %s", sprint_hex(bldata, 4));
            UsbCommand d = {CMD_MIFAREU_WRITEBL, {blockNo}};
            memcpy(d.d.asBytes,bldata, 4);
            SendCommand(&d);
            if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
                uint8_t isOK  = resp.arg[0] & 0xff;
                PrintAndLog("isOk:%02x", isOK);
            } else {
                PrintAndLog("Command execute timeout");
            }
            break;
        default: 
            PrintAndLog("--block no:%02x", blockNo);
            PrintAndLog("--data: %s", sprint_hex(bldata, 4));        	
            UsbCommand e = {CMD_MIFAREU_WRITEBL, {blockNo}};
            memcpy(e.d.asBytes,bldata, 4);
            SendCommand(&e);
            if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
                uint8_t isOK  = resp.arg[0] & 0xff;
                PrintAndLog("isOk:%02x", isOK);
            } else {
                PrintAndLog("Command execute timeout");
            }
            break;
        }
        return 0;
}

//------------------------------------
// Menu Stuff
//------------------------------------
static command_t CommandTable[] =
{
    {"help",    CmdHelp,		1,"This help"},
    {"dbg",     CmdHF14AMfDbg,		0,"Set default debug mode"},
    {"urdbl",   CmdHF14AMfURdBl,        0,"Read MIFARE Ultralight block"},
    {"urdcard", CmdHF14AMfURdCard,      0,"Read MIFARE Ultralight Card"},
    {"udump",   CmdHF14AMfUDump,	0,"Dump MIFARE Ultralight tag to binary file"},
    {"uwrbl",   CmdHF14AMfUWrBl,	0,"Write MIFARE Ultralight block"},
    {"ucrdbl",  CmdHF14AMfUCRdBl,       0,"Read MIFARE Ultralight C block"},
    {"ucrdcard",CmdHF14AMfUCRdCard,     0,"Read MIFARE Ultralight C Card"},
    {"ucdump",  CmdHF14AMfUCDump,	0,"Dump MIFARE Ultralight C tag to binary file"},
    {"ucwrbl",  CmdHF14AMfUCWrBl,	0,"Write MIFARE Ultralight C block"},
    {"auth",    CmdHF14AMfucAuth,	0,"Ultralight C Authentication"},
    {NULL, NULL, 0, NULL}
};

int CmdHFMFUltra(const char *Cmd){
    // flush
    WaitForResponseTimeout(CMD_ACK,NULL,100);
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd){
    CmdsHelp(CommandTable);
    return 0;
}