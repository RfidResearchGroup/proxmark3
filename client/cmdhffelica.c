//-----------------------------------------------------------------------------
// Copyright (C) 2017 October, Satsuoni
// 2017 iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO18092 / FeliCa commands
//-----------------------------------------------------------------------------
#include "cmdhffelica.h"

static int CmdHelp(const char *Cmd);

int usage_hf_felica_sim(void) {
	PrintAndLog("\n Emulating ISO/18092 FeliCa tag \n");
	PrintAndLog("usage: hf felica sim [h] t <type> u <uid> [v]");
	PrintAndLog("options: ");
	PrintAndLog("    h     : This help");
	PrintAndLog("    t     : 1 = FeliCa");
	PrintAndLog("          : 2 = FeliCaS");
	PrintAndLog("    v     : (Optional) Verbose");
	PrintAndLog("samples:");
	PrintAndLog("          hf felica sim t 1 u 11223344556677");
	return 0;
}
int usage_hf_felica_sniff(void){
	PrintAndLog("It get data from the field and saves it into command buffer.");
	PrintAndLog("Buffer accessible from command 'hf list felica'");
	PrintAndLog("Usage:  hf felica sniff [c][r]");
	PrintAndLog("c - triggered by first data from card");
	PrintAndLog("r - triggered by first 7-bit request from reader (REQ,WUP,...)");
	PrintAndLog("sample: hf felica sniff c r");
	return 0;
}
int usage_hf_felica_raw(void){
	PrintAndLog("Usage: hf felica raw [-h] [-r] [-c] [-p] [-a] [-t] <milliseconds> [-b] <number of bits>  <0A 0B 0C ... hex>");
	PrintAndLog("       -h    this help");
	PrintAndLog("       -r    do not read response");
	PrintAndLog("       -c    calculate and append CRC");
	PrintAndLog("       -p    leave the signal field ON after receive");
	PrintAndLog("       -a    active signal field ON without select");
	PrintAndLog("       -s    active signal field ON with select");
	PrintAndLog("       -b    number of bits to send. Useful for send partial byte");
	PrintAndLog("       -t    timeout in ms");
	return 0;
}

int CmdHFFelicaList(const char *Cmd) {
	//PrintAndLog("Deprecated command, use 'hf list felica' instead");
	CmdHFList("felica");
	return 0;
}

int CmdHFFelicaReader(const char *Cmd) {
	bool silent = (Cmd[0] == 's' || Cmd[0] ==  'S');
	UsbCommand cDisconnect = {CMD_READER_ISO_14443a, {0,0,0}};
	UsbCommand c = {CMD_READER_ISO_14443a, {ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
		if (!silent) PrintAndLog("iso14443a card select failed");
		SendCommand(&cDisconnect);
		return 0;
	}
	
	iso14a_card_select_t card;
	memcpy(&card, (iso14a_card_select_t *)resp.d.asBytes, sizeof(iso14a_card_select_t));

	/* 
		0: couldn't read
		1: OK, with ATS
		2: OK, no ATS
		3: proprietary Anticollision	
	*/
	uint64_t select_status = resp.arg[0];
	
	if (select_status == 0) {
		if (!silent) PrintAndLog("iso14443a card select failed");
		SendCommand(&cDisconnect);
		return 0;
	}

	PrintAndLog(" UID : %s", sprint_hex(card.uid, card.uidlen));
	PrintAndLog("ATQA : %02x %02x", card.atqa[1], card.atqa[0]);
	PrintAndLog(" SAK : %02x [%d]", card.sak, resp.arg[0]);

	return select_status;
}

// simulate iso18092 / FeliCa tag
int CmdHFFelicaSim(const char *Cmd) {
	bool errors = false;
	uint8_t flags = 0;
	uint8_t tagtype = 1;	
	uint8_t cmdp = 0;
	uint8_t uid[10] = {0,0,0,0,0,0,0,0,0,0};
	int uidlen = 0;
	bool verbose =  false;
	
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
			case 'h':
			case 'H':
				return usage_hf_felica_sim();
			case 't':
			case 'T':
				// Retrieve the tag type
				tagtype = param_get8ex(Cmd, cmdp+1, 0, 10);
				if (tagtype == 0)
					errors = true; 
				cmdp += 2;
				break;
			case 'u':
			case 'U':
				// Retrieve the full 4,7,10 byte long uid 
				param_gethex_ex(Cmd, cmdp+1, uid, &uidlen);
				if (!errors) {
					PrintAndLog("Emulating ISO18092/FeliCa tag with %d byte UID (%s)", uidlen>>1, sprint_hex(uid, uidlen>>1));
				}
				cmdp += 2;
				break;
			case 'v':
			case 'V':
				verbose = true;
				cmdp++;
				break;
			case 'e':
			case 'E':
				cmdp++;
				break;				
			default:
				PrintAndLog("Unknown parameter '%c'", param_getchar(Cmd, cmdp));
				errors = true;
				break;
			}
	}

	//Validations
	if (errors || cmdp == 0) return usage_hf_felica_sim();
	
	UsbCommand c = {CMD_FELICA_SIMULATE_TAG,{ tagtype, flags, 0 }};	
	memcpy(c.d.asBytes, uid, uidlen>>1);
	clearCommandBuffer();
	SendCommand(&c);	
	UsbCommand resp;
	
	if ( verbose )
		PrintAndLog("Press pm3-button to abort simulation");
	
	while( !ukbhit() ){
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500) ) continue;
		
	}
	return 0;
}

int CmdHFFelicaSniff(const char *Cmd) {
	int param = 0;	
	uint8_t ctmp;
	for (int i = 0; i < 2; i++) {
		ctmp = param_getchar(Cmd, i);
		if (ctmp == 'h' || ctmp == 'H') return usage_hf_felica_sniff();
		if (ctmp == 'c' || ctmp == 'C') param |= 0x01;
		if (ctmp == 'r' || ctmp == 'R') param |= 0x02;
	}

	UsbCommand c = {CMD_FELICA_SNOOP, {param, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

int CmdHFFelicaCmdRaw(const char *cmd) {
    UsbCommand c = {CMD_FELICA_COMMAND, {0, 0, 0}};
    bool reply = 1;
    bool crc = false;
    bool power = false;
    bool active = false;
    bool active_select = false;
    uint16_t numbits = 0;
	bool bTimeout = false;
	uint32_t timeout = 0;
    char buf[5]="";
    int i = 0;
    uint8_t data[USB_CMD_DATA_SIZE];
	uint16_t datalen = 0;
	uint32_t temp;

    if (strlen(cmd) < 2) return usage_hf_felica_raw();

    // strip
    while (*cmd==' ' || *cmd=='\t') cmd++;

    while (cmd[i]!='\0') {
        if (cmd[i]==' ' || cmd[i]=='\t') { i++; continue; }
        if (cmd[i]=='-') {
            switch (cmd[i+1]) {
				case 'H':
				case 'h':
					return usage_hf_felica_raw();
                case 'r': 
                    reply = false;
                    break;
                case 'c':
                    crc = true;
                    break;
                case 'p':
                    power = true;
                    break;
                case 'a':
                    active = true;
                    break;
                case 's':
                    active_select = true;
                    break;
                case 'b': 
                    sscanf(cmd+i+2, "%d", &temp);
                    numbits = temp & 0xFFFF;
                    i+=3;
                    while(cmd[i]!=' ' && cmd[i]!='\0') { i++; }
                    i-=2;
                    break;
				case 't':
					bTimeout = true;
					sscanf(cmd+i+2, "%d", &temp);
					timeout = temp;
					i+=3;
					while(cmd[i]!=' ' && cmd[i]!='\0') { i++; }
					i-=2;
					break;
                default:
                    return usage_hf_felica_raw();
            }
            i += 2;
            continue;
        }
        if ((cmd[i]>='0' && cmd[i]<='9') ||
            (cmd[i]>='a' && cmd[i]<='f') ||
            (cmd[i]>='A' && cmd[i]<='F') ) {
            buf[strlen(buf)+1]=0;
            buf[strlen(buf)]=cmd[i];
            i++;

            if (strlen(buf)>=2) {
                sscanf(buf,"%x",&temp);
                data[datalen]=(uint8_t)(temp & 0xff);
                *buf=0;
				if (++datalen >= sizeof(data)){
					if (crc)
						PrintAndLog("Buffer is full, we can't add CRC to your data");
					break;
				}
            }
            continue;
        }
        PrintAndLog("Invalid char on input");
        return 0;
    }

    if (crc && datalen>0 && datalen<sizeof(data)-2) {
        uint8_t first, second;
		ComputeCrc14443(CRC_14443_B, data, datalen, &first, &second);
        data[datalen++] = first;
        data[datalen++] = second;
    }

    if (active || active_select) {
        c.arg[0] |= ISO14A_CONNECT;
        if(active)
            c.arg[0] |= ISO14A_NO_SELECT;
    }

	if (bTimeout){
	    #define MAX_TIMEOUT 40542464 	// = (2^32-1) * (8*16) / 13560000Hz * 1000ms/s
        c.arg[0] |= ISO14A_SET_TIMEOUT;
        if(timeout > MAX_TIMEOUT) {
            timeout = MAX_TIMEOUT;
            PrintAndLog("Set timeout to 40542 seconds (11.26 hours). The max we can wait for response");
        }
		c.arg[2] = 13560000 / 1000 / (8*16) * timeout; // timeout in ETUs (time to transfer 1 bit, approx. 9.4 us)
	}

    if (power) {
        c.arg[0] |= ISO14A_NO_DISCONNECT;
	}
	
    if (datalen>0) {
        c.arg[0] |= ISO14A_RAW;
	}
			
	// Max buffer is USB_CMD_DATA_SIZE
	datalen = (datalen > USB_CMD_DATA_SIZE) ? USB_CMD_DATA_SIZE : datalen;
		
    c.arg[1] = (datalen & 0xFFFF) | (uint32_t)(numbits << 16);
    memcpy(c.d.asBytes, data, datalen);

	clearCommandBuffer();
    SendCommand(&c);

    if (reply) {
        if (active_select)
            waitCmdFelica(1);
        if (datalen > 0)
            waitCmdFelica(0);
    }
    return 0;
}

void waitCmdFelica(uint8_t iSelect) {
    UsbCommand resp;
    uint16_t len = 0;

    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {        
        len = iSelect ? (resp.arg[1] & 0xffff) : (resp.arg[0]  & 0xffff);
        PrintAndLog("received %i octets", len);
        if(!len)
            return;
		PrintAndLog("%s", sprint_hex(resp.d.asBytes, len) );
    } else {
        PrintAndLog("timeout while waiting for reply.");
    }
}

static command_t CommandTable[] = {
  {"help",   CmdHelp,              1, "This help"},
  {"list",   CmdHFFelicaList,         0, "[Deprecated] List ISO 18092/FeliCa history"},
  {"reader", CmdHFFelicaReader,       0, "Act like an ISO18092/FeliCa reader"},
  {"sim",    CmdHFFelicaSim,          0, "<UID> -- Simulate ISO 18092/FeliCa tag"},
  {"sniff",  CmdHFFelicaSniff,        0, "sniff ISO 18092/Felica traffic"},
  {"raw",    CmdHFFelicaCmdRaw,       0, "Send raw hex data to tag"},
  {NULL, NULL, 0, NULL}
};

int CmdHFFelica(const char *Cmd) {
	clearCommandBuffer();
	CmdsParse(CommandTable, Cmd);
	return 0;
}

int CmdHelp(const char *Cmd) {
	CmdsHelp(CommandTable);
	return 0;
}