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
	PrintAndLogEx(NORMAL, "\n Emulating ISO/18092 FeliCa tag \n");
	PrintAndLogEx(NORMAL, "Usage: hf felica sim [h] t <type> [v]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "    h     : This help");
	PrintAndLogEx(NORMAL, "    t     : 1 = FeliCa");
	PrintAndLogEx(NORMAL, "          : 2 = FeliCaLiteS");
	PrintAndLogEx(NORMAL, "    v     : (Optional) Verbose");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "          hf felica sim t 1 ");
	return 0;
}
int usage_hf_felica_sniff(void){
	PrintAndLogEx(NORMAL, "It get data from the field and saves it into command buffer.");
	PrintAndLogEx(NORMAL, "Buffer accessible from command 'hf list felica'");
	PrintAndLogEx(NORMAL, "Usage:  hf felica sniff <s > <t>");
	PrintAndLogEx(NORMAL, "      s       samples to skip (decimal)");
	PrintAndLogEx(NORMAL, "      t       triggers to skip (decimal)");
 	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "          hf felica sniff s 1000");
	return 0;
}
int usage_hf_felica_simlite(void) {
	PrintAndLogEx(NORMAL, "\n Emulating ISO/18092 FeliCa Lite tag \n");
	PrintAndLogEx(NORMAL, "Usage: hf felica litesim [h] u <uid>");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "    h     : This help");
	PrintAndLogEx(NORMAL, "    uid   : UID in hexsymbol");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "          hf felica litesim 11223344556677");
	return 0;
}
int usage_hf_felica_dumplite(void) {
	PrintAndLogEx(NORMAL, "\n Dump ISO/18092 FeliCa Lite tag \n");
	PrintAndLogEx(NORMAL, "press button to abort run, otherwise it will loop for 200sec.");
	PrintAndLogEx(NORMAL, "Usage: hf felica litedump [h]");
	PrintAndLogEx(NORMAL, "Options:");
	PrintAndLogEx(NORMAL, "    h     : This help");
	PrintAndLogEx(NORMAL, "Examples:");
	PrintAndLogEx(NORMAL, "          hf felica litedump");
	return 0;
}
int usage_hf_felica_raw(void){
	PrintAndLogEx(NORMAL, "Usage: hf felica raw [-h] [-r] [-c] [-p] [-a] <0A 0B 0C ... hex>");
	PrintAndLogEx(NORMAL, "       -h    this help");
	PrintAndLogEx(NORMAL, "       -r    do not read response");
	PrintAndLogEx(NORMAL, "       -c    calculate and append CRC");
	PrintAndLogEx(NORMAL, "       -p    leave the signal field ON after receive");
	PrintAndLogEx(NORMAL, "       -a    active signal field ON without select");
	PrintAndLogEx(NORMAL, "       -s    active signal field ON with select");
	return 0;
}

int CmdHFFelicaList(const char *Cmd) {
	//PrintAndLogEx(NORMAL, "Deprecated command, use 'hf list felica' instead");
	CmdTraceList("raw");
	return 0;
}

int CmdHFFelicaReader(const char *Cmd) {
	bool silent = (Cmd[0] == 's' || Cmd[0] ==  'S');
	//UsbCommand cDisconnect = {CMD_FELICA_COMMAND, {0,0,0}};
	UsbCommand c = {CMD_FELICA_COMMAND, {FELICA_CONNECT, 0, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
		if (!silent) PrintAndLogEx(WARNING, "FeliCa card select failed");
		//SendCommand(&cDisconnect);
		return 0;
	}
	
	felica_card_select_t card;
	memcpy(&card, (felica_card_select_t *)resp.d.asBytes, sizeof(felica_card_select_t));
	uint64_t status = resp.arg[0];
	
	switch(status) {
		case 1: {
			if (!silent) 
				PrintAndLogEx(WARNING, "card timeout"); 
			break;
		}
		case 2: {
			if (!silent)
				PrintAndLogEx(WARNING, "card answered wrong"); 
			break;
		}
		case 3: {
			if (!silent)
				PrintAndLogEx(WARNING, "CRC check failed");
			break;
		}
		case 0: {
			PrintAndLogEx(SUCCESS, "FeliCa tag info");
			
			PrintAndLogEx(NORMAL, "IDm  %s", sprint_hex(card.IDm, sizeof(card.IDm)));
			PrintAndLogEx(NORMAL, "  - CODE    %s", sprint_hex(card.code, sizeof(card.code)));
			PrintAndLogEx(NORMAL, "  - NFCID2  %s", sprint_hex(card.uid, sizeof(card.uid)));
			
			PrintAndLogEx(NORMAL, "Parameter (PAD) | %s", sprint_hex(card.PMm, sizeof(card.PMm)));
			PrintAndLogEx(NORMAL, "  - IC CODE %s", sprint_hex(card.iccode, sizeof(card.iccode)));
			PrintAndLogEx(NORMAL, "  - MRT     %s", sprint_hex(card.mrt, sizeof(card.mrt)));
			
			PrintAndLogEx(NORMAL, "SERVICE CODE %s", sprint_hex(card.servicecode, sizeof(card.servicecode)));
			break;
		}
	}
	return status;
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
	
	while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch (param_getchar(Cmd, cmdp)) {
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
					PrintAndLogEx(NORMAL, "Emulating ISO18092/FeliCa tag with %d byte UID (%s)", uidlen>>1, sprint_hex(uid, uidlen>>1));
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
				PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
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
		PrintAndLogEx(NORMAL, "Press pm3-button to abort simulation");
	
	while( !ukbhit() ){
		if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500) ) continue;		
	}
	return 0;
}

int CmdHFFelicaSniff(const char *Cmd) {	

	uint8_t cmdp = 0;
	uint64_t samples2skip = 0;
	uint64_t triggers2skip = 0;
	bool errors = false;
			
	while(param_getchar(Cmd, cmdp) != 0x00 && !errors) {
		switch(param_getchar(Cmd, cmdp)) {
		case 'h':
		case 'H':
			return usage_hf_felica_sniff();
		case 's':
		case 'S':
			samples2skip = param_get32ex(Cmd, cmdp+1, 0, 10);
			cmdp += 2;
			break;
		case 't': 
		case 'T':
			triggers2skip = param_get32ex(Cmd, cmdp+1, 0, 10);
			cmdp += 2;
			break;
		default:
			PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
			errors = true;
			break;
		}
	}
	//Validations
	if (errors || cmdp == 0) return usage_hf_felica_sniff();
	
	UsbCommand c = {CMD_FELICA_SNOOP, {samples2skip, triggers2skip, 0}};
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}

// uid  hex
int CmdHFFelicaSimLite(const char *Cmd) {

	uint64_t uid = param_get64ex(Cmd, 0, 0, 16);

    if (!uid)
		return usage_hf_felica_simlite();
	
	UsbCommand c = {CMD_FELICA_LITE_SIM, {uid, 0, 0} };
	clearCommandBuffer();
	SendCommand(&c);
	return 0;
}
 
static void printSep() {
	PrintAndLogEx(NORMAL, "------------------------------------------------------------------------------------");
}

uint16_t PrintFliteBlock(uint16_t tracepos, uint8_t *trace,uint16_t tracelen) {
	if (tracepos+19 >= tracelen) 
		return tracelen;
	
	trace += tracepos;
	uint8_t blocknum = trace[0];
	uint8_t status1 = trace[1];
	uint8_t status2 = trace[2];

	char line[110] = {0};
	for (int j = 0; j < 16; j++) {
		snprintf(line+( j  * 4),110, "%02x  ", trace[j+3]);
	}

	PrintAndLogEx(NORMAL, "block number %02x, status: %02x %02x",blocknum,status1, status2);
	switch (blocknum) {
		case 0x00: PrintAndLogEx(NORMAL,  "S_PAD0: %s",line);break;
		case 0x01: PrintAndLogEx(NORMAL,  "S_PAD1: %s",line);break;
		case 0x02: PrintAndLogEx(NORMAL,  "S_PAD2: %s",line);break;
		case 0x03: PrintAndLogEx(NORMAL,  "S_PAD3: %s",line);break;
		case 0x04: PrintAndLogEx(NORMAL,  "S_PAD4: %s",line);break;
		case 0x05: PrintAndLogEx(NORMAL,  "S_PAD5: %s",line);break;
		case 0x06: PrintAndLogEx(NORMAL,  "S_PAD6: %s",line);break;
		case 0x07: PrintAndLogEx(NORMAL,  "S_PAD7: %s",line);break;
		case 0x08: PrintAndLogEx(NORMAL,  "S_PAD8: %s",line);break;
		case 0x09: PrintAndLogEx(NORMAL,  "S_PAD9: %s",line);break;
		case 0x0a: PrintAndLogEx(NORMAL,  "S_PAD10: %s",line);break;
		case 0x0b: PrintAndLogEx(NORMAL,  "S_PAD11: %s",line);break;
		case 0x0c: PrintAndLogEx(NORMAL,  "S_PAD12: %s",line);break;
		case 0x0d: PrintAndLogEx(NORMAL,  "S_PAD13: %s",line);break;
		case 0x0E: {
			uint32_t regA = trace[3] + (trace[4]>>8) + (trace[5]>>16) + (trace[6]>>24);
			uint32_t regB = trace[7] + (trace[8]>>8) + (trace[9]>>16) + (trace[10]>>24);
			line[0] = 0;
			for (int j = 0; j < 8; j++) 
				snprintf(line+( j  * 2),110, "%02x", trace[j+11]);
			PrintAndLogEx(NORMAL,  "REG: regA: %d regB: %d regC: %s ", regA, regB, line);
			}
		break;
		case 0x80: PrintAndLogEx(NORMAL,  "Random Challenge, WO:  %s ", line); break;  
		case 0x81: PrintAndLogEx(NORMAL,  "MAC, only set on dual read:  %s ", line); break;            
		case 0x82: {
			char idd[20];
			char idm[20];
			for (int j = 0; j < 8; j++) 
				snprintf(idd+( j  * 2),20, "%02x", trace[j+3]);
			
			for (int j = 0; j < 6; j++) 
				snprintf(idm+( j  * 2),20, "%02x", trace[j+13]);
				
			PrintAndLogEx(NORMAL,  "ID Block, IDd: 0x%s DFC: 0x%02x%02x Arb: %s ", idd, trace[11], trace [12], idm);
			}
		break;
		case 0x83: {
			char idm[20];
			char pmm[20];
			for (int j = 0; j < 8; j++)
				snprintf(idm+( j  * 2),20, "%02x", trace[j+3]);
			
			for (int j = 0; j < 8; j++)
				snprintf(pmm+( j  * 2),20, "%02x", trace[j+11]);
			
			PrintAndLogEx(NORMAL,  "DeviceId:  IDm: 0x%s PMm: 0x%s ", idm, pmm);
			}
		break;    
		case 0x84: PrintAndLogEx(NORMAL,  "SER_C: 0x%02x%02x ", trace[3], trace[4]); break;
		case 0x85: PrintAndLogEx(NORMAL,  "SYS_Cl 0x%02x%02x ", trace[3], trace[4]); break;   
		case 0x86: PrintAndLogEx(NORMAL,  "CKV (key version): 0x%02x%02x ", trace[3], trace[4]); break;  
		case 0x87: PrintAndLogEx(NORMAL,  "CK (card key), WO:   %s ", line); break;
		case 0x88: {
			PrintAndLogEx(NORMAL,  "Memory Configuration (MC):");
			PrintAndLogEx(NORMAL,  "MAC needed to write state: %s", trace[3+12]? "on" : "off");
			//order might be off here...
			PrintAndLogEx(NORMAL,  "Write with MAC for S_PAD  : %s ", sprint_bin(trace+3+10, 2) );
			PrintAndLogEx(NORMAL,  "Write with AUTH for S_PAD : %s ", sprint_bin(trace+3+8, 2) );
			PrintAndLogEx(NORMAL,  "Read after AUTH for S_PAD : %s ", sprint_bin(trace+3+6, 2) );
			PrintAndLogEx(NORMAL,  "MAC needed to write CK and CKV: %s", trace[3+5] ? "on" : "off");
			PrintAndLogEx(NORMAL,  "RF parameter: %02x", (trace[3+4] & 0x7) );
			PrintAndLogEx(NORMAL,  "Compatible with NDEF: %s", trace[3+3] ? "yes" : "no");
			PrintAndLogEx(NORMAL,  "Memory config writable : %s", (trace[3+2] == 0xff) ? "yes" : "no");
			PrintAndLogEx(NORMAL,  "RW access for S_PAD : %s ", sprint_bin(trace+3, 2) );
			}
		break;         
		case 0x90: {
            PrintAndLogEx(NORMAL,  "Write count, RO:   %02x %02x %02x ", trace[3], trace[4], trace[5]);
			}
		break; 
		case 0x91: {
            PrintAndLogEx(NORMAL,  "MAC_A, RW (auth):   %s ", line);
           }
		break; 
		case 0x92:
            PrintAndLogEx(NORMAL,  "State:");
            PrintAndLogEx(NORMAL,  "Polling disabled: %s", trace[3+8] ? "yes" : "no");
            PrintAndLogEx(NORMAL,  "Authenticated: %s", trace[3] ? "yes" : "no");
			break;
		case 0xa0:
            PrintAndLogEx(NORMAL,  "CRC of all bloacks match : %s", (trace[3+2]==0xff) ? "no" : "yes");
			break;
		default: 
			PrintAndLogEx(WARNING,  "INVALID %d: %s", blocknum, line);
		break;
	}
	return tracepos+19;
}

int CmdHFFelicaDumpLite(const char *Cmd) {

	char ctmp = param_getchar(Cmd, 0);
	if ( ctmp == 'h' || ctmp == 'H') return usage_hf_felica_dumplite();

	PrintAndLogEx(SUCCESS, "FeliCa lite - dump started");
	PrintAndLogEx(SUCCESS, "press pm3-button to cancel");
	UsbCommand c = {CMD_FELICA_LITE_DUMP, {0,0,0}};
	clearCommandBuffer();
	SendCommand(&c);
	UsbCommand resp;
	
	uint8_t timeout = 0;
	while ( !WaitForResponseTimeout(CMD_ACK, &resp, 2000) ) {
		timeout++;
		printf("."); fflush(stdout);
		if (ukbhit()) {
			int gc = getchar(); (void)gc;
			PrintAndLogEx(NORMAL, "\n[!] aborted via keyboard!\n");
			DropField();
			return 1;
		}
		if (timeout > 100) {
			PrintAndLogEx(WARNING, "timeout while waiting for reply.");
			DropField();
			return 1;
		}
	}
	if (resp.arg[0] == 0) {
		PrintAndLogEx(WARNING, "\nButton pressed. Aborted.");
		return 1;
	}
	
	uint64_t tracelen = resp.arg[1];	
	uint8_t *trace = calloc(tracelen, sizeof(uint8_t));
	if ( trace == NULL ) {
		PrintAndLogEx(WARNING, "Cannot allocate memory for trace");		
		return 1;
	}

	// only download data if there is any.
	if ( tracelen > 0 ) {		
	
		if ( !GetFromDevice(BIG_BUF, trace, tracelen, 0, NULL, 2500, false) ){
			PrintAndLogEx(WARNING, "command execution time out");
			free(trace);
			return 0;
		}
		
		PrintAndLogEx(SUCCESS, "Recorded Activity (trace len = %d bytes)", tracelen);
		
		print_hex_break(trace, tracelen, 32);
		
		printSep();
		uint16_t tracepos = 0;
		while (tracepos < tracelen)
			tracepos = PrintFliteBlock(tracepos, trace, tracelen);
		
		printSep();
	}

    free(trace);
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
						PrintAndLogEx(NORMAL, "Buffer is full, we can't add CRC to your data");
					break;
				}
            }
            continue;
        }
        PrintAndLogEx(WARNING, "Invalid char on input");
        return 0;
    }

    if (crc && datalen>0 && datalen < sizeof(data)-2) {
        uint8_t b1, b2;
		compute_crc(CRC_FELICA, data, datalen, &b1, &b2);
        data[datalen++] = b1;
        data[datalen++] = b2;
    }

    if (active || active_select) {
        c.arg[0] |= FELICA_CONNECT;
        if(active)
            c.arg[0] |= FELICA_NO_SELECT;
    }

    if (power) {
        c.arg[0] |= FELICA_NO_DISCONNECT;
	}
	
    if (datalen > 0) {
        c.arg[0] |= FELICA_RAW;
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

    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {        
        len = iSelect ? (resp.arg[1] & 0xffff) : (resp.arg[0]  & 0xffff);
        PrintAndLogEx(NORMAL, "received %i octets", len);
        if(!len)
            return;
		PrintAndLogEx(NORMAL, "%s", sprint_hex(resp.d.asBytes, len) );
    } else {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
    }
}

static command_t CommandTable[] = {
  {"help",   	CmdHelp,              1, "This help"},
  {"list",   	CmdHFFelicaList,      0, "[Deprecated] List ISO 18092/FeliCa history"},
  {"reader", 	CmdHFFelicaReader,    0, "Act like an ISO18092/FeliCa reader"},
  {"sim",    	CmdHFFelicaSim,       0, "<UID> -- Simulate ISO 18092/FeliCa tag"},
  {"sniff",  	CmdHFFelicaSniff,     0, "sniff ISO 18092/Felica traffic"},
  {"raw",    	CmdHFFelicaCmdRaw,    0, "Send raw hex data to tag"},

  {"litesim",	CmdHFFelicaSimLite,   0, "<NDEF2> - only reply to poll request"},
  {"litedump", 	CmdHFFelicaDumpLite,  0, "Wait for and try dumping FelicaLite"},
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