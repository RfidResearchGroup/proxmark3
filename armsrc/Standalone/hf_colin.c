//-----------------------------------------------------------------------------
// Colin Brigato, 2016,2017
// Christian Herrmann, 2017
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for HF Mifare aka ColinRun by Colin Brigato
//-----------------------------------------------------------------------------
#include "hf_colin.h"

// Colin's sniff and repeat routine for HF Mifare
void RunMod() {

	/* Messy messy */
	#define MF1KSZ 1024
	#define MF1KSZSIZE 64
	
	/* some mess forgotten to get rid of */
    uint8_t sectorsCnt = (mifare_size / sectorSize);
    uint64_t key64;
    uint8_t *keyBlock = NULL;

	/* know number of known keys for standalone mode */
	#define STKEYS 35
	uint64_t mfKeys[STKEYS] = {
        0xffffffffffff, // TRANSPORTS
        0x414c41524f4e, // ALARON NORALSY
        0x424c41524f4e, // BLARON NORALSY
        0x8829da9daf76, // URMET CAPTIV IF A => ALL A/B
        0xa0a1a2a3a4a5, // PUBLIC BLOC0 BTICINO HARDENED & MAD ACCESS
        0x021209197591, // BTCINO HARDENED UNDETERMINED SPREAKD 0x01->0x13 key
        0x484558414354, // INFINEON ON A / 0F SEC B
        /* . . * /
	}

	/* Can remember something like that in case of Bigbuf */
    keyBlock = BigBuf_malloc(STKEYS * 6);
    int mfKeysCnt = sizeof(mfKeys) / sizeof(uint64_t);

    for (int mfKeyCounter = 0; mfKeyCounter < mfKeysCnt; mfKeyCounter++) {
        num_to_bytes(mfKeys[mfKeyCounter], 6, (uint8_t *)(keyBlock + mfKeyCounter * 6));
    }

    uint8_t sectorsCnt = (MF1KSZ / MF1KSZSIZE);
    uint8_t foundKey[2][40][6]= {0xff}; /* C99 abusal 6.7.8.21 */
    /* TODO : remember why we actually had need to initialize this array in such specific case */
    /* and why not a simple memset abuse to 0xffize the whole space in one go ? */

    int key = -1;
    int block = 0;
    bool err = 0;
    bool trapped = 0;
    uint32_t size = mfKeysCnt; /* what’s the point for copy ? int should be uint32_t in this case, same deal */

	Dbprintf("...Waiting For Tag...");
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
	while (!iso14443a_select_card(cjuid, NULL, &cjcuid, true, 0, true)) {
		WDT_HIT();
	}
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelay(100);
	
	Dbprintf("Got tag : %02x%02x%02x%02x", at91stdio_explode(cjuid, &cjcuid));

	uint32_t end_time;
	uint32_t start_time = end_time = GetTickCount();

	/* then let’s expose this “optimal case” of “well known vigik schemes” : */
	for (uint8_t type = 0; type < 2 && !err && !trapped; type++) {
        for (int sec = 0; sec < sectorsCnt && !err && !trapped; ++sec) {
            /* see after for the chk, nothing fancy */
            key = cjat91_saMifareChkKeys(sec * 4, type, NULL, size, &keyBlock[0], &key64);
            if (key == -1) {
                err = 1;
                /* used in “portable” imlementation on microcontroller: it reports back the fail and open the standalone lock */
                cmd_send(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
                break;
            } else {

			/*  BRACE YOURSELF */
			/* AS LONG AS WE TRAP A KNOWN KEY, WE STOP CHECKING AND ENFORCE KNOWN SCHEMES */
		else {
                num_to_bytes(key64, 6, foundKey[type][sec]);
                uint8_t tosendkey[12];
                sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
					foundKey[type][sec][0], foundKey[type][sec][1], foundKey[type][sec][2], 
					foundKey[type][sec][3], foundKey[type][sec][4], foundKey[type][sec][5]
				);
                cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sec, type, tosendkey, 12);

                switch (key64) {
                case 0x484558414354:
                    Dbprintf("%c>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%c", _RED_, _WHITE_);
                    Dbprintf("    .TAG SEEMS %cDETERMINISTIC%c.     ", _GREEN_, _WHITE_);
                    Dbprintf("%cDetected: %c INFI_HEXACT_VIGIK_TAG%c", _ORANGE_, _CYAN_, _WHITE_);
					Dbprintf("...%c[%cKey_derivation_schemeTest%c]%c...", _YELLOW_,_GREEN_, _YELLOW_, _GREEN_);
                    Dbprintf("%c>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%c",_GREEN_, _WHITE_);
                    ;
                    uint16_t t = 0;
                    for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
                        num_to_bytes(0x484558414354, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
								foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
								foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
							);
                        cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    }
                    t = 1;
                    uint16_t sectorNo = 0;
                    num_to_bytes(0xa22ae129c013, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
							foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 1;
                    num_to_bytes(0x49fae4e3849f, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
							foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 2;
                    num_to_bytes(0x38fcf33072e0, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
							foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 3;
                    num_to_bytes(0x8ad5517b4b18, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
							foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 4;
                    num_to_bytes(0x509359f131b1, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 5;
                    num_to_bytes(0x6c78928e1317, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 6;
                    num_to_bytes(0xaa0720018738, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 7;
                    num_to_bytes(0xa6cac2886412, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 8;
                    num_to_bytes(0x62d0c424ed8e, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 9;
                    num_to_bytes(0xe64a986a5d94, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 10;
                    num_to_bytes(0x8fa1d601d0a2, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 11;
                    num_to_bytes(0x89347350bd36, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 12;
                    num_to_bytes(0x66d2b7dc39ef, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 13;
                    num_to_bytes(0x6bc1e1ae547d, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 14;
                    num_to_bytes(0x22729a9bd40f, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    sectorNo = 15;
                    num_to_bytes(0x484558414354, 6, foundKey[t][sectorNo]);
                    sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
                            foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                    cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    trapped = 1;
                    break;
                case 0x8829da9daf76:
                    Dbprintf("%c>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%c", _RED_, _WHITE_);
                    Dbprintf("    .TAG SEEMS %cDETERMINISTIC%c.     ", _GREEN_, _WHITE_);
                    Dbprintf("%cDetected :%cURMET_CAPTIVE_VIGIK_TAG%c", _ORANGE_, _CYAN_, _WHITE_);
					Dbprintf("...%c[%cKey_derivation_schemeTest%c]%c...", _YELLOW_, _GREEN_, _YELLOW_, _GREEN_);
                    Dbprintf("%c>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%c",_GREEN_, _WHITE_);
                    // emlClearMem();
                    for (uint16_t t = 0; t < 2; t++) {
                        for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
                            //                          validKey[t][sectorNo] = true;
                            num_to_bytes(key64, 6, foundKey[t][sectorNo]);
                            sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
								foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
								foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
							);
                            cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                        }
                    }
                    trapped = 1;
                    break;
                case 0x414c41524f4e:
                case 0x424c41524f4e:
                    Dbprintf("%c>>>>>>>>>>>>!*STOP*!<<<<<<<<<<<<<<%c", _RED_, _WHITE_);
                    Dbprintf("    .TAG SEEMS %cDETERMINISTIC%c.     ", _GREEN_, _WHITE_);
                    Dbprintf("%c  Detected :%cNORALSY_VIGIK_TAG %c", _ORANGE_, _CYAN_, _WHITE_);
					Dbprintf("...%c[%cKey_derivation_schemeTest%c]%c...", _YELLOW_, _GREEN_, _YELLOW_, _GREEN_);
                    Dbprintf("%c>>>>>>>>>>>>!*DONE*!<<<<<<<<<<<<<<%c", _GREEN_, _WHITE_);
                    ;
                    t = 0;
                    for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
                        num_to_bytes(0x414c41524f4e, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
							foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                        cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    }
                    t = 1;
                    for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
                        num_to_bytes(0x424c41524f4e, 6, foundKey[t][sectorNo]);
                        sprintf(tosendkey, "%02x%02x%02x%02x%02x%02x",
							foundKey[t][sectorNo][0], foundKey[t][sectorNo][1], foundKey[t][sectorNo][2],
							foundKey[t][sectorNo][3], foundKey[t][sectorNo][4], foundKey[t][sectorNo][5]
						);
                        cmd_send(CMD_CJB_INFORM_CLIENT_KEY, 12, sectorNo, t, tosendkey, 12);
                    }
                    trapped = 1;
                    break;
                }
				/* etc etc for testing schemes quick schemes */
            }
        }
    }

		if (!allKeysFound) {
			cmd_send(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
			return;
		}

		/* Settings keys to emulator */
        emlClearMem();
        uint8_t mblock[16];
        for (uint8_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
            emlGetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
            for (uint8_t t = 0; t < 2; t++) {
                memcpy(mblock + t * 10, foundKey[t][sectorNo], 6);
            }
            emlSetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
        }
        Dbprintf("%c>>%c Setting Keys->Emulator MEM...[%cOK%c]", _YELLOW_, _WHITE_, _GREEN_, _WHITE_);

        /* filling TAG to emulator */
        uint8_t filled = 0
            Dbprintf("%c>>%c Filling Emulator <- from A keys...", _YELLOW_, _WHITE_);
            /* no trace, no dbg  */
            MifareECardLoad(sectorsCnt, 0, 0, &filled);
            if (filled != 1) {
                Dbprintf("%c>>%c W_FAILURE ! %cTrying fallback B keys....", _RED_, _ORANGE_, _WHITE_);

                /* no trace, no dbg  */
                MifareECardLoad(sectorsCnt, 1, 0, &filled);
                if (filled != 1) {
                    Dbprintf("FATAL:EML_FALLBACKFILL_B");
                    cmd_send(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
                    return;
                }
            }
            end_time = GetTickCount();
            Dbprintf("%c>>%c Time for VIGIK break :%c%dms%c", _GREEN_, _WHITE_, _YELLOW_, end_time - start_time, _WHITE_);
            cmd_send(CMD_CJB_FSMSTATE_MENU, 0, 0, 0, 0, 0);
            return;
        }
    }
/* . . . */

/* the chk function is a piwi’ed(tm) check that will try all keys for
a particular sector. also no tracing no dbg */

int cjat91_saMifareChkKeys(uint8_t blockNo, uint8_t keyType, bool clearTrace, uint8_t keyCount, uint8_t * datain, uint64_t *key) {

   MF_DBGLEVEL = MF_DBG_NONE;
   iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
   set_tracing(FALSE);

   for (i = 0; i < keyCount; ++i) {
			/* no need for anticollision. just verify tag is still here */
			if (!iso14443a_select_card(uid, NULL, &cuid, true, 0 , true)) {
				  cjat91_printf("FATAL : E_MF_LOSTTAG");
				  return -1;
			}

			uint64_t ui64Key = bytes_to_num(datain + i * 6, 6);
			if (mifare_classic_auth(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST)) {

					uint8_t dummy_answer = 0;
					ReaderTransmit(&dummy_answer, 1, NULL);
				   // wait for the card to become ready again
					SpinDelayUs(AUTHENTICATION_TIMEOUT);
					
					continue;
			}
			isOK = 1;
			crypto1_destroy(pcs);
			FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
			*key = ui64Key;
			return i;
	}
	crypto1_destroy(pcs);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	return -1;
}