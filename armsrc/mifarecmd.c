//-----------------------------------------------------------------------------
// Merlok - June 2011
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------

#include "mifarecmd.h"
#include "apps.h"

//-----------------------------------------------------------------------------
// Select, Authenticaate, Read an MIFARE tag. 
// read block
//-----------------------------------------------------------------------------
void MifareReadBlock(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain)
{
  // params
	uint8_t blockNo = arg0;
	uint8_t keyType = arg1;
	uint64_t ui64Key = 0;
	ui64Key = bytes_to_num(datain, 6);
	
	// variables
	byte_t isOK = 0;
	byte_t dataoutbuf[16];
	uint8_t uid[8];
	uint32_t cuid;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;

	// clear trace
	iso14a_clear_tracelen();
//	iso14a_set_tracing(false);

	iso14443a_setup();

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();

	while (true) {
		if(!iso14443a_select_card(uid, NULL, &cuid)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Can't select card");
			break;
		};

		if(mifare_classic_auth(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Auth error");
			break;
		};
		
		if(mifare_classic_readblock(pcs, cuid, blockNo, dataoutbuf)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Read block error");
			break;
		};

		if(mifare_classic_halt(pcs, cuid)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Halt error");
			break;
		};
		
		isOK = 1;
		break;
	}
	
	//  ----------------------------- crypto1 destroy
	crypto1_destroy(pcs);
	
	if (MF_DBGLEVEL >= 2)	DbpString("READ BLOCK FINISHED");

	// add trace trailer
	memset(uid, 0x44, 4);
	LogTrace(uid, 4, 0, 0, TRUE);

	UsbCommand ack = {CMD_ACK, {isOK, 0, 0}};
	memcpy(ack.d.asBytes, dataoutbuf, 16);
	
	LED_B_ON();
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
	LED_B_OFF();


  // Thats it...
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
//  iso14a_set_tracing(TRUE);

}

//-----------------------------------------------------------------------------
// Select, Authenticaate, Read an MIFARE tag. 
// read sector (data = 4 x 16 bytes = 64 bytes)
//-----------------------------------------------------------------------------
void MifareReadSector(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain)
{
  // params
	uint8_t sectorNo = arg0;
	uint8_t keyType = arg1;
	uint64_t ui64Key = 0;
	ui64Key = bytes_to_num(datain, 6);
	
	// variables
	byte_t isOK = 0;
	byte_t dataoutbuf[16 * 4];
	uint8_t uid[8];
	uint32_t cuid;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;

	// clear trace
	iso14a_clear_tracelen();
//	iso14a_set_tracing(false);

	iso14443a_setup();

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();

	while (true) {
		if(!iso14443a_select_card(uid, NULL, &cuid)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Can't select card");
			break;
		};

		if(mifare_classic_auth(pcs, cuid, sectorNo * 4, keyType, ui64Key, AUTH_FIRST)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Auth error");
			break;
		};
		
		if(mifare_classic_readblock(pcs, cuid, sectorNo * 4 + 0, dataoutbuf + 16 * 0)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Read block 0 error");
			break;
		};
		if(mifare_classic_readblock(pcs, cuid, sectorNo * 4 + 1, dataoutbuf + 16 * 1)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Read block 1 error");
			break;
		};
		if(mifare_classic_readblock(pcs, cuid, sectorNo * 4 + 2, dataoutbuf + 16 * 2)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Read block 2 error");
			break;
		};
		if(mifare_classic_readblock(pcs, cuid, sectorNo * 4 + 3, dataoutbuf + 16 * 3)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Read block 3 error");
			break;
		};
		
		if(mifare_classic_halt(pcs, cuid)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Halt error");
			break;
		};

		isOK = 1;
		break;
	}
	
	//  ----------------------------- crypto1 destroy
	crypto1_destroy(pcs);
	
	if (MF_DBGLEVEL >= 2) DbpString("READ SECTOR FINISHED");

	// add trace trailer
	memset(uid, 0x44, 4);
	LogTrace(uid, 4, 0, 0, TRUE);

	UsbCommand ack = {CMD_ACK, {isOK, 0, 0}};
	memcpy(ack.d.asBytes, dataoutbuf, 16 * 2);
	
	LED_B_ON();
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));

	SpinDelay(100);
	
	memcpy(ack.d.asBytes, dataoutbuf + 16 * 2, 16 * 2);
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
	LED_B_OFF();	

	// Thats it...
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
//  iso14a_set_tracing(TRUE);

}

//-----------------------------------------------------------------------------
// Select, Authenticaate, Read an MIFARE tag. 
// read block
//-----------------------------------------------------------------------------
void MifareWriteBlock(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain)
{
	// params
	uint8_t blockNo = arg0;
	uint8_t keyType = arg1;
	uint64_t ui64Key = 0;
	byte_t blockdata[16];

	ui64Key = bytes_to_num(datain, 6);
	memcpy(blockdata, datain + 10, 16);
	
	// variables
	byte_t isOK = 0;
	uint8_t uid[8];
	uint32_t cuid;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;

	// clear trace
	iso14a_clear_tracelen();
//  iso14a_set_tracing(false);

	iso14443a_setup();

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();

	while (true) {
			if(!iso14443a_select_card(uid, NULL, &cuid)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Can't select card");
			break;
		};

		if(mifare_classic_auth(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Auth error");
			break;
		};
		
		if(mifare_classic_writeblock(pcs, cuid, blockNo, blockdata)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Write block error");
			break;
		};

		if(mifare_classic_halt(pcs, cuid)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Halt error");
			break;
		};
		
		isOK = 1;
		break;
	}
	
	//  ----------------------------- crypto1 destroy
	crypto1_destroy(pcs);
	
	if (MF_DBGLEVEL >= 2)	DbpString("WRITE BLOCK FINISHED");

	// add trace trailer
	memset(uid, 0x44, 4);
	LogTrace(uid, 4, 0, 0, TRUE);

	UsbCommand ack = {CMD_ACK, {isOK, 0, 0}};
	
	LED_B_ON();
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
	LED_B_OFF();	


	// Thats it...
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
//  iso14a_set_tracing(TRUE);

}

// Return 1 if the nonce is invalid else return 0
int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, byte_t * parity) {
	return ((oddparity((Nt >> 24) & 0xFF) == ((parity[0]) ^ oddparity((NtEnc >> 24) & 0xFF) ^ BIT(Ks1,16))) & \
	(oddparity((Nt >> 16) & 0xFF) == ((parity[1]) ^ oddparity((NtEnc >> 16) & 0xFF) ^ BIT(Ks1,8))) & \
	(oddparity((Nt >> 8) & 0xFF) == ((parity[2]) ^ oddparity((NtEnc >> 8) & 0xFF) ^ BIT(Ks1,0)))) ? 1 : 0;
}

//-----------------------------------------------------------------------------
// MIFARE nested authentication. 
// 
//-----------------------------------------------------------------------------
void MifareNested(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain)
{
	// params
	uint8_t blockNo = arg0;
	uint8_t keyType = arg1;
	uint8_t targetBlockNo = arg2 & 0xff;
	uint8_t targetKeyType = (arg2 >> 8) & 0xff;
	uint64_t ui64Key = 0;

	ui64Key = bytes_to_num(datain, 6);
	
	// variables
	int rtr, i, j, m, len;
	int davg, dmin, dmax;
	uint8_t uid[8];
	uint32_t cuid, nt1, nt2, nttmp, nttest, par, ks1;
	uint8_t par_array[4];
	nestedVector nvector[NES_MAX_INFO + 1][10];
	int nvectorcount[NES_MAX_INFO + 1];
	int ncount = 0;
	UsbCommand ack = {CMD_ACK, {0, 0, 0}};
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;
	uint8_t* receivedAnswer = mifare_get_bigbufptr();

	//init
	for (i = 0; i < NES_MAX_INFO + 1; i++) nvectorcount[i] = 11;  //  11 - empty block;
	
	// clear trace
	iso14a_clear_tracelen();
  iso14a_set_tracing(false);
	
	iso14443a_setup();

	LED_A_ON();
	LED_B_ON();
	LED_C_OFF();

  FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
  SpinDelay(200);
	
	davg = dmax = 0;
	dmin = 2000;

	// test nonce distance
	for (rtr = 0; rtr < 10; rtr++) {
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(100);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);

    // Test if the action was cancelled
    if(BUTTON_PRESS()) {
      break;
    }

		if(!iso14443a_select_card(uid, NULL, &cuid)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Can't select card");
			break;
		};
		
		if(mifare_classic_authex(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST, &nt1)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Auth1 error");
			break;
		};

		if(mifare_classic_authex(pcs, cuid, blockNo, keyType, ui64Key, AUTH_NESTED, &nt2)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Auth2 error");
			break;
		};
		
		nttmp = prng_successor(nt1, 500);
		for (i = 501; i < 2000; i++) {
			nttmp = prng_successor(nttmp, 1);
			if (nttmp == nt2) break;
		}
		
		if (i != 2000) {
			davg += i;
			if (dmin > i) dmin = i;
			if (dmax < i) dmax = i;
			if (MF_DBGLEVEL >= 4)	Dbprintf("r=%d nt1=%08x nt2=%08x distance=%d", rtr, nt1, nt2, i);
		}
	}
	
	if (rtr == 0)	return;

	davg = davg / rtr;
	if (MF_DBGLEVEL >= 3)	Dbprintf("distance: min=%d max=%d avg=%d", dmin, dmax, davg);

	LED_B_OFF();

//  -------------------------------------------------------------------------------------------------	
	
	LED_C_ON();

	//  get crypted nonces for target sector
	for (rtr = 0; rtr < NS_RETRIES_GETNONCE; rtr++) {
	if (MF_DBGLEVEL >= 4)			Dbprintf("------------------------------");

		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(100);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);

    // Test if the action was cancelled
    if(BUTTON_PRESS()) {
      break;
    }

		if(!iso14443a_select_card(uid, NULL, &cuid)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Can't select card");
			break;
		};
		
		if(mifare_classic_authex(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST, &nt1)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Auth1 error");
			break;
		};

		// nested authentication
		len = mifare_sendcmd_shortex(pcs, AUTH_NESTED, 0x60 + (targetKeyType & 0x01), targetBlockNo, receivedAnswer, &par);
		if (len != 4) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Auth2 error len=%d", len);
			break;
		};
	
		nt2 = bytes_to_num(receivedAnswer, 4);		
		if (MF_DBGLEVEL >= 4)	Dbprintf("r=%d nt1=%08x nt2enc=%08x nt2par=%08x", rtr, nt1, nt2, par);
		
		// Parity validity check
		for (i = 0; i < 4; i++) {
			par_array[i] = (oddparity(receivedAnswer[i]) != ((par & 0x08) >> 3));
			par = par << 1;
		}
		
		ncount = 0;
		for (m = dmin - NS_TOLERANCE; m < dmax + NS_TOLERANCE; m++) {
			nttest = prng_successor(nt1, m);
			ks1 = nt2 ^ nttest;

			if (valid_nonce(nttest, nt2, ks1, par_array) && (ncount < 11)){
				
				nvector[NES_MAX_INFO][ncount].nt = nttest;
				nvector[NES_MAX_INFO][ncount].ks1 = ks1;
				ncount++;
				nvectorcount[NES_MAX_INFO] = ncount;
				if (MF_DBGLEVEL >= 4)	Dbprintf("valid m=%d ks1=%08x nttest=%08x", m, ks1, nttest);
			}

		}
		
		// select vector with length less than got
		if (nvectorcount[NES_MAX_INFO] != 0) {
			m = NES_MAX_INFO;
			
			for (i = 0; i < NES_MAX_INFO; i++)
				if (nvectorcount[i] > 10) {
					m = i;
					break;
				}
				
			if (m == NES_MAX_INFO)
				for (i = 0; i < NES_MAX_INFO; i++)
					if (nvectorcount[NES_MAX_INFO] < nvectorcount[i]) {
						m = i;
						break;
					}
					
			if (m != NES_MAX_INFO) {
				for (i = 0; i < nvectorcount[m]; i++) {
					nvector[m][i] = nvector[NES_MAX_INFO][i];
				}
				nvectorcount[m] = nvectorcount[NES_MAX_INFO];
			}
		}
	}

	LED_C_OFF();
	
	//  ----------------------------- crypto1 destroy
	crypto1_destroy(pcs);
	
	// add trace trailer
	memset(uid, 0x44, 4);
	LogTrace(uid, 4, 0, 0, TRUE);

	for (i = 0; i < NES_MAX_INFO; i++) {
		if (nvectorcount[i] > 10) continue;
		
		for (j = 0; j < nvectorcount[i]; j += 5) {
			ncount = nvectorcount[i] - j;
			if (ncount > 5) ncount = 5; 

			ack.arg[0] = 0; // isEOF = 0
			ack.arg[1] = ncount;
			ack.arg[2] = targetBlockNo + (targetKeyType * 0x100);
			memset(ack.d.asBytes, 0x00, sizeof(ack.d.asBytes));
			
			memcpy(ack.d.asBytes, &cuid, 4);
			for (m = 0; m < ncount; m++) {
				memcpy(ack.d.asBytes + 8 + m * 8 + 0, &nvector[i][m + j].nt, 4);
				memcpy(ack.d.asBytes + 8 + m * 8 + 4, &nvector[i][m + j].ks1, 4);
			}
	
			LED_B_ON();
			SpinDelay(100);
			UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
			LED_B_OFF();	
		}
	}

	// finalize list
	ack.arg[0] = 1; // isEOF = 1
	ack.arg[1] = 0;
	ack.arg[2] = 0;
	memset(ack.d.asBytes, 0x00, sizeof(ack.d.asBytes));
	
	LED_B_ON();
	SpinDelay(300);
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
	LED_B_OFF();	

	if (MF_DBGLEVEL >= 4)	DbpString("NESTED FINISHED");

	// Thats it...
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	
  iso14a_set_tracing(TRUE);
}

//-----------------------------------------------------------------------------
// MIFARE check keys. key count up to 8. 
// 
//-----------------------------------------------------------------------------
void MifareChkKeys(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain)
{
  // params
	uint8_t blockNo = arg0;
	uint8_t keyType = arg1;
	uint8_t keyCount = arg2;
	uint64_t ui64Key = 0;
	
	// variables
	int i;
	byte_t isOK = 0;
	uint8_t uid[8];
	uint32_t cuid;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;
	
	// clear debug level
	int OLD_MF_DBGLEVEL = MF_DBGLEVEL;	
	MF_DBGLEVEL = MF_DBG_NONE;
	
	// clear trace
	iso14a_clear_tracelen();
  iso14a_set_tracing(TRUE);

	iso14443a_setup();

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();

	SpinDelay(300);
	for (i = 0; i < keyCount; i++) {
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    SpinDelay(100);
    FpgaWriteConfWord(FPGA_MAJOR_MODE_HF_ISO14443A | FPGA_HF_ISO14443A_READER_MOD);

		if(!iso14443a_select_card(uid, NULL, &cuid)) {
			if (OLD_MF_DBGLEVEL >= 1)	Dbprintf("Can't select card");
			break;
		};

		ui64Key = bytes_to_num(datain + i * 6, 6);
		if(mifare_classic_auth(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST)) {
			continue;
		};
		
		isOK = 1;
		break;
	}
	
	//  ----------------------------- crypto1 destroy
	crypto1_destroy(pcs);
	
	// add trace trailer
	memset(uid, 0x44, 4);
	LogTrace(uid, 4, 0, 0, TRUE);

	UsbCommand ack = {CMD_ACK, {isOK, 0, 0}};
	if (isOK) memcpy(ack.d.asBytes, datain + i * 6, 6);
	
	LED_B_ON();
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
	LED_B_OFF();

  // Thats it...
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();

	// restore debug level
	MF_DBGLEVEL = OLD_MF_DBGLEVEL;	
}

//-----------------------------------------------------------------------------
// MIFARE commands set debug level
// 
//-----------------------------------------------------------------------------
void MifareSetDbgLvl(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain){
	MF_DBGLEVEL = arg0;
	Dbprintf("Debug level: %d", MF_DBGLEVEL);
}

//-----------------------------------------------------------------------------
// Work with emulator memory
// 
//-----------------------------------------------------------------------------
void MifareEMemClr(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain){
	emlClearMem();
}

void MifareEMemSet(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain){
	emlSetMem(datain, arg0, arg1); // data, block num, blocks count
}

void MifareEMemGet(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain){
	UsbCommand ack = {CMD_ACK, {arg0, arg1, 0}};

	emlGetMem(ack.d.asBytes, arg0, arg1); // data, block num, blocks count

	LED_B_ON();
	UsbSendPacket((uint8_t *)&ack, sizeof(UsbCommand));
	LED_B_OFF();
}

//-----------------------------------------------------------------------------
// Load a card into the emulator memory
// 
//-----------------------------------------------------------------------------
void MifareECardLoad(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain){
	int i;
	uint8_t sectorNo = 0;
	uint8_t keyType = arg1;
	uint64_t ui64Key = 0;
	uint32_t cuid;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;

	// variables
	byte_t dataoutbuf[16];
	byte_t dataoutbuf2[16];
	uint8_t uid[8];

	// clear trace
	iso14a_clear_tracelen();
	iso14a_set_tracing(false);
	
	iso14443a_setup();

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();
	
	while (true) {
		if(!iso14443a_select_card(uid, NULL, &cuid)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Can't select card");
			break;
		};
		
		for (i = 0; i < 16; i++) {
			sectorNo = i;
			ui64Key = emlGetKey(sectorNo, keyType);
	
			if (!i){
				if(mifare_classic_auth(pcs, cuid, sectorNo * 4, keyType, ui64Key, AUTH_FIRST)) {
					if (MF_DBGLEVEL >= 1)	Dbprintf("Sector[%d]. Auth error", i);
					break;
				}
			} else {
				if(mifare_classic_auth(pcs, cuid, sectorNo * 4, keyType, ui64Key, AUTH_NESTED)) {
					if (MF_DBGLEVEL >= 1)	Dbprintf("Sector[%d]. Auth nested error", i);
					break;
				}
			}
		
			if(mifare_classic_readblock(pcs, cuid, sectorNo * 4 + 0, dataoutbuf)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Read block 0 error");
				break;
			};
			emlSetMem(dataoutbuf, sectorNo * 4 + 0, 1);
			
			if(mifare_classic_readblock(pcs, cuid, sectorNo * 4 + 1, dataoutbuf)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Read block 1 error");
				break;
			};
			emlSetMem(dataoutbuf, sectorNo * 4 + 1, 1);

			if(mifare_classic_readblock(pcs, cuid, sectorNo * 4 + 2, dataoutbuf)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Read block 2 error");
				break;
			};
			emlSetMem(dataoutbuf, sectorNo * 4 + 2, 1);

			// get block 3 bytes 6-9
			if(mifare_classic_readblock(pcs, cuid, sectorNo * 4 + 3, dataoutbuf)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Read block 3 error");
				break;
			};
			emlGetMem(dataoutbuf2, sectorNo * 4 + 3, 1);
			memcpy(&dataoutbuf2[6], &dataoutbuf[6], 4);
			emlSetMem(dataoutbuf2,  sectorNo * 4 + 3, 1);
		}

		if(mifare_classic_halt(pcs, cuid)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("Halt error");
			break;
		};
		
		break;
	}	

	//  ----------------------------- crypto1 destroy
	crypto1_destroy(pcs);

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	
	if (MF_DBGLEVEL >= 2) DbpString("EMUL FILL SECTORS FINISHED");

	// add trace trailer
	memset(uid, 0x44, 4);
	LogTrace(uid, 4, 0, 0, TRUE);
}

//-----------------------------------------------------------------------------
// MIFARE 1k emulator
// 
//-----------------------------------------------------------------------------

