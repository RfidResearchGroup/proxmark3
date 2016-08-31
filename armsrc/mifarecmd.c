//-----------------------------------------------------------------------------
// Merlok - June 2011, 2012
// Gerhard de Koning Gans - May 2008
// Hagen Fritsch - June 2010
// Midnitesnake - Dec 2013
// Andy Davies  - Apr 2014
// Iceman - May 2014,2015,2016
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Routines to support ISO 14443 type A.
//-----------------------------------------------------------------------------

#include "mifarecmd.h"
#include "apps.h"
#include "util.h"
#include "crc.h"
#include "protocols.h"
#include "parity.h"

//-----------------------------------------------------------------------------
// Select, Authenticate, Read a MIFARE tag. 
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
	byte_t dataoutbuf[16] = {0x00};
	uint8_t uid[10] = {0x00};
	uint32_t cuid = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;

	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	clear_trace();
	set_tracing(true);

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();

	while (true) {
		if(!iso14443a_select_card(uid, NULL, &cuid, true, 0)) {
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
	
	crypto1_destroy(pcs);
	
	if (MF_DBGLEVEL >= 2)	DbpString("READ BLOCK FINISHED");

	LED_B_ON();
	cmd_send(CMD_ACK,isOK,0,0,dataoutbuf,16);
	LED_B_OFF();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
}

void MifareUC_Auth(uint8_t arg0, uint8_t *keybytes){

	bool turnOffField = (arg0 == 1);

	LED_A_ON(); LED_B_OFF(); LED_C_OFF();

	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	clear_trace();
	set_tracing(true);

	if(!iso14443a_select_card(NULL, NULL, NULL, true, 0)) {
		if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Can't select card");
		OnError(0);
		return;
	};
	
	if(!mifare_ultra_auth(keybytes)){
		if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Authentication failed");
		OnError(1);
		return;
	}

	if (turnOffField) {
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
		LEDsoff();
	}
	cmd_send(CMD_ACK,1,0,0,0,0);
}

// Arg0 = BlockNo,
// Arg1 = UsePwd bool
// datain = PWD bytes,
void MifareUReadBlock(uint8_t arg0, uint8_t arg1, uint8_t *datain)
{
	uint8_t blockNo = arg0;
	byte_t dataout[16] = {0x00};
	bool useKey = (arg1 == 1); //UL_C
	bool usePwd = (arg1 == 2); //UL_EV1/NTAG

	LEDsoff();
	LED_A_ON();
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	clear_trace();
	set_tracing(true);

	int len = iso14443a_select_card(NULL, NULL, NULL, true, 0);
	if(!len) {
		if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Can't select card (RC:%02X)",len);
		OnError(1);
		return;
	}

	// UL-C authentication
	if ( useKey ) {
		uint8_t key[16] = {0x00};
		memcpy(key, datain, sizeof(key) );

		if ( !mifare_ultra_auth(key) ) {
			OnError(1);
			return;
		}
	}

	// UL-EV1 / NTAG authentication
	if ( usePwd ) {
		uint8_t pwd[4] = {0x00};
		memcpy(pwd, datain, 4);
		uint8_t pack[4] = {0,0,0,0};
		if (!mifare_ul_ev1_auth(pwd, pack)) {
			OnError(1);
			return;
		}
	}	

	if( mifare_ultra_readblock(blockNo, dataout) ) {
		if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Read block error");
		OnError(2);
		return;
	}

	if( mifare_ultra_halt() ) {
		if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Halt error");
		OnError(3);
		return;
	}

    cmd_send(CMD_ACK,1,0,0,dataout,16);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
}

//-----------------------------------------------------------------------------
// Select, Authenticate, Read a MIFARE tag. 
// read sector (data = 4 x 16 bytes = 64 bytes, or 16 x 16 bytes = 256 bytes)
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
	byte_t dataoutbuf[16 * 16];
	uint8_t uid[10] = {0x00};
	uint32_t cuid = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;

	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	clear_trace();
	set_tracing(true);
	
	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();

	isOK = 1;
	if(!iso14443a_select_card(uid, NULL, &cuid, true, 0)) {
		isOK = 0;
		if (MF_DBGLEVEL >= 1)	Dbprintf("Can't select card");
	}
	
	
	if(isOK && mifare_classic_auth(pcs, cuid, FirstBlockOfSector(sectorNo), keyType, ui64Key, AUTH_FIRST)) {
		isOK = 0;
		if (MF_DBGLEVEL >= 1)	Dbprintf("Auth error");
	}
	
	for (uint8_t blockNo = 0; isOK && blockNo < NumBlocksPerSector(sectorNo); blockNo++) {
		if(mifare_classic_readblock(pcs, cuid, FirstBlockOfSector(sectorNo) + blockNo, dataoutbuf + 16 * blockNo)) {
			isOK = 0;
			if (MF_DBGLEVEL >= 1)	Dbprintf("Read sector %2d block %2d error", sectorNo, blockNo);
			break;
		}
	}
		
	if(mifare_classic_halt(pcs, cuid)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Halt error");
	}

	if (MF_DBGLEVEL >= 2) DbpString("READ SECTOR FINISHED");

	crypto1_destroy(pcs);

	LED_B_ON();
	cmd_send(CMD_ACK,isOK,0,0,dataoutbuf,16*NumBlocksPerSector(sectorNo));
	LED_B_OFF();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
}

// arg0 = blockNo (start)
// arg1 = Pages (number of blocks)
// arg2 = useKey
// datain = KEY bytes
void MifareUReadCard(uint8_t arg0, uint16_t arg1, uint8_t arg2, uint8_t *datain)
{
	LEDsoff();
	LED_A_ON();
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	// free eventually allocated BigBuf memory
	BigBuf_free(); BigBuf_Clear_ext(false);
	clear_trace();
	set_tracing(true);
	
	// params
	uint8_t blockNo = arg0;
	uint16_t blocks = arg1;
	bool useKey = (arg2 == 1); //UL_C
	bool usePwd = (arg2 == 2); //UL_EV1/NTAG
	uint32_t countblocks = 0;
	uint8_t *dataout = BigBuf_malloc(CARD_MEMORY_SIZE);
	if (dataout == NULL){
		Dbprintf("out of memory");
		OnError(1);
		return;
	}

	int len = iso14443a_select_card(NULL, NULL, NULL, true, 0);
	if (!len) {
		if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Can't select card (RC:%d)",len);
		OnError(1);
		return;
	}

	// UL-C authentication
	if ( useKey ) {
		uint8_t key[16] = {0x00};
		memcpy(key, datain, sizeof(key) );

		if ( !mifare_ultra_auth(key) ) {
			OnError(1);
			return;
		}
	}

	// UL-EV1 / NTAG authentication
	if (usePwd) {
		uint8_t pwd[4] = {0x00};
		memcpy(pwd, datain, sizeof(pwd));
		uint8_t pack[4] = {0,0,0,0};

		if (!mifare_ul_ev1_auth(pwd, pack)){
			OnError(1);
			return;			
		}
	}

	for (int i = 0; i < blocks; i++){
		if ((i*4) + 4 >= CARD_MEMORY_SIZE) {
			Dbprintf("Data exceeds buffer!!");
			break;
		}

		len = mifare_ultra_readblock(blockNo + i, dataout + 4 * i);
		
		if (len) {
			if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Read block %d error",i);
			// if no blocks read - error out
			if (i==0){
				OnError(2);
			return;
			} else {
				//stop at last successful read block and return what we got
				break;
			}
		} else {
			countblocks++;
		}
	}

	len = mifare_ultra_halt();
	if (len) {
		if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Halt error");
		OnError(3);
		return;
	}

	if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("Blocks read %d", countblocks);

	countblocks *= 4;

	cmd_send(CMD_ACK, 1, countblocks, BigBuf_max_traceLen(), 0, 0);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	BigBuf_free();
	set_tracing(FALSE);
}

//-----------------------------------------------------------------------------
// Select, Authenticate, Write a MIFARE tag. 
// read block
//-----------------------------------------------------------------------------
void MifareWriteBlock(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain)
{
	// params
	uint8_t blockNo = arg0;
	uint8_t keyType = arg1;
	uint64_t ui64Key = 0;
	byte_t blockdata[16] = {0x00};

	ui64Key = bytes_to_num(datain, 6);
	memcpy(blockdata, datain + 10, 16);
	
	// variables
	byte_t isOK = 0;
	uint8_t uid[10] = {0x00};
	uint32_t cuid = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;

	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	clear_trace();
	set_tracing(true);
	
	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();

	while (true) {
			if(!iso14443a_select_card(uid, NULL, &cuid, true, 0)) {
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

	LED_B_ON();
	cmd_send(CMD_ACK,isOK,0,0,0,0);
	LED_B_OFF();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
}

/* // Command not needed but left for future testing 
void MifareUWriteBlockCompat(uint8_t arg0, uint8_t *datain)
{
	uint8_t blockNo = arg0;
	byte_t blockdata[16] = {0x00};

	memcpy(blockdata, datain, 16);

	uint8_t uid[10] = {0x00};

	LED_A_ON(); LED_B_OFF(); LED_C_OFF();

	clear_trace();
	set_tracing(true);
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	if(!iso14443a_select_card(uid, NULL, NULL, true, 0)) {
		if (MF_DBGLEVEL >= 1)   Dbprintf("Can't select card");
		OnError(0);
		return;
	};

	if(mifare_ultra_writeblock_compat(blockNo, blockdata)) {
		if (MF_DBGLEVEL >= 1)   Dbprintf("Write block error");
		OnError(0);
		return;	};

	if(mifare_ultra_halt()) {
		if (MF_DBGLEVEL >= 1)   Dbprintf("Halt error");
		OnError(0);
		return;
	};

	if (MF_DBGLEVEL >= 2)   DbpString("WRITE BLOCK FINISHED");

	cmd_send(CMD_ACK,1,0,0,0,0);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
}
*/

// Arg0   : Block to write to.
// Arg1   : 0 = use no authentication.
//          1 = use 0x1A authentication.
//          2 = use 0x1B authentication.
// datain : 4 first bytes is data to be written.
//        : 4/16 next bytes is authentication key.
void MifareUWriteBlock(uint8_t arg0, uint8_t arg1, uint8_t *datain)
{
	uint8_t blockNo = arg0;
	bool useKey = (arg1 == 1); //UL_C
	bool usePwd = (arg1 == 2); //UL_EV1/NTAG
	byte_t blockdata[4] = {0x00};

	memcpy(blockdata, datain,4);
	
	LEDsoff();
	LED_A_ON();
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	clear_trace();
	set_tracing(true);
	
	if(!iso14443a_select_card(NULL, NULL, NULL, true, 0)) {
		if (MF_DBGLEVEL >= 1) Dbprintf("Can't select card");
		OnError(0);
		return;
	};

	// UL-C authentication
	if ( useKey ) {
		uint8_t key[16] = {0x00};	
		memcpy(key, datain+4, sizeof(key) );

		if ( !mifare_ultra_auth(key) ) {
			OnError(1);
			return;			
		}
	}
	
	// UL-EV1 / NTAG authentication
	if (usePwd) { 
		uint8_t pwd[4] = {0x00};
		memcpy(pwd, datain+4, 4);
		uint8_t pack[4] = {0,0,0,0};
		if (!mifare_ul_ev1_auth(pwd, pack)) {
			OnError(1);
			return;			
		}
	}
	
	if(mifare_ultra_writeblock(blockNo, blockdata)) {
		if (MF_DBGLEVEL >= 1) Dbprintf("Write block error");
		OnError(0);
		return;
	};

	if(mifare_ultra_halt()) {
		if (MF_DBGLEVEL >= 1) Dbprintf("Halt error");
		OnError(0);
		return;
	};

	if (MF_DBGLEVEL >= 2) DbpString("WRITE BLOCK FINISHED");

	cmd_send(CMD_ACK,1,0,0,0,0);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
}

void MifareUSetPwd(uint8_t arg0, uint8_t *datain){
	
	uint8_t pwd[16] = {0x00};
	byte_t blockdata[4] = {0x00};
	
	memcpy(pwd, datain, 16);
	
	LED_A_ON(); LED_B_OFF(); LED_C_OFF();
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	clear_trace();
	set_tracing(true);
	
	if(!iso14443a_select_card(NULL, NULL, NULL, true, 0)) {
		if (MF_DBGLEVEL >= 1) Dbprintf("Can't select card");
		OnError(0);
		return;
	};

	blockdata[0] = pwd[7];
	blockdata[1] = pwd[6];
	blockdata[2] = pwd[5];
	blockdata[3] = pwd[4];
	if(mifare_ultra_writeblock( 44, blockdata)) {
		if (MF_DBGLEVEL >= 1) Dbprintf("Write block error");
		OnError(44);
		return;
	};

	blockdata[0] = pwd[3];
	blockdata[1] = pwd[2];
	blockdata[2] = pwd[1];
	blockdata[3] = pwd[0];
	if(mifare_ultra_writeblock( 45, blockdata)) {
		if (MF_DBGLEVEL >= 1) Dbprintf("Write block error");
		OnError(45);
		return;
	};

	blockdata[0] = pwd[15];
	blockdata[1] = pwd[14];
	blockdata[2] = pwd[13];
	blockdata[3] = pwd[12];
	if(mifare_ultra_writeblock( 46, blockdata)) {
		if (MF_DBGLEVEL >= 1) Dbprintf("Write block error");
		OnError(46);
		return;
	};

	blockdata[0] = pwd[11];
	blockdata[1] = pwd[10];
	blockdata[2] = pwd[9];
	blockdata[3] = pwd[8];
	if(mifare_ultra_writeblock( 47, blockdata)) {
		if (MF_DBGLEVEL >= 1) Dbprintf("Write block error");
		OnError(47);
		return;
	};	

	if(mifare_ultra_halt()) {
		if (MF_DBGLEVEL >= 1) Dbprintf("Halt error");
		OnError(0);
		return;
	};

	cmd_send(CMD_ACK,1,0,0,0,0);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
}

// Return 1 if the nonce is invalid else return 0
int valid_nonce(uint32_t Nt, uint32_t NtEnc, uint32_t Ks1, uint8_t *parity) {
	return ((oddparity8((Nt >> 24) & 0xFF) == ((parity[0]) ^ oddparity8((NtEnc >> 24) & 0xFF) ^ BIT(Ks1,16))) & \
	(oddparity8((Nt >> 16) & 0xFF) == ((parity[1]) ^ oddparity8((NtEnc >> 16) & 0xFF) ^ BIT(Ks1,8))) & \
	(oddparity8((Nt >> 8) & 0xFF) == ((parity[2]) ^ oddparity8((NtEnc >> 8) & 0xFF) ^ BIT(Ks1,0)))) ? 1 : 0;
}


//-----------------------------------------------------------------------------
// acquire encrypted nonces in order to perform the attack described in
// Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
// Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on 
// Computer and Communications Security, 2015
//-----------------------------------------------------------------------------
#define AUTHENTICATION_TIMEOUT  848 //848			// card times out 1ms after wrong authentication (according to NXP documentation)
#define PRE_AUTHENTICATION_LEADTIME 400		// some (non standard) cards need a pause after select before they are ready for first authentication 

void MifareAcquireEncryptedNonces(uint32_t arg0, uint32_t arg1, uint32_t flags, uint8_t *datain)
{
	uint64_t ui64Key = 0;
	uint8_t uid[10] = {0x00};
	uint32_t cuid = 0;
	uint8_t cascade_levels = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;
	uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
	int16_t isOK = 0;
	uint8_t par_enc[1] = {0x00};
	uint8_t nt_par_enc = 0;
	uint8_t buf[USB_CMD_DATA_SIZE] = {0x00};
	uint32_t timeout = 0;
	
	uint8_t blockNo = arg0 & 0xff;
	uint8_t keyType = (arg0 >> 8) & 0xff;
	uint8_t targetBlockNo = arg1 & 0xff;
	uint8_t targetKeyType = (arg1 >> 8) & 0xff;
	ui64Key = bytes_to_num(datain, 6);
	bool initialize = flags & 0x0001;
	bool slow = flags & 0x0002;
	bool field_off = flags & 0x0004;
	
	LED_A_ON();
	LED_C_OFF();

	if (initialize) {
		iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
		clear_trace();
		set_tracing(true);
	}
	
	LED_C_ON();
	
	uint16_t num_nonces = 0;
	bool have_uid = false;
	for (uint16_t i = 0; i <= USB_CMD_DATA_SIZE - 9; ) {

		// Test if the action was cancelled
		if(BUTTON_PRESS()) {
			isOK = 2;
			field_off = true;
			break;
		}

		if (!have_uid) { // need a full select cycle to get the uid first
			iso14a_card_select_t card_info;		
			if(!iso14443a_select_card(uid, &card_info, &cuid, true, 0)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("AcquireNonces: Can't select card (ALL)");
				continue;
			}
			switch (card_info.uidlen) {
				case 4 : cascade_levels = 1; break;
				case 7 : cascade_levels = 2; break;
				case 10: cascade_levels = 3; break;
				default: break;
			}
			have_uid = true;	
		} else { // no need for anticollision. We can directly select the card
			if(!iso14443a_select_card(uid, NULL, NULL, false, cascade_levels)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("AcquireNonces: Can't select card (UID)");
				continue;
			}
		}
		
		if (slow) {
			timeout = GetCountSspClk() + PRE_AUTHENTICATION_LEADTIME;
			while(GetCountSspClk() < timeout);
		}

		uint32_t nt1;
		if (mifare_classic_authex(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST, &nt1, NULL)) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("AcquireNonces: Auth1 error");
			continue;
		}

		// nested authentication
		uint16_t len = mifare_sendcmd_short(pcs, AUTH_NESTED, 0x60 + (targetKeyType & 0x01), targetBlockNo, receivedAnswer, par_enc, NULL);
		if (len != 4) {
			if (MF_DBGLEVEL >= 1)	Dbprintf("AcquireNonces: Auth2 error len=%d", len);
			continue;
		}
	
		// send a dummy byte as reader response in order to trigger the cards authentication timeout
		uint8_t dummy_answer = 0;
		ReaderTransmit(&dummy_answer, 1, NULL);
		timeout = GetCountSspClk() + AUTHENTICATION_TIMEOUT;
		
		num_nonces++;
		if (num_nonces % 2) {
			memcpy(buf+i, receivedAnswer, 4);
			nt_par_enc = par_enc[0] & 0xf0;
		} else {
			nt_par_enc |= par_enc[0] >> 4;
			memcpy(buf+i+4, receivedAnswer, 4);
			memcpy(buf+i+8, &nt_par_enc, 1);
			i += 9;
		}
		// wait for the card to become ready again
		while(GetCountSspClk() < timeout);	
	}

	LED_C_OFF();
	
	crypto1_destroy(pcs);
	
	LED_B_ON();
	cmd_send(CMD_ACK, isOK, cuid, num_nonces, buf, sizeof(buf));
	LED_B_OFF();

	if (MF_DBGLEVEL >= 3)	DbpString("AcquireEncryptedNonces finished");

	if (field_off) {
		FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
		LEDsoff();
		set_tracing(FALSE);
	}
}


//-----------------------------------------------------------------------------
// MIFARE nested authentication. 
// 
//-----------------------------------------------------------------------------
void MifareNested(uint32_t arg0, uint32_t arg1, uint32_t calibrate, uint8_t *datain)
{
	// params
	uint8_t blockNo = arg0 & 0xff;
	uint8_t keyType = (arg0 >> 8) & 0xff;
	uint8_t targetBlockNo = arg1 & 0xff;
	uint8_t targetKeyType = (arg1 >> 8) & 0xff;
	uint64_t ui64Key = 0;

	ui64Key = bytes_to_num(datain, 6);
	
	// variables
	uint16_t rtr, i, j, len;
	uint16_t davg = 0;
	static uint16_t dmin, dmax;
	uint8_t uid[10] = {0x00};
	uint32_t cuid = 0, nt1, nt2, nttmp, nttest, ks1;
	uint8_t par[1] = {0x00};
	uint32_t target_nt[2] = {0x00}, target_ks[2] = {0x00};
	
	uint8_t par_array[4] = {0x00};
	uint16_t ncount = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;
	uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};

	uint32_t auth1_time, auth2_time;
	static uint16_t delta_time = 0;

	LED_A_ON();
	LED_C_OFF();
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	// free eventually allocated BigBuf memory
	BigBuf_free(); BigBuf_Clear_ext(false);
	
	if (calibrate) clear_trace();
	set_tracing(true);

	// statistics on nonce distance
	int16_t isOK = 0;
	#define NESTED_MAX_TRIES 12
	uint16_t unsuccessfull_tries = 0;
	if (calibrate) {	// for first call only. Otherwise reuse previous calibration
		LED_B_ON();
		WDT_HIT();

		davg = dmax = 0;
		dmin = 2000;
		delta_time = 0;
		
		for (rtr = 0; rtr < 17; rtr++) {

			// Test if the action was cancelled
			if(BUTTON_PRESS()) {
				isOK = -2;
				break;
			}

			// prepare next select. No need to power down the card.
			if(mifare_classic_halt(pcs, cuid)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Nested: Halt error");
				rtr--;
				continue;
			}

			if(!iso14443a_select_card(uid, NULL, &cuid, true, 0)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Nested: Can't select card");
				rtr--;
				continue;
			};

			auth1_time = 0;
			if(mifare_classic_authex(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST, &nt1, &auth1_time)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Nested: Auth1 error");
				rtr--;
				continue;
			};
			auth2_time = (delta_time) ? auth1_time + delta_time : 0;

			if(mifare_classic_authex(pcs, cuid, blockNo, keyType, ui64Key, AUTH_NESTED, &nt2, &auth2_time)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Nested: Auth2 error");
				rtr--;
				continue;
			};

			nttmp = prng_successor(nt1, 100);				//NXP Mifare is typical around 840,but for some unlicensed/compatible mifare card this can be 160
			for (i = 101; i < 1200; i++) {
				nttmp = prng_successor(nttmp, 1);
				if (nttmp == nt2) break;
			}

			if (i != 1200) {
				if (rtr != 0) {
					davg += i;
					dmin = MIN(dmin, i);
					dmax = MAX(dmax, i);
				}
				else {
					delta_time = auth2_time - auth1_time + 32;  // allow some slack for proper timing
				}
				if (MF_DBGLEVEL >= 3) Dbprintf("Nested: calibrating... ntdist=%d", i);
			} else {
				unsuccessfull_tries++;
				if (unsuccessfull_tries > NESTED_MAX_TRIES) {	// card isn't vulnerable to nested attack (random numbers are not predictable)
					isOK = -3;
				}
			}
		}

		davg = (davg + (rtr - 1)/2) / (rtr - 1);
		
		if (MF_DBGLEVEL >= 3) Dbprintf("rtr=%d isOK=%d min=%d max=%d avg=%d, delta_time=%d", rtr, isOK, dmin, dmax, davg, delta_time);

		dmin = davg - 2;
		dmax = davg + 2;
		
		LED_B_OFF();
	}
//  -------------------------------------------------------------------------------------------------	
	
	LED_C_ON();

	//  get crypted nonces for target sector
	for(i=0; i < 2 && !isOK; i++) { // look for exactly two different nonces

		target_nt[i] = 0;
		while(target_nt[i] == 0) { // continue until we have an unambiguous nonce
		
			// prepare next select. No need to power down the card.
			if(mifare_classic_halt(pcs, cuid)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Nested: Halt error");
				continue;
			}

			if(!iso14443a_select_card(uid, NULL, &cuid, true, 0)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Nested: Can't select card");
				continue;
			};
		
			auth1_time = 0;
			if(mifare_classic_authex(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST, &nt1, &auth1_time)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Nested: Auth1 error");
				continue;
			};

			// nested authentication
			auth2_time = auth1_time + delta_time;

			len = mifare_sendcmd_short(pcs, AUTH_NESTED, 0x60 + (targetKeyType & 0x01), targetBlockNo, receivedAnswer, par, &auth2_time);
			if (len != 4) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("Nested: Auth2 error len=%d", len);
				continue;
			};
		
			nt2 = bytes_to_num(receivedAnswer, 4);		
			if (MF_DBGLEVEL >= 3) Dbprintf("Nonce#%d: Testing nt1=%08x nt2enc=%08x nt2par=%02x", i+1, nt1, nt2, par[0]);
			
			// Parity validity check
//			for (j = 0; j < 4; j++) {
//				par_array[j] = (oddparity8(receivedAnswer[j]) != ((par[0] >> (7-j)) & 0x01));
//			}
			par_array[0] = (oddparity8(receivedAnswer[0]) != ((par[0] >> (7-0)) & 0x01));
			par_array[1] = (oddparity8(receivedAnswer[1]) != ((par[0] >> (7-1)) & 0x01));
			par_array[2] = (oddparity8(receivedAnswer[2]) != ((par[0] >> (7-2)) & 0x01));
			par_array[3] = (oddparity8(receivedAnswer[3]) != ((par[0] >> (7-3)) & 0x01));
			
			ncount = 0;
			nttest = prng_successor(nt1, dmin - 1);
			for (j = dmin; j < dmax + 1; j++) {
				nttest = prng_successor(nttest, 1);
				ks1 = nt2 ^ nttest;

				if (valid_nonce(nttest, nt2, ks1, par_array)){
					if (ncount > 0) { 		// we are only interested in disambiguous nonces, try again
						if (MF_DBGLEVEL >= 3) Dbprintf("Nonce#%d: dismissed (ambigous), ntdist=%d", i+1, j);
						target_nt[i] = 0;
						break;
					}
					target_nt[i] = nttest;
					target_ks[i] = ks1;
					ncount++;
					if (i == 1 && target_nt[1] == target_nt[0]) { // we need two different nonces
						target_nt[i] = 0;
						if (MF_DBGLEVEL >= 3) Dbprintf("Nonce#2: dismissed (= nonce#1), ntdist=%d", j);
						break;
					}
					if (MF_DBGLEVEL >= 3) Dbprintf("Nonce#%d: valid, ntdist=%d", i+1, j);
				}
			}
			if (target_nt[i] == 0 && j == dmax+1 && MF_DBGLEVEL >= 3) Dbprintf("Nonce#%d: dismissed (all invalid)", i+1);
		}
	}

	LED_C_OFF();
	
	crypto1_destroy(pcs);
	
	byte_t buf[4 + 4 * 4] = {0};
	memcpy(buf, &cuid, 4);
	memcpy(buf+4, &target_nt[0], 4);
	memcpy(buf+8, &target_ks[0], 4);
	memcpy(buf+12, &target_nt[1], 4);
	memcpy(buf+16, &target_ks[1], 4);
	
	LED_B_ON();
	cmd_send(CMD_ACK, isOK, 0, targetBlockNo + (targetKeyType * 0x100), buf, sizeof(buf));
	LED_B_OFF();

	if (MF_DBGLEVEL >= 3)	DbpString("NESTED FINISHED");

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
}

//-----------------------------------------------------------------------------
// MIFARE check keys. key count up to 85. 
// 
//-----------------------------------------------------------------------------
void MifareChkKeys(uint16_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain) {
	uint8_t blockNo = arg0 & 0xff;
	uint8_t keyType = (arg0 >> 8) & 0xff;
	bool clearTrace = arg1;
	uint8_t keyCount = arg2;
	uint64_t ui64Key = 0;
	
	bool have_uid = FALSE;
	uint8_t cascade_levels = 0;
	uint32_t timeout = 0;
	
	int i;
	byte_t isOK = 0;
	uint8_t uid[10] = {0x00};
	uint32_t cuid = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;
	
	// save old debuglevel, and tempory turn off dbg printing. speedissues.
	int OLD_MF_DBGLEVEL = MF_DBGLEVEL;	
	MF_DBGLEVEL = MF_DBG_NONE;
	
	LEDsoff();
	LED_A_ON();
	
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	if (clearTrace) 
		clear_trace();
	
	set_tracing(TRUE);
	
	for (i = 0; i < keyCount; ++i) {

		//mifare_classic_halt(pcs, cuid);

		// this part is from Piwi's faster nonce collecting part in Hardnested.
		if (!have_uid) { // need a full select cycle to get the uid first
			iso14a_card_select_t card_info;		
			if(!iso14443a_select_card(uid, &card_info, &cuid, true, 0)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("ChkKeys: Can't select card (ALL)");
				break;
			}
			switch (card_info.uidlen) {
				case 4 : cascade_levels = 1; break;
				case 7 : cascade_levels = 2; break;
				case 10: cascade_levels = 3; break;
				default: break;
			}
			have_uid = TRUE;	
		} else { // no need for anticollision. We can directly select the card
			if(!iso14443a_select_card(uid, NULL, NULL, false, cascade_levels)) {
				if (MF_DBGLEVEL >= 1)	Dbprintf("ChkKeys: Can't select card (UID)");
				continue;
			}
		}
	
		ui64Key = bytes_to_num(datain + i * 6, 6);
		
		if (mifare_classic_auth(pcs, cuid, blockNo, keyType, ui64Key, AUTH_FIRST)) {

			uint8_t dummy_answer = 0;
			ReaderTransmit(&dummy_answer, 1, NULL);
			timeout = GetCountSspClk() + AUTHENTICATION_TIMEOUT;
			
			// wait for the card to become ready again
			while(GetCountSspClk() < timeout);
			
			continue;
		}
		isOK = 1;
		break;
	}
	
	LED_B_ON();
    cmd_send(CMD_ACK, isOK, 0, 0, datain + i * 6, 6);

	// restore debug level
	MF_DBGLEVEL = OLD_MF_DBGLEVEL;	
	
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
	crypto1_destroy(pcs);
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
// Note: we call FpgaDownloadAndGo(FPGA_BITSTREAM_HF) here although FPGA is not
// involved in dealing with emulator memory. But if it is called later, it might
// destroy the Emulator Memory.
//-----------------------------------------------------------------------------

void MifareEMemClr(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain){
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	emlClearMem();
}

void MifareEMemSet(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain){
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	if (arg2==0) arg2 = 16; // backwards compat... default bytewidth
	emlSetMem_xt(datain, arg0, arg1, arg2); // data, block num, blocks count, block byte width
}

void MifareEMemGet(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain){
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
	byte_t buf[USB_CMD_DATA_SIZE] = {0x00};
	emlGetMem(buf, arg0, arg1); // data, block num, blocks count (max 4)

	LED_B_ON();
	cmd_send(CMD_ACK,arg0,arg1,0,buf,USB_CMD_DATA_SIZE);
	LED_B_OFF();
}

//-----------------------------------------------------------------------------
// Load a card into the emulator memory
// 
//-----------------------------------------------------------------------------
void MifareECardLoad(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain){
	uint8_t numSectors = arg0;
	uint8_t keyType = arg1;
	uint64_t ui64Key = 0;
	uint32_t cuid = 0;
	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;

	// variables
	byte_t dataoutbuf[16] = {0x00};
	byte_t dataoutbuf2[16] = {0x00};
	uint8_t uid[10] = {0x00};

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
	
	clear_trace();
	set_tracing(TRUE);
	
	bool isOK = true;

	if(!iso14443a_select_card(uid, NULL, &cuid, true, 0)) {
		isOK = false;
		if (MF_DBGLEVEL >= 1)	Dbprintf("Can't select card");
	}
		
	for (uint8_t sectorNo = 0; isOK && sectorNo < numSectors; sectorNo++) {
		ui64Key = emlGetKey(sectorNo, keyType);
		if (sectorNo == 0){
			if(isOK && mifare_classic_auth(pcs, cuid, FirstBlockOfSector(sectorNo), keyType, ui64Key, AUTH_FIRST)) {
				isOK = false;
				if (MF_DBGLEVEL >= 1)	Dbprintf("Sector[%2d]. Auth error", sectorNo);
				break;
			}
		} else {
			if(isOK && mifare_classic_auth(pcs, cuid, FirstBlockOfSector(sectorNo), keyType, ui64Key, AUTH_NESTED)) {
				isOK = false;
				if (MF_DBGLEVEL >= 1)	Dbprintf("Sector[%2d]. Auth nested error", sectorNo);
				break;
			}
		}
		
		for (uint8_t blockNo = 0; isOK && blockNo < NumBlocksPerSector(sectorNo); blockNo++) {
			if(isOK && mifare_classic_readblock(pcs, cuid, FirstBlockOfSector(sectorNo) + blockNo, dataoutbuf)) {
				isOK = false;
				if (MF_DBGLEVEL >= 1)	Dbprintf("Error reading sector %2d block %2d", sectorNo, blockNo);
				break;
			}
			if (isOK) {
				if (blockNo < NumBlocksPerSector(sectorNo) - 1) {
					emlSetMem(dataoutbuf, FirstBlockOfSector(sectorNo) + blockNo, 1);
				} else {	// sector trailer, keep the keys, set only the AC
					emlGetMem(dataoutbuf2, FirstBlockOfSector(sectorNo) + blockNo, 1);
					memcpy(&dataoutbuf2[6], &dataoutbuf[6], 4);
					emlSetMem(dataoutbuf2,  FirstBlockOfSector(sectorNo) + blockNo, 1);
				}
			}
		}

	}

	if(mifare_classic_halt(pcs, cuid))
		if (MF_DBGLEVEL >= 1)
			Dbprintf("Halt error");

	//  ----------------------------- crypto1 destroy
	crypto1_destroy(pcs);

	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	
	if (MF_DBGLEVEL >= 2) DbpString("EMUL FILL SECTORS FINISHED");

	set_tracing(FALSE);
}


//-----------------------------------------------------------------------------
// Work with "magic Chinese" card (email him: ouyangweidaxian@live.cn)
// 
// PARAMS - workFlags
// bit 0 - need get UID
// bit 1 - need wupC
// bit 2 - need HALT after sequence
// bit 3 - need turn on FPGA before sequence
// bit 4 - need turn off FPGA
// bit 5 - need to set datain instead of issuing USB reply (called via ARM for StandAloneMode14a)
// bit 6 - wipe tag.
//-----------------------------------------------------------------------------
// magic uid card generation 1 commands
uint8_t wupC1[] = { MIFARE_MAGICWUPC1 }; 
uint8_t wupC2[] = { MIFARE_MAGICWUPC2 }; 
uint8_t wipeC[] = { MIFARE_MAGICWIPEC }; 
	
void MifareCSetBlock(uint32_t arg0, uint32_t arg1, uint8_t *datain){
  
	// params
	uint8_t workFlags = arg0;
	uint8_t blockNo = arg1;
	
	// variables
	bool isOK = false; //assume we will get an error
	uint8_t errormsg = 0x00;
	uint8_t uid[10] = {0x00};
	uint8_t data[18] = {0x00};
	uint32_t cuid = 0;
	
	uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
	uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};

	if (workFlags & MAGIC_INIT) {
		LED_A_ON();
		LED_B_OFF();
		iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
		clear_trace();
		set_tracing(TRUE);
	}

	//loop doesn't loop just breaks out if error
	while (true) {
		// read UID and return to client with write
		if (workFlags & MAGIC_UID) {
			if(!iso14443a_select_card(uid, NULL, &cuid, true, 0)) {
				if (MF_DBGLEVEL >= MF_DBG_ERROR)	Dbprintf("Can't select card");
				errormsg = MAGIC_UID;
				// break;
			}
			
			if ( mifare_classic_halt_ex(NULL) ) break;
		}
	
		// wipe tag, fill it with zeros
		if (workFlags & MAGIC_WIPE){
			ReaderTransmitBitsPar(wupC1, 7, NULL, NULL);
			if(!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
				if (MF_DBGLEVEL >= MF_DBG_ERROR)	Dbprintf("wupC1 error");
				errormsg = MAGIC_WIPE;
				break;
			}

			ReaderTransmit(wipeC, sizeof(wipeC), NULL);
			if(!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
				if (MF_DBGLEVEL >= MF_DBG_ERROR)	Dbprintf("wipeC error");
				errormsg = MAGIC_WIPE;
				break;
			}

			if ( mifare_classic_halt_ex(NULL) ) break;
		}	

		// write block
		if (workFlags & MAGIC_WUPC) {
			ReaderTransmitBitsPar(wupC1, 7, NULL, NULL);
			if(!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
				if (MF_DBGLEVEL >= MF_DBG_ERROR)	Dbprintf("wupC1 error");
				errormsg = MAGIC_WUPC;
				break;
			}

			ReaderTransmit(wupC2, sizeof(wupC2), NULL);
			if(!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
				if (MF_DBGLEVEL >= MF_DBG_ERROR)	Dbprintf("wupC2 error");
				errormsg = MAGIC_WUPC;
				break;
			}
		}

		if ((mifare_sendcmd_short(NULL, 0, ISO14443A_CMD_WRITEBLOCK, blockNo, receivedAnswer, receivedAnswerPar, NULL) != 1) || (receivedAnswer[0] != 0x0a)) {
			if (MF_DBGLEVEL >= MF_DBG_ERROR)	Dbprintf("write block send command error");
			errormsg = 4;
			break;
		}
	
		memcpy(data, datain, 16);
		AppendCrc14443a(data, 16);
	
		ReaderTransmit(data, sizeof(data), NULL);
		if ((ReaderReceive(receivedAnswer, receivedAnswerPar) != 1) || (receivedAnswer[0] != 0x0a)) {
			if (MF_DBGLEVEL >= MF_DBG_ERROR)	Dbprintf("write block send data error");
			errormsg = 0;
			break;
		}	
	
		if (workFlags & MAGIC_OFF) 
			if ( mifare_classic_halt_ex(NULL) ) break;
		
		isOK = true;
		break;

	} // end while	

	if (isOK )
		cmd_send(CMD_ACK,1,0,0,uid,sizeof(uid));
	else
		OnErrorMagic(errormsg);

	if (workFlags & MAGIC_OFF)
		OnSuccessMagic();
}

void MifareCGetBlock(uint32_t arg0, uint32_t arg1, uint8_t *datain){
    
	uint8_t workFlags = arg0;
	uint8_t blockNo = arg1;
	uint8_t errormsg = 0x00;
	bool isOK = false; //assume we will get an error
	
	// variables
	uint8_t data[MAX_MIFARE_FRAME_SIZE];
	uint8_t receivedAnswer[MAX_MIFARE_FRAME_SIZE] = {0x00};
	uint8_t receivedAnswerPar[MAX_MIFARE_PARITY_SIZE] = {0x00};
	
	memset(data, 0x00, sizeof(data));
	
	if (workFlags & MAGIC_INIT) {
		LED_A_ON();
		LED_B_OFF();
		iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);	
		clear_trace();
		set_tracing(TRUE);
	}

	//loop doesn't loop just breaks out if error or done
	while (true) {
		if (workFlags & MAGIC_WUPC) {
			ReaderTransmitBitsPar(wupC1, 7, NULL, NULL);
			if(!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
				if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("wupC1 error");
				errormsg = MAGIC_WUPC;
				break;
			}

			ReaderTransmit(wupC2, sizeof(wupC2), NULL);
			if(!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
				if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("wupC2 error");
				errormsg = MAGIC_WUPC;
				break;
			}
		}

		// read block		
		if ((mifare_sendcmd_short(NULL, 0, ISO14443A_CMD_READBLOCK, blockNo, receivedAnswer, receivedAnswerPar, NULL) != 18)) {
			if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("read block send command error");
			errormsg = 0;
			break;
		}
		
		memcpy(data, receivedAnswer, sizeof(data));
		
		// send HALT
		if (workFlags & MAGIC_HALT)
			mifare_classic_halt_ex(NULL);

		isOK = true;
		break;
	}
	// if MAGIC_DATAIN, the data stays on device side.
	if (workFlags & MAGIC_DATAIN) {
		if (isOK)
			memcpy(datain, data, sizeof(data));
	} else {
		if (isOK) 
			cmd_send(CMD_ACK,1,0,0,data,sizeof(data));	
		else 
			OnErrorMagic(errormsg);	
	}
	
	if (workFlags & MAGIC_OFF)
		OnSuccessMagic();
}

void MifareCIdent(){
	
	// variables
	bool isOK = true;	
	uint8_t receivedAnswer[1] = {0x00};
	uint8_t receivedAnswerPar[1] = {0x00};

	ReaderTransmitBitsPar(wupC1, 7, NULL, NULL);
	if(!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
		isOK = false;
	}

	ReaderTransmit(wupC2, sizeof(wupC2), NULL);
	if(!ReaderReceive(receivedAnswer, receivedAnswerPar) || (receivedAnswer[0] != 0x0a)) {
		isOK = false;
	}

	// removed the if,  since some magic tags misbehavies and send an answer to it.
	mifare_classic_halt(NULL, 0);
	cmd_send(CMD_ACK,isOK,0,0,0,0);
}

void OnSuccessMagic(){
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);	
}
void OnErrorMagic(uint8_t reason){
	//          ACK, ISOK, reason,0,0,0
	cmd_send(CMD_ACK,0,reason,0,0,0);
	OnSuccessMagic();
}
//
// DESFIRE
//
void Mifare_DES_Auth1(uint8_t arg0, uint8_t *datain){
	byte_t dataout[12] = {0x00};
	uint8_t uid[10] = {0x00};
	uint32_t cuid = 0;
    
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
	clear_trace();
	set_tracing(true);

	int len = iso14443a_select_card(uid, NULL, &cuid, true, 0);
	if(!len) {
		if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Can't select card");
		OnError(1);
		return;
	};

	if(mifare_desfire_des_auth1(cuid, dataout)){
		if (MF_DBGLEVEL >= MF_DBG_ERROR) Dbprintf("Authentication part1: Fail.");
		OnError(4);
		return;
	}

	if (MF_DBGLEVEL >= MF_DBG_EXTENDED) DbpString("AUTH 1 FINISHED");
    cmd_send(CMD_ACK, 1, cuid, 0, dataout, sizeof(dataout));
}

void Mifare_DES_Auth2(uint32_t arg0, uint8_t *datain){
	uint32_t cuid = arg0;
	uint8_t key[16] = {0x00};
	byte_t dataout[12] = {0x00};
	byte_t isOK = 0;
    
	memcpy(key, datain, 16);
	
	isOK = mifare_desfire_des_auth2(cuid, key, dataout);
	
	if( isOK) {
	    if (MF_DBGLEVEL >= MF_DBG_EXTENDED) Dbprintf("Authentication part2: Failed");  
		OnError(4);
		return;
	}

	if (MF_DBGLEVEL >= MF_DBG_EXTENDED) DbpString("AUTH 2 FINISHED");

	cmd_send(CMD_ACK, isOK, 0, 0, dataout, sizeof(dataout));
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
	set_tracing(FALSE);
}