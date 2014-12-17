#include "mifaredesfire.h"

#define MAX_APPLICATION_COUNT 28
#define MAX_FILE_COUNT 16
#define MAX_DESFIRE_FRAME_SIZE 60
#define NOT_YET_AUTHENTICATED 255
#define FRAME_PAYLOAD_SIZE (MAX_DESFIRE_FRAME_SIZE - 5)
#define RECEIVE_SIZE 64

// the block number for the ISO14443-4 PCB
uint8_t pcb_blocknum = 0;
// Deselect card by sending a s-block. the crc is precalced for speed
static  uint8_t deselect_cmd[] = {0xc2,0xe0,0xb4};

//static uint8_t __msg[MAX_FRAME_SIZE] = { 0x0A, 0x00, 0x00, /* ..., */ 0x00 };
/*                                       PCB   CID   CMD    PAYLOAD    */
//static uint8_t __res[MAX_FRAME_SIZE];

bool InitDesfireCard(){

	// Make sure it is off.
//	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
//	SpinDelay(300);
	
	byte_t cardbuf[USB_CMD_DATA_SIZE];
	memset(cardbuf,0,sizeof(cardbuf));
	
	iso14a_set_tracing(TRUE);
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
	
	iso14a_card_select_t *card = (iso14a_card_select_t*)cardbuf;
	int len = iso14443a_select_card(NULL,card,NULL);

	if (!len) {
		if (MF_DBGLEVEL >= 1) {
			Dbprintf("Can't select card");
		}
		OnError();
		return false;
	}
	return true;
}

// ARG0 flag enums
enum  {
 NONE		= 	0x00,
 INIT 		=	0x01,
 DISCONNECT =	0x02,
 CLEARTRACE	= 	0x04,
 BAR		= 	0x08,
} CmdOptions ;

void MifareSendCommand(uint8_t arg0, uint8_t arg1, uint8_t *datain){
	
	/* ARG0 contains flags.
		0x01 = init card.
		0x02 = Disconnect
		0x03
	*/
	uint8_t flags = arg0;
	size_t datalen = arg1;
	uint8_t resp[RECEIVE_SIZE];
	memset(resp,0,sizeof(resp));
	
	if (MF_DBGLEVEL >= 4) {
		Dbprintf(" flags : %02X", flags);
		Dbprintf(" len   : %02X", datalen);
		print_result(" RX    : ", datain, datalen);
	}
	
	if ( flags & CLEARTRACE ){
		iso14a_clear_trace();
	}
	
	if ( flags & INIT ){
		if ( !InitDesfireCard() )
			return;
	}
	
	int len = DesfireAPDU(datain, datalen, resp);
		if (MF_DBGLEVEL >= 4) {
			print_result("ERR <--: ", resp, len);	
		}

	if ( !len ) {
		OnError();
		return;
	}
	
	// reset the pcb_blocknum,
	pcb_blocknum = 0;
	
	if ( flags & DISCONNECT ){
		OnSuccess();
	}
	
	cmd_send(CMD_ACK,1,len,0,resp,len);
}

void MifareDesfireGetInformation(){
		
	int len = 0;
	uint8_t resp[USB_CMD_DATA_SIZE];
	uint8_t dataout[USB_CMD_DATA_SIZE];
	byte_t cardbuf[USB_CMD_DATA_SIZE];
	
	memset(resp,0,sizeof(resp));
	memset(dataout,0, sizeof(dataout));
	memset(cardbuf,0,sizeof(cardbuf));
	
	/*
		1 = PCB					1
		2 = cid					2
		3 = desfire command		3 
		4-5 = crc				4  key
								5-6 crc								
		PCB == 0x0A because sending CID byte.
		CID == 0x00 first card?		
	*/
	iso14a_clear_trace();
	iso14a_set_tracing(TRUE);
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	// card select - information
	iso14a_card_select_t *card = (iso14a_card_select_t*)cardbuf;
	byte_t isOK = iso14443a_select_card(NULL, card, NULL);
	if (isOK != 1) {
		if (MF_DBGLEVEL >= 1) {
			Dbprintf("Can't select card");
		}
		OnError();
		return;
	}

	memcpy(dataout,card->uid,7);

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();
	
	uint8_t cmd[] = {GET_VERSION};	
	size_t cmd_len = sizeof(cmd);
	
	len =  DesfireAPDU(cmd, cmd_len, resp);
	if ( !len ) {
		print_result("ERROR <--: ", resp, len);	
		OnError();
		return;
	}
	
	LED_A_OFF();
	LED_B_ON();
	memcpy(dataout+7,resp+3,7);
	
	// ADDITION_FRAME 1
	cmd[0] = ADDITIONAL_FRAME;
	len =  DesfireAPDU(cmd, cmd_len, resp);
	if ( !len ) {
		print_result("ERROR <--: ", resp, len);	
		OnError();
		return;
	}	
	
	LED_B_OFF();
	LED_C_ON();
	memcpy(dataout+7+7,resp+3,7);

	// ADDITION_FRAME 2
	len =  DesfireAPDU(cmd, cmd_len, resp);
	if ( !len ) {
		print_result("ERROR <--: ", resp, len);	
		OnError();
		return;
	}
	
	memcpy(dataout+7+7+7,resp+3,14);
	
	cmd_send(CMD_ACK,1,0,0,dataout,sizeof(dataout));
		
	// reset the pcb_blocknum,
	pcb_blocknum = 0;
	OnSuccess();
}

void MifareDES_Auth1(uint8_t mode, uint8_t algo, uint8_t keyno,  uint8_t *datain){

	int len = 0;
	//uint8_t PICC_MASTER_KEY8[8] = { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47};
	uint8_t PICC_MASTER_KEY16[16] = { 0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f };
	//uint8_t null_key_data8[8] = {0x00};
	//uint8_t null_key_data16[16] = {0x00};	
	//uint8_t new_key_data8[8]  = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77};
	//uint8_t new_key_data16[16]  = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

	//uint8_t* bigbuffer = get_bigbufptr_recvrespbuf();
	uint8_t resp[256] = {0x00};
	uint8_t IV[16] = {0x00};

	size_t datalen = datain[0];
	
	uint8_t cmd[40] = {0x00};
	uint8_t encRndB[16] = {0x00};
	uint8_t decRndB[16] = {0x00};
	uint8_t nonce[16] = {0x00};
	uint8_t both[32] = {0x00};
	uint8_t encBoth[32] = {0x00};

	InitDesfireCard();

	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();
	
	// 3 olika sätt att authenticera.   AUTH (CRC16) , AUTH_ISO (CRC32) , AUTH_AES (CRC32)
	// 4 olika crypto algo   DES, 3DES, 3K3DES, AES
	// 3 olika kommunikations sätt,   PLAIN,MAC,CRYPTO
	
	// des, nyckel 0, 
	switch (mode){
		case 1:
			// if ( SendDesfireCommand(AUTHENTICATE, &keyno, resp) > 0 ){
				// // fick nonce från kortet
			// }
			break;
		case 2:
			//SendDesfireCommand(AUTHENTICATE_ISO, &keyno, resp);
			break;
		case 3:{
		
			//defaultkey
			uint8_t keybytes[16];
			if (datain[1] == 0xff){
				memcpy(keybytes,PICC_MASTER_KEY16,16); 
			} else{
				memcpy(keybytes, datain+1, datalen);
			}
			
			struct desfire_key defaultkey = {0};
			desfirekey_t key = &defaultkey;
			Desfire_aes_key_new( keybytes, key);
		
			AesCtx ctx;
			if ( AesCtxIni(&ctx, IV, key->data, KEY128, CBC) < 0 ){
				if( MF_DBGLEVEL >= 4) {
					Dbprintf("AES context failed to init");
				}
				OnError();
				return;
			}
			
			cmd[0] = AUTHENTICATE_AES;
			cmd[1] = 0x00;  //keynumber
			len = DesfireAPDU(cmd, 2, resp);
			if ( !len ) {
				if (MF_DBGLEVEL >= 1) {
					DbpString("Authentication failed. Card timeout.");
				}
				OnError();
				return;
			}
			
			memcpy( encRndB, resp+3, 16);
		
			// dekryptera tagnonce.
			AesDecrypt(&ctx, encRndB, decRndB, 16);
			rol(decRndB,16);
			memcpy(both, nonce,16);
			memcpy(both+16, decRndB ,16 );
			AesEncrypt(&ctx, both, encBoth, 32 );
			
			cmd[0] = ADDITIONAL_FRAME;
			memcpy(cmd+1, encBoth, 32 );
			
			len = DesfireAPDU(cmd, 33, resp);  // 1 + 32 == 33
			if ( !len ) {
				if (MF_DBGLEVEL >= 1) {
					DbpString("Authentication failed. Card timeout.");
				}
                OnError();
				return;
			}
			
			if ( resp[2] == 0x00 ){
				// Create AES Session key		
				struct desfire_key sessionKey = {0};
				desfirekey_t skey = &sessionKey;
				Desfire_session_key_new( nonce, decRndB , key, skey );
				print_result("SESSION : ", skey->data, 16);
			} else {
				DbpString("Authetication failed.");
				OnError();
				return;
			}
			
			break;
		}	
	}
	
	OnSuccess();
	cmd_send(CMD_ACK,1,len,0,resp,len);
}

// 3 olika ISO sätt att skicka data till DESFIRE (direkt, inkapslat, inkapslat ISO)
// cmd  =  cmd bytes to send
// cmd_len = length of cmd
// dataout = pointer to response data array
int DesfireAPDU(uint8_t *cmd, size_t cmd_len, uint8_t *dataout){

	uint32_t status = 0;
	size_t wrappedLen = 0;
	uint8_t wCmd[USB_CMD_DATA_SIZE] = {0};
	
	uint8_t *resp = ((uint8_t *)BigBuf) + RECV_RESP_OFFSET;
    uint8_t *resp_par = ((uint8_t *)BigBuf) + RECV_RESP_PAR_OFFSET;
	
	wrappedLen = CreateAPDU( cmd, cmd_len, wCmd);
	
	if (MF_DBGLEVEL >= 4) {
		print_result("WCMD <--: ", wCmd, wrappedLen);	
	}
	ReaderTransmit( wCmd, wrappedLen, NULL);

	status = ReaderReceive(resp, resp_par);
	
	if( status == 0x00){
		if (MF_DBGLEVEL >= 4) {
			Dbprintf("fukked");
		}
		return FALSE; //DATA LINK ERROR
	}
	// if we received an I- or R(ACK)-Block with a block number equal to the
	// current block number, toggle the current block number
	else if (status >= 4 // PCB+CID+CRC = 4 bytes
	         && ((resp[0] & 0xC0) == 0 // I-Block
	             || (resp[0] & 0xD0) == 0x80) // R-Block with ACK bit set to 0
	         && (resp[0] & 0x01) == pcb_blocknum) // equal block numbers
	{
		pcb_blocknum ^= 1;  //toggle next block 
	}
	// copy response to
	dataout = resp;
	return status;
}	

// CreateAPDU
size_t CreateAPDU( uint8_t *datain, size_t len, uint8_t *dataout){
	
	size_t cmdlen = MIN(len+4, USB_CMD_DATA_SIZE-1);

	uint8_t cmd[cmdlen];
	memset(cmd, 0, cmdlen);
	
	cmd[0] = 0x0A;  //  0x0A = skicka cid,  0x02 = ingen cid. Särskilda bitar //
	cmd[0] |= pcb_blocknum; // OR the block number into the PCB	
	cmd[1] = 0x00;  //  CID: 0x00 //FIXME: allow multiple selected cards
	
	memcpy(cmd+2, datain, len);
	AppendCrc14443a(cmd, len+2);
	
	memcpy(dataout, cmd, cmdlen);
	
	return cmdlen;
}

	// crc_update(&desfire_crc32, 0, 1); /* CMD_WRITE */
	// crc_update(&desfire_crc32, addr, addr_sz);
	// crc_update(&desfire_crc32, byte, 8);
	// uint32_t crc = crc_finish(&desfire_crc32);

void OnSuccess(){
	pcb_blocknum = 0;
	ReaderTransmit(deselect_cmd, 3 , NULL);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
}

void OnError(){
	pcb_blocknum = 0;
	ReaderTransmit(deselect_cmd, 3 , NULL);
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	cmd_send(CMD_ACK,0,0,0,0,0);
	LEDsoff();
}
