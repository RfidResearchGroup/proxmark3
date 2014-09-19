#include "mifaredesfire.h"

#define MAX_APPLICATION_COUNT 28
#define MAX_FILE_COUNT 16
#define MAX_FRAME_SIZE 60
#define NOT_YET_AUTHENTICATED 255
#define FRAME_PAYLOAD_SIZE (MAX_FRAME_SIZE - 5)

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
 FOO		= 	0x04,
 BAR		= 	0x08,
} CmdOptions ;

void MifareSendCommand(uint8_t arg0, uint8_t arg1, uint8_t *datain){
	
	/* ARG0 contains flags.
		0x01 = init card.
		0x02 = No Disconnect
		0x03
	*/
	uint8_t flags = arg0;
	size_t datalen = arg1;
	uint8_t resp[RECV_RES_SIZE];
	memset(resp,0,sizeof(resp));
	
	if (MF_DBGLEVEL >= 4) {
		Dbprintf(" flags : %02X", flags);
		Dbprintf(" len   : %02X", datalen);
		print_result(" RX    : ", datain, datalen);
	}
	
	if ( flags & INIT ){
		if ( !InitDesfireCard() )
			return;
	}
	
	int len = DesfireAPDU(datain, datalen, resp);
	print_result(" <--: ", resp, len);	
	if ( !len ) {
		if (MF_DBGLEVEL >= 4) {
			print_result("ERR <--: ", resp, len);	
		}
		OnError();
		return;
	}
	
	// reset the pcb_blocknum,
	pcb_blocknum = 0;
	
	if ( flags & DISCONNECT )
		OnSuccess();
	
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

	uint8_t null_key_data[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	//uint8_t new_key_data[8]  = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };
	int res = 0;
	
	desfirekey_t default_key = Desfire_des_key_new_with_version (null_key_data);

	// res = Desfire_select_application (tags[i], aid);
	if (res < 0) {
		print_result("default key: ", default_key->data, 24 );
		return;
	}
				
	return;
	//                pcb  cid  cmd               key   crc1  cr2   	
	//uint8_t cmd2[] = {0x02,0x00,GET_KEY_VERSION, 0x00, 0x00, 0x00 };

	//uint8_t* bigbuffer = mifare_get_bigbufptr();
	byte_t isOK = 1;
	uint8_t resp[256];
	uint8_t key[24];
	uint8_t IV[16];
	
	// första byten håller keylength.
	uint8_t keylen = datain[0];
	memcpy(key, datain+1, keylen);
	
	if (MF_DBGLEVEL >= 1) {
		
		Dbprintf("MODE: %d", mode);
		Dbprintf("ALGO: %d", algo);
		Dbprintf("KEYNO: %d", keyno);
		Dbprintf("KEYLEN: %d", keylen);
		
		print_result("KEY", key, keylen);
	}
	
	// card select - information
	byte_t buf[USB_CMD_DATA_SIZE];
	iso14a_card_select_t *card = (iso14a_card_select_t*)buf;
	
	// test of DES on ARM side.
	/* 
	if ( mode == 1){
		uint8_t IV[8];
		uint8_t plain[16];
		uint8_t encData[16];

		uint8_t tmpData[8];
		uint8_t tmpPlain[8];
		
		memset(IV, 0, 8);
		memset(tmpData, 0 ,8);
		memset(tmpPlain,0 ,8);
		memcpy(key, datain, 8);
		memcpy(plain, datain+30, 16);
		
		for(uint8_t i=0; i< sizeof(plain); i=i+8 ){
		
			memcpy(tmpPlain, plain+i, 8);
			des_enc( &tmpData, &tmpPlain, &key);
			memcpy(encData+i, tmpData, 8);
		}
	}
*/

	iso14a_clear_trace();

	iso14a_set_tracing(TRUE);

	// power up the field
	iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);

	// select the card
	isOK = iso14443a_select_card(resp, card, NULL);
	if (isOK != 1) {
		if (MF_DBGLEVEL >= 1) {
			Dbprintf("CAN'T SELECT CARD, SOMETHING WENT WRONG BEFORE AUTH");
		}
		OnError();
		return;
	}

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
			AesCtx ctx;
			if ( AesCtxIni(&ctx, IV, key, KEY128, CBC) < 0 ){
				if (MF_DBGLEVEL >= 1) {
					Dbprintf("AES context failed to init");
				}
				OnError();
				return;
			}
			uint8_t real_cmd[6];
			real_cmd[0] = 0x90;
			real_cmd[1] = 0x02;
			real_cmd[2] = AUTHENTICATE_AES;
			real_cmd[3] = keyno;
			
			AppendCrc14443a(real_cmd, 4);
			ReaderTransmit(real_cmd, sizeof(real_cmd), NULL);
	
			int len = ReaderReceive(resp);
			if(!len) {
				OnError();
				return;
			}

			print_result("RX:", resp, len);
   
			enum DESFIRE_STATUS status = resp[1];
			if ( status != ADDITIONAL_FRAME) {
				OnError();
				return;
			}
			
			// tags enc nonce
			uint8_t encRndB[16];
			uint8_t decRndB[16];
			uint8_t nonce[16];
			uint8_t both[32];
			uint8_t encBoth[32];

			memset(nonce, 0, 16);
			memcpy( encRndB, resp+2, 16);

			// dekryptera tagnonce.
			AesDecrypt(&ctx, encRndB, decRndB, 16);
			
			rol(decRndB,16);
			
			memcpy(both, nonce,16);
			memcpy(both+16, decRndB ,16 );

			AesEncrypt(&ctx, both, encBoth, 32 );

			uint8_t real_cmd_A[36];
			real_cmd_A[0] = 0x03;
			real_cmd_A[1] = ADDITIONAL_FRAME;
			
			memcpy(real_cmd_A+2, encBoth, sizeof(encBoth) );
			AppendCrc14443a(real_cmd_A, 34);
			ReaderTransmit(real_cmd_A, sizeof(real_cmd_A), NULL);
		
			len = ReaderReceive(resp);

			print_result("Auth1a ", resp, 36);
			
			status = resp[1];
			if ( status != OPERATION_OK)	{
				Dbprintf("Cmd Error: %02x  Len: %d", status,len);
				OnError();
				return;
			}
				
				break;
			}
			
	}
	
	OnSuccess(resp);
}

// 3 olika ISO sätt att skicka data till DESFIRE (direkt, inkapslat, inkapslat ISO)
// cmd  =  cmd bytes to send
// cmd_len = length of cmd
// dataout = pointer to response data array
int DesfireAPDU(uint8_t *cmd, size_t cmd_len, uint8_t *dataout){

	uint32_t status = 0;
	size_t wrappedLen = 0;
	uint8_t wCmd[USB_CMD_DATA_SIZE];
	
	wrappedLen = CreateAPDU( cmd, cmd_len, wCmd);
	
	if (MF_DBGLEVEL >= 4) {
		print_result("WCMD <--: ", wCmd, wrappedLen);	
	}
	ReaderTransmit( wCmd, wrappedLen, NULL);

	status = ReaderReceive(dataout);
	
	if(!status){
		return FALSE; //DATA LINK ERROR
	}
	// if we received an I- or R(ACK)-Block with a block number equal to the
	// current block number, toggle the current block number
	else if (status >= 4 // PCB+CID+CRC = 4 bytes
	         && ((dataout[0] & 0xC0) == 0 // I-Block
	             || (dataout[0] & 0xD0) == 0x80) // R-Block with ACK bit set to 0
	         && (dataout[0] & 0x01) == pcb_blocknum) // equal block numbers
	{
		pcb_blocknum ^= 1;  //toggle next block 
	}
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
			

	/* Version
	
	//uint8_t versionCmd1[] = {0x02, 0x60};
	//uint8_t versionCmd2[] = {0x03, 0xaf};
	//uint8_t versionCmd3[] = {0x02, 0xaf};

    // AUTH 1  -  CMD: 0x02, 0x0A, 0x00  = Auth
	// 0x02 = status byte för simpla svar?!? 
	// 0x0a = krypto typ
	// 0x00 = key nr
	//uint8_t initAuthCmdDES[]  = {0x02, 0x0a, 0x00};  // DES
	//uint8_t initAuthCmd3DES[] = {0x02, 0x1a, 0x00};  // 3DES
	//uint8_t initAuthCmdAES[]  = {0x02, 0xaa, 0x00};  // AES
	// auth 1 - answer command
	// 0x03 = status byte för komplexa typer?
	// 0xaf = additional frame
	// LEN = 1+1+32+2 = 36
	//uint8_t answerAuthCmd[34] = {0x03, 0xaf}; 

	// Lägg till CRC
	//AppendCrc14443a(versionCmd1,sizeof(versionCmd1));
*/

	// Sending commands
	/*ReaderTransmit(versionCmd1,sizeof(versionCmd1)+2, NULL);
	len = ReaderReceive(buffer);
	print_result("Get Version 3", buffer, 9);
	*/
	
	// for( int i = 0; i < 8; i++){
		// // Auth 1 - Request authentication
		// ReaderTransmit(initAuthCmdAES,sizeof(initAuthCmdAES)+2, NULL);
		// //len = ReaderReceive(buffer);

		// // 0xAE =  authentication error
		// if (buffer[1] == 0xae)	{
				// Dbprintf("Cmd Error: %02x", buffer[1]);
				// OnError();
				// return;
		// }

		// // tags enc nonce
		// memcpy(encRndB, buffer+2, 16);

		// // dekryptera svaret från tag.
		// AesDecrypt(&ctx, encRndB, decRndB, 16);

		// rol8(decRndB,16);
		// memcpy(RndARndB, RndA,16);
		// memcpy(RndARndB+16, decRndB ,16 );

		// AesEncrypt(&ctx, RndARndB, encRndARndB, 32 );

		// memcpy(answerAuthCmd+2, encRndARndB, 32);
 		// AppendCrc14443a(answerAuthCmd,sizeof(answerAuthCmd));
	
		// ReaderTransmit(answerAuthCmd,sizeof(answerAuthCmd)+2, NULL);

		// len = ReaderReceive(buffer);

		// print_result("Auth1a ", buffer, 8);
		// Dbprintf("Rx len: %02x", len);

		// if (buffer[1] == 0xCA)	{
				// Dbprintf("Cmd Error: %02x  Len: %d", buffer[1],len);
				// cmd_send(CMD_ACK,0,0,0,0,0);
				// key[1] = i;
				// AesCtxIni(&ctx, iv, key, KEY128, CBC);
		// }
	// }

	//des_dec(decRndB, encRndB, key);
	
    //Do crypto magic
	/*
    DES_ede2_cbc_encrypt(e_RndB,RndB,sizeof(e_RndB),&ks1,&ks2,&iv,0);
    memcpy(RndARndB,RndA,8);
    memcpy(RndARndB+8,RndB,8);
    PrintAndLog("     RA+B:%s",sprint_hex(RndARndB, 16));
    DES_ede2_cbc_encrypt(RndARndB,RndARndB,sizeof(RndARndB),&ks1,&ks2,&e_RndB,1);
    PrintAndLog("enc(RA+B):%s",sprint_hex(RndARndB, 16));
    */


int mifare_des_auth2(uint32_t uid, uint8_t *key, uint8_t *blockData){
	
	uint8_t* buffer = mifare_get_bigbufptr();
	uint8_t dcmd[19];
    
	dcmd[0] = 0xAF;
    memcpy(dcmd+1,key,16);
	AppendCrc14443a(dcmd, 17);
	

	ReaderTransmit(dcmd, sizeof(dcmd), NULL);
	int len = ReaderReceive(buffer);
	if(!len) {
          if (MF_DBGLEVEL >= 1)   Dbprintf("Authentication failed. Card timeout.");
          len = ReaderReceive(buffer);
    }
    
	if(len==1)	{
        if (MF_DBGLEVEL >= 1) {
			Dbprintf("NAK - Authentication failed.");
			Dbprintf("Cmd Error: %02x", buffer[0]);
		}
		return 1;
	}

	if (len == 11){
		if (MF_DBGLEVEL >= 1) {
			Dbprintf("Auth2 Resp: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
					  buffer[0],buffer[1],buffer[2],buffer[3],buffer[4],
					  buffer[5],buffer[6],buffer[7],buffer[8],buffer[9],
					  buffer[10]);
		}
		return 0;
	}
	return 1;
}

void MifareDES_Auth2(uint32_t arg0, uint8_t *datain){

	return;
	uint32_t cuid = arg0;
	uint8_t key[16];

	byte_t isOK = 0;
	byte_t dataoutbuf[16];
	
    memset(key, 0, 16);
	memcpy(key, datain, 16);
    
	LED_A_ON();
	LED_B_OFF();
	LED_C_OFF();

	if(mifare_des_auth2(cuid, key, dataoutbuf)){
	    if (MF_DBGLEVEL >= 1) Dbprintf("Authentication part2: Fail...");    
	}
	isOK=1;
	if (MF_DBGLEVEL >= 2)	DbpString("AUTH 2 FINISHED");
    
	LED_B_ON();
    cmd_send(CMD_ACK,isOK,0,0,dataoutbuf,11);
	LED_B_OFF();
    
    // Thats it...
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LEDsoff();
}

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
