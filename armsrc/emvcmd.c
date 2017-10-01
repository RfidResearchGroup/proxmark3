//Peter Fillmore - 2014
//
//--------------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//--------------------------------------------------------------------------------
//--------------------------------------------------------------------------------
//Routines to support EMV transactions
//--------------------------------------------------------------------------------
#include "emvcmd.h"

static emvcard currentcard; //use to hold emv tags for the reader/card during communications

void EMVTest(void)
{
    uint8_t rats[0x0b] = {0x0b,0x78,0x80,0x81,0x02,0x4b,0x4f,0x4e,0x41, 0x14, 0x11};
    EMVFuzz_RATS(0xb, rats);
    //grab card
    //EMVClone(1,1);
    /* 
    uint8_t tagvalbuffer[256];
    uint8_t tagvallen;  
    uint8_t template6F[] = {0x6F,0x00}; 
    uint8_t templateA5[] = {0xA5,0x00}; 
    uint8_t tag1[] = {0x50,0x00,0x00};
    uint8_t tag2[] = {0x87,0x00,0x00};
    uint8_t tag3[] = {0x9f,0x38,0x00};
    uint8_t tag4[] = {0x5F,0x2D,0x00};
    uint8_t tag5[] = {0x9F,0x11,0x00};
    uint8_t tag6[] = {0x9F,0x12,0x00};

    uint8_t tag7[] = {0x84, 0x00};
    uint8_t tag8[] = {0xA5, 0x00};
    emv_generatetemplate(templateA5,&currentcard,tagvalbuffer,&tagvallen, 6, tag1, tag2, tag3, tag4, tag5, tag6);
    memcpy(currentcard.tag_A5, tagvalbuffer+2, tagvallen-2);
    currentcard.tag_A5_len = tagvallen-2;
    emv_generatetemplate(template6F,&currentcard,currentcard.tag_6F ,&currentcard.tag_6F_len, 2, tag7, tag8);
    Dbprintf("TAG A5=");
    Dbhexdump(currentcard.tag_A5_len,currentcard.tag_A5 , false); 
    */
    //EMVSim(); 
}


//load individual tag into current card
void EMVloadvalue(uint32_t tag, uint8_t *datain){
    //Dbprintf("TAG=%i\n", tag);
    //Dbprintf("DATA=%s\n", datain);
    emv_settag(tag, datain, &currentcard);
}

void EMVReadRecord(uint8_t arg0, uint8_t arg1,emvcard *currentcard)
{
    uint8_t record = arg0;
    uint8_t sfi = arg1 & 0x0F; // convert arg1 to number
    uint8_t *resp  = BigBuf_malloc(256); 
    // variables
    tlvtag inputtag; // create the tag structure
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
		
    // perform read 
    // write the result to the provided card 
    while(true) {
    if(!emv_readrecord(record, sfi, resp)) {
        if(MF_DBGLEVEL >= 1) Dbprintf("readrecord failed");
    }
    if(*(resp+1) == 0x70){ 
        decode_ber_tlv_item(resp+1, &inputtag);
        emv_decode_field(inputtag.value, inputtag.valuelength, currentcard); 
    } 
    else
    {
        if(MF_DBGLEVEL >= 1) 
            Dbprintf("Record not found SFI=%i RECORD=%i", sfi, record); 
    }
	    LED_B_ON();
        LED_B_OFF();
		break;
	}	   
	LEDsoff();
}

void EMVSelectAID(uint8_t *AID, uint8_t AIDlen, emvcard* inputcard)
{    
    uint8_t* resp = BigBuf_malloc(256);     
    // variables
    tlvtag inputtag; // create the tag structure 
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
	
	while(true) {	
       
       if(!emv_select(AID, AIDlen, resp)){
          if(MF_DBGLEVEL == 1) DbpString("AID Select failed");
          break; 
       }
	   
       // write the result to the provided card 
       if(*(resp+1) == 0x6F){ 
          // decode the 6F template 
          decode_ber_tlv_item(resp+1, &inputtag);	  
		  
          // store 84 and A5 tags 
          emv_decode_field(inputtag.value, inputtag.valuelength, &currentcard); 
          
		  // decode the A5 tag 
          if(currentcard.tag_A5_len > 0) 
             emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
        
          // copy this result to the DFName 
          if(currentcard.tag_84_len == 0) 
             memcpy(currentcard.tag_DFName, currentcard.tag_84, currentcard.tag_84_len);
        
           // decode the BF0C result, assuming 1 directory entry for now 
           if(currentcard.tag_BF0C_len !=0){
              emv_decode_field(currentcard.tag_BF0C, currentcard.tag_BF0C_len, &currentcard);}
          
		    // retrieve the AID, use the AID to decide what transaction flow to use 
           if(currentcard.tag_61_len !=0)
              emv_decode_field(currentcard.tag_61, currentcard.tag_61_len, &currentcard);
		}
        LED_B_ON();
        LED_B_OFF();         
        break;		 
	}
	
    if(MF_DBGLEVEL >= 2) DbpString("SELECT AID COMPLETED");
	LEDsoff();
}
							   
void EMVSelectPPSE(void)
{
    while(true) { 
        if(!emv_selectPPSE()) {
            if(MF_DBGLEVEL >= 1) DbpString("PPSE failed");
            break;
        }
         
        LED_B_ON();
        LED_B_OFF();         
        break;
    }
    if(MF_DBGLEVEL >= 2) DbpString("SELECT PPSE COMPLETED");
    LEDsoff();
}

int EMVGetProcessingOptions(uint8_t *PDOL, uint8_t PDOLlen, emvcard* inputcard)
{
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
     
    // variables
    tlvtag inputtag; //create the tag structure
    // perform pdol 
    if(!emv_getprocessingoptions(PDOL, PDOLlen, receivedAnswer)){
        if(MF_DBGLEVEL >= 1) Dbprintf("get processing options failed");
        return 0; 
    }
    // write the result to the provided card 
    // FORMAT 1 received 
    if(receivedAnswer[1] == 0x80){ 
        // store AIP
        // decode tag 80 
        decode_ber_tlv_item(receivedAnswer+1, &inputtag);
        memcpy(currentcard.tag_82, &inputtag.value, sizeof(currentcard.tag_82));
        memcpy(currentcard.tag_94, &inputtag.value[2], inputtag.valuelength - sizeof(currentcard.tag_82));
        currentcard.tag_94_len = inputtag.valuelength - sizeof(currentcard.tag_82); 
    }
    else if(receivedAnswer[1] == 0x77){
        // decode the 77 template 
        decode_ber_tlv_item(receivedAnswer+1, &inputtag);
        // store 82 and 94 tags (AIP, AFL) 
        emv_decode_field(inputtag.value, inputtag.valuelength, &currentcard); 
    } 
    if(MF_DBGLEVEL >= 2) 
        DbpString("GET PROCESSING OPTIONS COMPLETE");
    return 1;
}

int EMVGetChallenge(emvcard* inputcard)
{
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
    // variables
    // tlvtag inputtag; //create the tag structure
    // perform select 
    if(!emv_getchallenge(receivedAnswer)){
        if(MF_DBGLEVEL >= 1) Dbprintf("get processing options failed");
        return 1; 
    }
    return 0;
}

int EMVGenerateAC(uint8_t refcontrol, emvcard* inputcard)
{
    uint8_t receivedAnswer[MAX_FRAME_SIZE];
    uint8_t cdolcommand[MAX_FRAME_SIZE];
    uint8_t cdolcommandlen = 0;
    tlvtag temptag;
 
    if(currentcard.tag_8C_len > 0) { 
        emv_generateDOL(currentcard.tag_8C, currentcard.tag_8C_len, &currentcard, cdolcommand, &cdolcommandlen); }
    else{
            // cdolcommand = NULL; //cdol val is null
        cdolcommandlen = 0;
    }
    // variables
    // tlvtag inputtag; //create the tag structure
    // perform select 
    if(!emv_generateAC(refcontrol, cdolcommand, cdolcommandlen,receivedAnswer)){
        if(MF_DBGLEVEL >= 1) Dbprintf("get processing options failed");
        return 1; 
    }
    if(receivedAnswer[2] == 0x77) //format 2 data field returned
    {
        decode_ber_tlv_item(&receivedAnswer[2], &temptag);
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    } 
    
    return 0;
}

//function to perform paywave transaction
//takes in TTQ, amount authorised, unpredicable number and transaction currency code
int EMV_PaywaveTransaction(void)
{
    uint8_t *resp  = BigBuf_malloc(256);
    tlvtag temptag; 
    //get the current block counter 
    //select the AID (Mastercard 
    EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
    
    if(resp[1] == 0x6F){ //decode template
        decode_ber_tlv_item(&resp[1], &temptag);
        //decode 84 and A5 tags 
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
        //decode the A5 tag 
        emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
        //decode the BF0C result, assuming 1 directory entry for now 
        //retrieve the AID 
    }
    // get PDOL
    uint8_t pdolcommand[20]; //20 byte buffer for pdol data 
    uint8_t pdolcommandlen = 0; 
    if(currentcard.tag_9F38_len > 0) { 
        emv_generateDOL(currentcard.tag_9F38, currentcard.tag_9F38_len, &currentcard, pdolcommand, &pdolcommandlen); 
    } else {
        pdolcommandlen = 0;
    }

    if(!EMVGetProcessingOptions(pdolcommand, pdolcommandlen, &currentcard)) {
        if(MF_DBGLEVEL >= 1) Dbprintf("PDOL failed");
        return 1; 
    }
    if(resp[1] == 0x80) //format 1 data field returned
    { 
        memcpy(currentcard.tag_82, &resp[3],2); //copy AIP
        currentcard.tag_94_len =  resp[2]-2; //AFL len
        memcpy(currentcard.tag_94, &resp[5], currentcard.tag_94_len); //copy AFL 
    }
    else if(resp[1] == 0x77) //format 2 data field returned
    {
        decode_ber_tlv_item(&resp[1], &temptag);
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    } 
    else
    {
        //throw an error
    }
    Dbprintf("AFL=");
    Dbhexdump(currentcard.tag_94_len, currentcard.tag_94,false); 
    Dbprintf("AIP=");
    Dbhexdump(2, currentcard.tag_82, false); 
    emv_decodeAIP(currentcard.tag_82); 
//    
//    decode the AFL list and read records 
       
    //record, sfi 
	EMVReadRecord(1,1,&currentcard);
    Dbhexdump(200, resp, false); 
	EMVReadRecord(2,1,&currentcard);
    Dbhexdump(200, resp,false); 
    EMVReadRecord( 1,2, &currentcard);
    Dbhexdump(200, resp,false); 
	EMVReadRecord(2,2,&currentcard);
    Dbhexdump(200, resp,false); 
    EMVReadRecord( 3,2, &currentcard);
    Dbhexdump(200, resp,false); 
    EMVReadRecord( 4,2, &currentcard);
    Dbhexdump(200, resp,false); 
    EMVReadRecord( 1,3, &currentcard);
    Dbhexdump(200, resp,false); 
	EMVReadRecord(2,3,&currentcard);
    Dbhexdump(200, resp,false); 
	EMVReadRecord(4,2,&currentcard);
    EMVReadRecord( 1,3, &currentcard);
    Dbhexdump(200, resp,false); 
    
    //DDA supported, so read more records 
    if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED){ 
        EMVReadRecord( 1,4, &currentcard);
        EMVReadRecord( 2,4, &currentcard);
    }

     
   emv_decodeCVM(currentcard.tag_8E, currentcard.tag_8E_len); 
    /* get ICC dynamic data */
    //if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED)
    {
        //DDA supported, so perform GENERATE AC 
        uint8_t cdolcommand[40]; //20 byte buffer for pdol data 
        uint8_t cdolcommandlen; 
        //generate the iCC UN 
        EMVGetChallenge(&currentcard);
		
        memcpy(currentcard.tag_9F37,&resp[1],8); // ICC UN 
        memcpy(currentcard.tag_9F4C,&resp[1],8); // ICC UN 
        if(currentcard.tag_8C_len > 0) { 
            emv_generateDOL(currentcard.tag_8C, currentcard.tag_8C_len, &currentcard, cdolcommand, &cdolcommandlen);
	    } else {
            cdolcommandlen = 0;
        }
        Dbhexdump(currentcard.tag_8C_len, currentcard.tag_8C,false); 
        Dbhexdump(cdolcommandlen, cdolcommand,false); 
        
		EMVGenerateAC(0x41, &currentcard);
        
        Dbhexdump(100, resp,false); 
   } 
    return 0;
} 

int EMV_PaypassTransaction(void)
{
    uint8_t *resp  = BigBuf_malloc(256); 
    tlvtag temptag; //buffer for decoded tags 
    // get the current block counter 
    // select the AID (Mastercard 
    EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
    
    if(resp[1] == 0x6F){ //decode template
        decode_ber_tlv_item(&resp[1], &temptag);
        //decode 84 and A5 tags 
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
        //decode the A5 tag 
        emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
        //decode the BF0C result, assuming 1 directory entry for now 
        //retrieve the AID 
    }
    // get PDOL
    uint8_t pdolcommand[20]; // 20 byte buffer for pdol data 
    uint8_t pdolcommandlen = 0; 
    if(currentcard.tag_9F38_len > 0) { 
        emv_generateDOL(currentcard.tag_9F38, currentcard.tag_9F38_len, &currentcard, pdolcommand, &pdolcommandlen); 
    } else {
        pdolcommandlen = 0;
    }
    if(EMVGetProcessingOptions(pdolcommand,pdolcommandlen, &currentcard)) {
        if(MF_DBGLEVEL >= 1) Dbprintf("PDOL failed");
        return 1; 
    }
    if(resp[1] == 0x80) //format 1 data field returned
    { 
        memcpy(currentcard.tag_82, &resp[3],2); //copy AIP
        currentcard.tag_94_len =  resp[2]-2; //AFL len
        memcpy(currentcard.tag_94, &resp[5],currentcard.tag_94_len); //copy AFL 
    }
    else if(resp[1] == 0x77) //format 2 data field returned
    {
        decode_ber_tlv_item(&resp[1], &temptag);
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    } 
    else
    {
        //throw an error
    }
    Dbprintf("AFL=");
    Dbhexdump(currentcard.tag_94_len, currentcard.tag_94,false); 
    Dbprintf("AIP=");
    Dbhexdump(2, currentcard.tag_82, false); 
    emv_decodeAIP(currentcard.tag_82); 
    
    // decode the AFL list and read records 

    //record, sfi 
    EMVReadRecord( 1,1, &currentcard);
    EMVReadRecord( 1,2, &currentcard);
    EMVReadRecord( 1,3, &currentcard);
    EMVReadRecord( 2,3, &currentcard);
    
    //DDA supported, so read more records 
    if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED){ 
        EMVReadRecord( 1,4, &currentcard);
        EMVReadRecord( 2,4, &currentcard);
    }


    /* get ICC dynamic data */
    if((currentcard.tag_82[0] & AIP_CDA_SUPPORTED) == AIP_CDA_SUPPORTED)
    {
        // DDA supported, so perform GENERATE AC 
        uint8_t cdolcommand[40]; //20 byte buffer for pdol data 
        uint8_t cdolcommandlen; 
        // generate the iCC UN 
        EMVGetChallenge(&currentcard);
        memcpy(currentcard.tag_9F4C, &resp[1],8); // ICC UN 
		
		if(currentcard.tag_8C_len > 0) { 
            emv_generateDOL(currentcard.tag_8C, currentcard.tag_8C_len, &currentcard, cdolcommand, &cdolcommandlen);
		} else {           
            cdolcommandlen = 0;
		}
		EMVGenerateAC(0x80, &currentcard);

        if(resp[1] == 0x77) //format 2 data field returned
        {
            decode_ber_tlv_item(&resp[1], &temptag);
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
        }
        
        // generate AC2  
        if(currentcard.tag_8D_len > 0) { 
            emv_generateDOL(currentcard.tag_8D, currentcard.tag_8D_len, &currentcard, cdolcommand, &cdolcommandlen); }
        else{
            //cdolcommand = NULL; //cdol val is null
            cdolcommandlen = 0;
        }
		
        EMVGenerateAC(0x80, &currentcard);
        
        if(resp[1] == 0x77) //format 2 data field returned
        {
            decode_ber_tlv_item(&resp[1], &temptag);
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
        }
    } 
    // generate cryptographic checksum
    uint8_t udol[4] = {0x00,0x00,0x00,0x00}; 
	
    emv_computecryptogram(udol, sizeof(udol), resp);
	
    if(resp[1] == 0x77) //format 2 data field returned
    {
        decode_ber_tlv_item(&resp[1], &temptag);
        emv_decode_field(temptag.value, temptag.valuelength, &currentcard); 
    } 
    return 0;
}

void EMVTransaction(void)
{
    //params
    uint8_t uid[10] = {0x00};
    uint32_t cuid = 0;
       
    //setup stuff
	BigBuf_free(); BigBuf_Clear_ext(false);
    clear_trace();
    set_tracing(true);
 
    
    uint8_t *resp  = BigBuf_malloc(256);
    //variables
    tlvtag temptag; //used to buffer decoded tag valuesd  
    //initialize the emv card structure
    //extern emvcard currentcard;
    
    memset(&currentcard, 0x00, sizeof(currentcard)); //set all to zeros 
    memcpy(currentcard.tag_9F66,"\xD7\x20\xC0\x00",4);
    memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6); //20 dollars 
    memcpy(currentcard.tag_9F37, "\x01\x02\x03\x04", 4); //UN 
    memcpy(currentcard.tag_5F2A, "\x00\x36",2); //currency code
    //CDOL stuff 
    memcpy(currentcard.tag_9F03,"\x00\x00\x00\x00\x00\x00",6);
    memcpy(currentcard.tag_9F1A,"\x00\x36",2); //country code
    memcpy(currentcard.tag_95,"\x00\x00\x00\x00\x00",5); //TVR
    memcpy(currentcard.tag_9A,"\x14\x04\x01",3); //date
    memcpy(currentcard.tag_9C,"\x00",1); //processingcode;
    memcpy(currentcard.tag_9F45, "\x00\x00", 2); //Data Authentication Code
    memset(currentcard.tag_9F4C,0x00,8); // ICC UN
    memcpy(currentcard.tag_9F35,"\x12",1);
    memcpy(currentcard.tag_9F34,"\x3F\x00\x00", 3); //CVM 
      

    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
 
    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
	
    while(true) { 
        if(!iso14443a_select_card(uid, NULL, &cuid, true, 0, false)) {
            if(MF_DBGLEVEL >= 1) Dbprintf("Can't select card");
            break;
        }
        EMVSelectPPSE();
        //get response
        if (resp[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&resp[1], &temptag);
            //decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //decode the A5 tag 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
            //decode the BF0C result, assuming 1 directory entry for now 
            if(currentcard.tag_BF0C_len !=0){
                emv_decode_field(currentcard.tag_BF0C, currentcard.tag_BF0C_len, &currentcard);}
            //retrieve the AID, use the AID to decide what transaction flow to use 
            if(currentcard.tag_61_len !=0){
                emv_decode_field(currentcard.tag_61, currentcard.tag_61_len, &currentcard);}
        } 
        if (!memcmp(currentcard.tag_4F, AID_MASTERCARD, sizeof(AID_MASTERCARD))){
            Dbprintf("Mastercard Paypass Card Detected"); 
            EMV_PaypassTransaction();
        }
        else if (!memcmp(currentcard.tag_4F, AID_VISA, sizeof(AID_VISA))){            
            Dbprintf("VISA Paywave Card Detected"); 
            EMV_PaywaveTransaction();
        }
        //TODO: add other card schemes like AMEX, JCB, China Unionpay etc 
	           LED_B_ON();
        //output the sensitive data
        cmd_send(CMD_ACK, 0, 0,0,resp,100); 
        LED_B_OFF();
        break;
    }
    if (MF_DBGLEVEL >= 2) DbpString("EMV TRANSACTION FINISHED");
        //finish up
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
}

void EMVdumpcard(void){
    dumpCard(&currentcard);
} 
										
//EMV clone a card - read up to the max SFI and max records for that SFI
void EMVClone(uint8_t maxsfi, uint8_t maxrecord)
{
     //params
	uint8_t uid[10];
    uint32_t cuid;
    uint8_t *resp  = BigBuf_malloc(256);
    iso14a_card_select_t hi14a_card; //card select values
    //variables
    tlvtag temptag; //used to buffer decoded tag valuesd  
    
    memset(&currentcard, 0x00, sizeof(currentcard)); //set all to zeros 
    //memcpy(currentcard.tag_9F66,"\x20\x00\x00\x00",4);
    memcpy(currentcard.tag_9F66,"\xD7\x20\xC0\x00",4);
    //memcpy(currentcard.tag_9F66,"\xC0\x00\x00\x00",2);
    memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6); //20 dollars 
    memcpy(currentcard.tag_9F37, "\x01\x02\x03\x04", 4); //UN 
    memcpy(currentcard.tag_5F2A, "\x00\x36",2); //currency code
    //CDOL stuff 
    //memcpy(currentcard.tag_9F02,"\x00\x00\x00\x00\x00\x20",6);
    memcpy(currentcard.tag_9F03,"\x00\x00\x00\x00\x00\x00",6);
    memcpy(currentcard.tag_9F1A,"\x00\x36",2); //country code
    memcpy(currentcard.tag_95,"\x00\x00\x00\x00\x00",5); //TVR
    //memcpy(currentcard.tag_5F2A,"\x00\x36",2);
    memcpy(currentcard.tag_9A,"\x14\x04x01",3); //date
    memcpy(currentcard.tag_9C,"\x00",1); //processingcode;
    memcpy(currentcard.tag_9F45, "\x00\x00", 2); //Data Authentication Code
    memset(currentcard.tag_9F4C,0x00,8); // ICC UN
    memcpy(currentcard.tag_9F35,"\x12",1);
    memcpy(currentcard.tag_9F34,"\x3F\x00\x00", 3); //CVM 

    iso14443a_setup(FPGA_HF_ISO14443A_READER_LISTEN);
    LED_A_ON();
    LED_B_OFF();
    LED_C_OFF();
    
    while(true) { 
        if(!iso14443a_select_card(uid, &hi14a_card, &cuid, true, 0, false)) {
            if(MF_DBGLEVEL >= 1) Dbprintf("Can't select card");
            break;
        }
        //copy UID and ATQA SAK and ATS values
        memcpy(currentcard.UID, hi14a_card.uid, hi14a_card.uidlen);  
        currentcard.UID_len = hi14a_card.uidlen; 
        memcpy(currentcard.ATQA, hi14a_card.atqa, 2);
        currentcard.SAK = (uint8_t)hi14a_card.sak;
        memcpy(currentcard.ATS, hi14a_card.ats, hi14a_card.ats_len);
        currentcard.ATS_len = hi14a_card.ats_len;
 
        if(MF_DBGLEVEL >= 1){
            Dbprintf("UID=");
            Dbhexdump(currentcard.UID_len, currentcard.UID, false);
            Dbprintf("ATQA=");
            Dbhexdump(2, currentcard.ATQA,false);
            Dbprintf("SAK=");
            Dbhexdump(1, &currentcard.SAK,false);
            Dbprintf("ATS=");
            Dbhexdump(currentcard.ATS_len, currentcard.ATS,false);
        }
        EMVSelectPPSE();
        //get response
        if(resp[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&resp[1], &temptag);
            //decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //decode the A5 tag 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
            //decode the BF0C result, assuming 1 directory entry for now 
            if(currentcard.tag_BF0C_len !=0){
                emv_decode_field(currentcard.tag_BF0C, currentcard.tag_BF0C_len, &currentcard);}
            //retrieve the AID, use the AID to decide what transaction flow to use 
            if(currentcard.tag_61_len !=0){
                emv_decode_field(currentcard.tag_61, currentcard.tag_61_len, &currentcard);}
        } 
        //perform AID selection 
        EMVSelectAID(currentcard.tag_4F,currentcard.tag_4F_len, &currentcard);  
        if(resp[1] == 0x6F){ //decode template
            decode_ber_tlv_item(&resp[1], &temptag);
            //decode 84 and A5 tags 
            emv_decode_field(temptag.value, temptag.valuelength, &currentcard);
            //decode the A5 tag 
            emv_decode_field(currentcard.tag_A5, currentcard.tag_A5_len, &currentcard);
            //decode the BF0C result, assuming 1 directory entry for now 
        }
        //decode the AFL list and read records 
        
        //scan all card records 
        Dbprintf("Reading %u SFIs and %u records...", maxsfi, maxrecord); 
        for(uint8_t sfi = 1; sfi < maxsfi; sfi++){ //all possible SFI values
            for(uint8_t record = 1; record < maxrecord; record++){
                EMVReadRecord(record,sfi, &currentcard);
                if(resp[1] == 0x70){ 
                Dbprintf("Record Found! SFI=%u RECORD=%u", sfi, record);
                } 
            }
        }
        Dbprintf("Reading finished"); 
        
        LED_B_ON();
        //output the sensitive data
        cmd_send(CMD_ACK, 0, 0,0,resp,100); 
        LED_B_OFF();
        break;
    }

    if(MF_DBGLEVEL >= 2) DbpString("EMV TRANSACTION FINISHED");
        //finish up
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
}

//SIMULATOR CODE
//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void EMVSim(void)
{
	/*
	
	//uint8_t sak; //select ACKnowledge
    uint16_t readerPacketLen = 64; //reader packet length - provided by RATS, default to 64 bytes if RATS not supported
	
    // The first response contains the ATQA (note: bytes are transmitted in reverse order).
	//uint8_t atqapacket[2];
	
	// The second response contains the (mandatory) first 24 bits of the UID
	uint8_t uid0packet[5] = {0x00};
    memcpy(uid0packet, currentcard.UID, sizeof(uid0packet));
	// Check if the uid uses the (optional) part
    uint8_t uid1packet[5] = {0x00};
    memcpy(uid1packet, currentcard.UID, sizeof(uid1packet));
	
	// Calculate the BitCountCheck (BCC) for the first 4 bytes of the UID.
	uid0packet[4] = uid0packet[0] ^ uid0packet[1] ^ uid0packet[2] ^ uid0packet[3];

	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t sak0packet[3] = {0x00};
    memcpy(sak0packet,&currentcard.SAK1,1);
	ComputeCrc14443(CRC_14443_A, sak0packet, 1, &sak0packet[1], &sak0packet[2]);
	uint8_t sak1packet[3]  = {0x00};
    memcpy(sak1packet,&currentcard.SAK2,1);
	// Prepare the optional second SAK (for 7 byte UID), drop the cascade bit
	ComputeCrc14443(CRC_14443_A, sak1packet, 1, &sak1packet[1], &sak1packet[2]);
	
    uint8_t authanspacket[] = { 0x00, 0x00, 0x00, 0x00 }; // Very random tag nonce
    //setup response to ATS 
    uint8_t ratspacket[currentcard.ATS_len];
    memcpy(ratspacket,currentcard.ATS, currentcard.ATS_len);
    AppendCrc14443a(ratspacket,sizeof(ratspacket)-2); 
    
	// Format byte = 0x58: FSCI=0x08 (FSC=256), TA(1) and TC(1) present, 
	// TA(1) = 0x80: different divisors not supported, DR = 1, DS = 1
	// TB(1) = not present. Defaults: FWI = 4 (FWT = 256 * 16 * 2^4 * 1/fc = 4833us), SFGI = 0 (SFG = 256 * 16 * 2^0 * 1/fc = 302us)
	// TC(1) = 0x02: CID supported, NAD not supported
	//ComputeCrc14443(CRC_14443_A, response6, 4, &response6[4], &response6[5]);
    
    //Receive Acknowledge responses differ by PCB byte 
    uint8_t rack0packet[] = {0xa2,0x00,0x00};
    AppendCrc14443a(rack0packet,1); 
    uint8_t rack1packet[] = {0xa3,0x00,0x00};
    AppendCrc14443a(rack1packet,1); 
    //Negative Acknowledge
    uint8_t rnak0packet[] = {0xb2,0x00,0x00};
    uint8_t rnak1packet[] = {0xb3,0x00,0x00};
    AppendCrc14443a(rnak0packet,1); 
    AppendCrc14443a(rnak1packet,1); 
    
    //Protocol and parameter selection response, just say yes
    uint8_t ppspacket[] = {0xd0,0x00,0x00};
    AppendCrc14443a(ppspacket,1);
   
    //hardcoded WTX packet - set to max time (49) 
    uint8_t wtxpacket[] ={0xf2,0x31,0x00,0x00};
    AppendCrc14443a(wtxpacket,2);
    
    //added additional responses for different readers, namely protocol parameter select and Receive acknowledments. - peter fillmore.
    //added defininitions for predone responses to aid readability
    #define ATR     0 
    #define UID1    1
    #define UID2    2
    #define SELACK1 3
    #define SELACK2 4
    #define AUTH_ANS 5
    #define ATS     6
    #define RACK0   7
    #define RACK1   8
    #define RNAK0   9
    #define RNAK1   10
    #define PPSresponse 11
    #define WTX    12
  	
    #define TAG_RESPONSE_COUNT 13 
	tag_response_info_t responses[TAG_RESPONSE_COUNT] = {
		{ .response = currentcard.ATQA,  .response_n = sizeof(currentcard.ATQA)  },  // Answer to request - respond with card type
		{ .response = uid0packet,  .response_n = sizeof(uid0packet)  },  // Anticollision cascade1 - respond with uid
		{ .response = uid1packet, .response_n = sizeof(uid1packet) },  // Anticollision cascade2 - respond with 2nd half of uid if asked
		{ .response = sak0packet,  .response_n = sizeof(sak0packet)  },  // Acknowledge select - cascade 1
		{ .response = sak1packet, .response_n = sizeof(sak1packet) },  // Acknowledge select - cascade 2
		{ .response = authanspacket,  .response_n = sizeof(authanspacket)  },  // Authentication answer (random nonce)
		{ .response = ratspacket,  .response_n = sizeof(ratspacket)  },  // dummy ATS (pseudo-ATR), answer to RATS
        { .response = rack0packet, .response_n = sizeof(rack0packet) },  //R(ACK)0
        { .response = rack1packet, .response_n = sizeof(rack1packet) },  //R(ACK)0
        { .response = rnak0packet, .response_n = sizeof(rnak0packet) },  //R(NAK)0
        { .response = rnak1packet, .response_n = sizeof(rnak1packet) },  //R(NAK)1
        { .response = ppspacket, .response_n = sizeof(ppspacket)},       //PPS packet 
        { .response = wtxpacket, .response_n = sizeof(wtxpacket)},       //WTX packet
};

    //calculated length of predone responses
    uint16_t allocatedtaglen = 0;
    for(int i=0;i<TAG_RESPONSE_COUNT;i++){
        allocatedtaglen += responses[i].response_n;
    }
	//uint8_t selectOrder = 0; 
 
	BigBuf_free_keep_EM();
    // Allocate 512 bytes for the dynamic modulation, created when the reader queries for it
	// Such a response is less time critical, so we can prepare them on the fly
	
    #define DYNAMIC_RESPONSE_BUFFER_SIZE 64
	#define DYNAMIC_MODULATION_BUFFER_SIZE 512
	
    //uint8_t dynamic_response_buffer[DYNAMIC_RESPONSE_BUFFER_SIZE];
	//uint8_t dynamic_modulation_buffer[DYNAMIC_MODULATION_BUFFER_SIZE];
    uint8_t *dynamic_response_buffer = BigBuf_malloc(DYNAMIC_RESPONSE_BUFFER_SIZE);
    uint8_t *dynamic_modulation_buffer = BigBuf_malloc(DYNAMIC_MODULATION_BUFFER_SIZE);
    
    tag_response_info_t dynamic_response_info = {
		.response = dynamic_response_buffer,
		.response_n = 0,
		.modulation = dynamic_modulation_buffer,
		.modulation_n = 0
	};
	// allocate buffers from BigBuf (so we're not in the stack)
	uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);
	uint8_t *receivedCmdPar = BigBuf_malloc(MAX_PARITY_SIZE);
    //uint8_t* free_buffer_pointer;
    //free_buffer_pointer = BigBuf_malloc((allocatedtaglen*8) +(allocatedtaglen) + (TAG_RESPONSE_COUNT * 3));
    BigBuf_malloc((allocatedtaglen*8) +(allocatedtaglen) + (TAG_RESPONSE_COUNT * 3));
    // clear trace
	clear_trace();
	set_tracing(true);

	// Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
	for (size_t i=0; i<TAG_RESPONSE_COUNT; i++)
		prepare_allocated_tag_modulation(&responses[i]);

	int len = 0;

	// To control where we are in the protocol
	int order = 0;
	int lastorder;
    int currentblock = 1; //init to 1 
    int previousblock = 0; //used to store previous block counter 

	// Just to allow some checks
	int happened = 0;
	int happened2 = 0;
	int cmdsRecvd = 0;

	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

	cmdsRecvd = 0;
	tag_response_info_t* p_response;

	LED_A_ON();
	for(;;) {
		// Clean receive command buffer
		
		if(!GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len)) {
			DbpString("Button press");
			break;
		}

		p_response = NULL;
		
		// Okay, look at the command now.
	    previousblock = currentblock; //get previous block	
        lastorder = order;
	    currentblock = receivedCmd[0] & 0x01; 	
        
        if(receivedCmd[0] == 0x26) { // Received a REQUEST
			p_response = &responses[ATR]; order = ISO14443A_CMD_REQA;
		} else if(receivedCmd[0] == 0x52) { // Received a WAKEUP
			p_response = &responses[ATR]; order = ISO14443A_CMD_WUPA;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
			p_response = &responses[UID1]; order =  ISO14443A_CMD_ANTICOLL_OR_SELECT;
		} else if(receivedCmd[1] == 0x20 && receivedCmd[0] == 0x95) { 	// Received request for UID (cascade 2)
			p_response = &responses[UID2]; order =  ISO14443A_CMD_ANTICOLL_OR_SELECT_2;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
			p_response = &responses[SELACK1]; order =  ISO14443A_CMD_ANTICOLL_OR_SELECT;
		} else if(receivedCmd[1] == 0x70 && receivedCmd[0] == 0x95) {	// Received a SELECT (cascade 2)
			p_response = &responses[SELACK2]; order =  ISO14443A_CMD_ANTICOLL_OR_SELECT_2;
		} else if((receivedCmd[0] & 0xA2) == 0xA2){ //R-Block received 
            if(previousblock == currentblock){ //rule 11, retransmit last block
		        p_response = &dynamic_response_info;
            } else {
                if((receivedCmd[0] & 0xB2) == 0xB2){ //RNAK, rule 12
                    if(currentblock == 0)
                        p_response = &responses[RACK0];
                    else
                        p_response = &responses[RACK1];
				} else {
                    //rule 13
                    //TODO: implement chaining 
                }
            }
        }
        else if(receivedCmd[0] == 0xD0){ //Protocol and parameter selection response
            p_response = &responses[PPSresponse];
			order = PPS;
        }
        else if(receivedCmd[0] == 0x30) {	// Received a (plain) READ
		    //we're an EMV card - so no read commands	
            p_response = NULL;
		} else if(receivedCmd[0] == 0x50) {	// Received a HALT
			LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
			p_response = NULL;
			order = HLTA;
		} else if(receivedCmd[0] == 0x60 || receivedCmd[0] == 0x61) {	// Received an authentication request
			p_response = &responses[AUTH_ANS];
			order = AUTH;
		} else if(receivedCmd[0] == 0xE0) {	// Received a RATS request
		    readerPacketLen = GetReaderLength(receivedCmd); //get length of supported packet   	
			p_response = &responses[ATS];
			order = RATS;
		} else if (order == AUTH && len == 8) { // Received {nr] and {ar} (part of authentication)
			LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
			uint32_t nr = bytes_to_num(receivedCmd,4);
			uint32_t ar = bytes_to_num(receivedCmd+4,4);
			Dbprintf("Auth attempt {nr}{ar}: %08x %08x",nr,ar);
		} else {
			// Check for ISO 14443A-4 compliant commands, look at left nibble
			switch (receivedCmd[0]) {
				case 0x0B:
				case 0x0A: // IBlock (command)
                case 0x02:
                case 0x03: {
				    dynamic_response_info.response_n = 0; 
                    dynamic_response_info.response[0] = receivedCmd[0]; // copy PCB 
                    //dynamic_response_info.response[1] = receivedCmd[1]; // copy PCB 
                    dynamic_response_info.response_n++ ; 
                    switch(receivedCmd[1]) {
                        case 0x00: 
                            switch(receivedCmd[2]){
                                case 0xA4: //select
                                    if(receivedCmd[5] == 0x0E){ 
                                    }
                                    else if(receivedCmd[5] == 0x07){
                                            //selectOrder = 0;
                                    }
                                    else{ //send not supported msg
                                        memcpy(dynamic_response_info.response+1, "\x6a\x82", 2);
                                        dynamic_response_info.response_n += 2;
                                    }
                                    break;
                                case 0xB2: //read record
                                    if(receivedCmd[3] == 0x01 && receivedCmd[4] == 0x0C){
                                        dynamic_response_info.response_n += 2;
                                        Dbprintf("READ RECORD 1 1"); 
                                    }
                                    break;
                                }
								break;
                        case 0x80: 
                            switch(receivedCmd[2]){
                                case 0xA8: //get processing options
                                    break;
				            }
                        } 
                    }break;
			    case 0x1A:
			    case 0x1B: { // Chaining command
				      dynamic_response_info.response[0] = 0xaa | ((receivedCmd[0]) & 1);
				      dynamic_response_info.response_n = 2;
				    } break;

				case 0xaa:
				case 0xbb: {
				  dynamic_response_info.response[0] = receivedCmd[0] ^ 0x11;
				  dynamic_response_info.response_n = 2;
				} break;
				  
				case 0xBA: { //
				  memcpy(dynamic_response_info.response,"\xAB\x00",2);
				  dynamic_response_info.response_n = 2;
				} break;

				case 0xCA:
                case 0xC2: { // Readers sends deselect command
				  //we send the command back - this is what tags do in android implemenation i believe - peterfillmore 
                   memcpy(dynamic_response_info.response,receivedCmd,1);
				   dynamic_response_info.response_n = 1;  
				} break;
                
				default: {
					// Never seen this command before
					LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
					Dbprintf("Received unknown command (len=%d):",len);
					Dbhexdump(len,receivedCmd,false);
					// Do not respond
					dynamic_response_info.response_n = 0;
				} break;
			}
      
			if (dynamic_response_info.response_n > 0) {
				// Copy the CID from the reader query
				//dynamic_response_info.response[1] = receivedCmd[1];

				// Add CRC bytes, always used in ISO 14443A-4 compliant cards
				AppendCrc14443a(dynamic_response_info.response,dynamic_response_info.response_n);
				dynamic_response_info.response_n += 2;
                if(dynamic_response_info.response_n > readerPacketLen){ //throw error if our reader doesn't support the send packet length
                    Dbprintf("Error: tag response is longer then what the reader supports, TODO:implement command chaining");
					LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
					break;
                }
				if (prepare_tag_modulation(&dynamic_response_info,DYNAMIC_MODULATION_BUFFER_SIZE) == false) {
					Dbprintf("Error preparing tag response");
					LogTrace(receivedCmd, Uart.len, Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, Uart.parity, true);
					break;
				}
				p_response = &dynamic_response_info;
			}
		}

		// Count number of wakeups received after a halt
		if(order == HLTA && lastorder == PPS) { happened++; }

		// Count number of other messages after a halt
		if(order != HLTA && lastorder == PPS) { happened2++; }

		if(cmdsRecvd > 999) {
			DbpString("1000 commands later...");
			break;
		}
		cmdsRecvd++;

		if (p_response != NULL) {
			EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n);
			// do the tracing for the previous reader request and this tag answer:

	
			// EmLogTrace(Uart.output, 
						// Uart.len, 
						// Uart.startTime*16 - DELAY_AIR2ARM_AS_TAG, 
						// Uart.endTime*16 - DELAY_AIR2ARM_AS_TAG, 
						// Uart.parity,
						// p_response->response, 
						// p_response->response_n,
						// LastTimeProxToAirStart*16 + DELAY_ARM2AIR_AS_TAG,
						// (LastTimeProxToAirStart + p_response->ProxToAirDuration)*16 + DELAY_ARM2AIR_AS_TAG, 
						// par);
						
		}
    		
//		if (!tracing) {
//			Dbprintf("Trace Full. Simulation stopped.");
//			break;
//		}
	
	}

	Dbprintf("%x %x %x", happened, happened2, cmdsRecvd);
	LED_A_OFF();
	BigBuf_free_keep_EM();
	
	*/
}
//-----------------------------------------------------------------------------
// Main loop of simulated tag: receive commands from reader, decide what
// response to send, and send it.
//-----------------------------------------------------------------------------
void EMVFuzz_RATS(uint8_t ratslen, uint8_t* RATS)
{
    int len; 
	uint8_t sak  = 0x28;
    //copy input rats into a buffer
    uint8_t ratscmd[ratslen+2]; 
    memcpy(ratscmd, RATS, ratslen);
	
    // The first response contains the ATQA (note: bytes are transmitted in reverse order).
	uint8_t atqa[2] = {0x04, 0x00};
	
	// The second response contains the (mandatory) first 24 bits of the UID
	uint8_t uid0[5] = {0x12,0x34,0x56,0x78,0x9A};

	// Calculate the BitCountCheck (BCC) for the first 4 bytes of the UID.
	uid0[4] = uid0[0] ^ uid0[1] ^ uid0[2] ^ uid0[3];

	// Prepare the mandatory SAK (for 4 and 7 byte UID)
	uint8_t sakresponse[3];
	sakresponse[0] = sak;
	ComputeCrc14443(CRC_14443_A, sakresponse, 1, &sakresponse[1], &sakresponse[2]);

	// Prepare the optional second SAK (for 7 byte UID), drop the cascade bit
    
    uint8_t ACK1[] = {0xa3,0x6f,0xc6}; //ACK packets 
    uint8_t ACK2[] = {0xa2,0x00,0x00};
    AppendCrc14443a(ACK2, 1);
    
    AppendCrc14443a(ratscmd, sizeof(ratscmd)-2); 

    //handle the PPS selection
    uint8_t PPSR[3] = {0xD0,0x00,0x00};
    AppendCrc14443a(PPSR, 1);
    
	//#define TAG_RESPONSE_COUNT 9 
	tag_response_info_t responses[7] = {
		{ .response = atqa,  .response_n = sizeof(atqa)  },  // Answer to request - respond with card type
		{ .response = uid0,  .response_n = sizeof(uid0)  },  // Anticollision cascade1 - respond with uid
		{ .response = sakresponse,  .response_n = sizeof(sakresponse)  },  // Acknowledge select - cascade 1
		{ .response = ratscmd,  .response_n = sizeof(ratscmd)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK1,  .response_n = sizeof(ACK1)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = ACK2,  .response_n = sizeof(ACK2)  },  // dummy ATS (pseudo-ATR), answer to RATS
		{ .response = PPSR,  .response_n = sizeof(PPSR)  },  // dummy ATS (pseudo-ATR), answer to RATS
	};

	// Reset the offset pointer of the free buffer
	//reset_free_buffer();
  
	// Prepare the responses of the anticollision phase
	// there will be not enough time to do this at the moment the reader sends it REQA
    for (size_t i=0; i<7; i++) {
		prepare_allocated_tag_modulation(&responses[i]);
	}
	uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);
	uint8_t *receivedCmdPar = BigBuf_malloc(MAX_PARITY_SIZE);
	
	// To control where we are in the protocol
	int order = 0;

	// We need to listen to the high-frequency, peak-detected path.
	iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);
	tag_response_info_t* p_response;
    
	LED_C_ON();
	// Clean receive command buffer
    for(;;){  
        if (!GetIso14443aCommandFromReader(receivedCmd, receivedCmdPar, &len)){
            break;
        } 
	    p_response = NULL;

        if ((receivedCmd[0] == 0x26) || (receivedCmd[0] == 0x52)) { // Received a REQUEST
	    	p_response = &responses[0]; order = 1;
        }	
	    if (receivedCmd[1] == 0x20 && receivedCmd[0] == 0x93) {	// Received request for UID (cascade 1)
            p_response = &responses[1]; order = 2; //send the UID 
	    }  
        if (receivedCmd[1] == 0x70 && receivedCmd[0] == 0x93) {	// Received a SELECT (cascade 1)
	    	p_response = &responses[2]; order = 3; //send the SAK
	    }
        if (receivedCmd[0] == 0xD0) {	// Received a PPS request
	    	p_response = &responses[6]; order = 70;
	    } 
	    if (receivedCmd[0] == 0xE0) {	// Received a RATS request
	    	p_response = &responses[3]; order = 70;
            EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n);
            break;
	    }
        if (p_response != NULL){
            EmSendCmd14443aRaw(p_response->modulation, p_response->modulation_n);
        } else {
            break;
        } 
    } 

	if (order && (MF_DBGLEVEL >= 2)) DbpString("just using order vars");
	
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	LED_C_OFF();
    return;
}
