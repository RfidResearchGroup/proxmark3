#include "proxmark3.h"
#include "apps.h"
#include "BigBuf.h"
#include "util.h"
#include "usb_cdc.h"	// for usb_poll_validate_length
#include "../common/protocols.h"

//random service RW: 0x0009
//random service RO: 0x000B

//structure to hold outgoing NFC frame 
static uint8_t frameSpace[MAX_FRAME_SIZE+4];

//structure to hold incoming NFC frame, used for ISO/IEC 18092-compatible frames
static struct {
    enum {
        STATE_UNSYNCD,
        STATE_TRYING_SYNC,
        STATE_GET_LENGTH,
        STATE_GET_DATA,
        STATE_GET_CRC,
        STATE_FULL
    } state;

    uint16_t  shiftReg; //for synchronization and offset calculation
    int       posCnt;
    uint8_t   crc_ok;
    int       rem_len;
    uint16_t  len;
    uint8_t   byte_offset;
    uint16_t  rolling_crc;    
    uint8_t   framebytes[260]; //should be enough. maxlen is 255, 254 for data, 2 for sync, 2  for crc
    // 0,1 -> SYNC, 2 - len,  3-(len+1)->data, then crc
} NFCFrame;

//b2 4d is SYNC, 45645 in 16-bit notation, 10110010 01001101 binary. Frame will not start filling until this is shifted in
//bit order in byte -reverse, I guess?  [((bt>>0)&1),((bt>>1)&1),((bt>>2)&1),((bt>>3)&1),((bt>>4)&1),((bt>>5)&1),((bt>>6)&1),((bt>>7)&1)] -at least in the mode that I read those in

# define SYNC_16BIT 45645

static void ResetNFCFrame() {
    NFCFrame.state = STATE_UNSYNCD;
    NFCFrame.posCnt = 0;
    NFCFrame.crc_ok = 0;
    NFCFrame.byte_offset = 0;
    NFCFrame.rolling_crc = 0;
}

//shift byte into frame, reversing it at the same time
static void shiftInByte(uint8_t bt) {
    
    for(int j=0; j < NFCFrame.byte_offset; j++) {
        NFCFrame.framebytes[NFCFrame.posCnt] = ( NFCFrame.framebytes[NFCFrame.posCnt]<<1 ) + (bt & 1); 
        bt >>= 1;
    }
    NFCFrame.posCnt++;
    NFCFrame.rem_len--;
    for(int j = NFCFrame.byte_offset; j<8; j++) {
        NFCFrame.framebytes[NFCFrame.posCnt] = (NFCFrame.framebytes[NFCFrame.posCnt]<<1 ) + (bt & 1);
        bt >>= 1;
    }
}

//crc table - from lammertb/libcrc
static uint16_t crc_tabccitt[256];
static uint8_t crc_tabccitt_init = 0;

static void init_crcccitt_tab( void ) {
    uint16_t i, j, crc, c;

    for (i=0; i<256; i++) {

        crc = 0;
        c   = i << 8;

        for (j=0; j<8; j++) {

            if ( (crc ^ c) & 0x8000 )
				crc = ( crc << 1 ) ^ 0x1021;
            else
				crc =   crc << 1;

            c = c << 1;
        }
        crc_tabccitt[i] = crc;
    }
    crc_tabccitt_init = true;
} 

static uint16_t update_crc_ccitt( uint16_t crc, unsigned char c ) {
    return (crc << 8) ^ crc_tabccitt[ ((crc >> 8) ^ (uint16_t) c) & 0x00FF ];
} 

void SetcrcToFrame(uint8_t * framebf) {
    //expect framebuf to be preset with len...
    uint16_t crc = 0;
    for (int i=2; i < 2 + framebf[2]; i++) {
        crc = update_crc_ccitt(crc, framebf[i]);
    }
    framebf[2 + framebf[2]] = (crc >> 8);
    framebf[3 + framebf[2]] = (crc & 0xff);
}

static void ProcessNFCByte(uint8_t bt) {
    switch (NFCFrame.state) {
		case STATE_UNSYNCD: {
			//almost any nonzero byte can be start of SYNC. SYNC should be preceded by zeros, but that is not alsways the case
			if (bt > 0) {
				NFCFrame.shiftReg = reflect(bt, 8);
				NFCFrame.state = STATE_TRYING_SYNC;
			}
			break;
		}
		case STATE_TRYING_SYNC: {
			if (bt == 0) {
				//desync
				NFCFrame.shiftReg = bt;
				NFCFrame.state = STATE_UNSYNCD;
			} else {
				for (int i=0; i<8; i++) {
					
					if (NFCFrame.shiftReg == SYNC_16BIT) {
						//SYNC done!
						NFCFrame.state = STATE_GET_LENGTH;
						NFCFrame.framebytes[0] = 0xb2;
						NFCFrame.framebytes[1] = 0x4d; //write SYNC
						NFCFrame.byte_offset = i;
						//shift in remaining byte, slowly...
						for(int j=i; j<8; j++) {
							NFCFrame.framebytes[2] = (NFCFrame.framebytes[2] << 1) + (bt & 1);
							bt >>= 1;
						}
						
						NFCFrame.posCnt = 2;
						if (i==0)
							break;
					}
					NFCFrame.shiftReg = (NFCFrame.shiftReg << 1) + (bt & 1);
					bt >>= 1;
				}

				//that byte was last byte of sync
				if (NFCFrame.shiftReg == SYNC_16BIT) {
					//Force SYNC on next byte
					NFCFrame.state = STATE_GET_LENGTH;
					NFCFrame.framebytes[0] = 0xb2;
					NFCFrame.framebytes[1] = 0x4d; 
					NFCFrame.byte_offset = 0;
					NFCFrame.posCnt = 1;
				}
			}
			break;
		}
		case STATE_GET_LENGTH: {
			shiftInByte(bt);
			NFCFrame.rem_len = NFCFrame.framebytes[2] - 1;
			NFCFrame.rolling_crc = update_crc_ccitt(0, NFCFrame.framebytes[2]); //start calculating CRC for later
			NFCFrame.len = NFCFrame.framebytes[2] + 4; //with crc and sync
			NFCFrame.state = STATE_GET_DATA;
			break;
		}
		case STATE_GET_DATA: {
			shiftInByte(bt);
			if (NFCFrame.byte_offset != 0)
				NFCFrame.rolling_crc = update_crc_ccitt(NFCFrame.rolling_crc, NFCFrame.framebytes[NFCFrame.posCnt-1] );
			else
				NFCFrame.rolling_crc = update_crc_ccitt(NFCFrame.rolling_crc, NFCFrame.framebytes[NFCFrame.posCnt]);
			
			if (NFCFrame.rem_len <= 0) {
				NFCFrame.state = STATE_GET_CRC;
				NFCFrame.rem_len = 2;
			}
			break;
		}
		case STATE_GET_CRC: {
			shiftInByte(bt);
			if ( NFCFrame.rem_len <= 0 ) {
				NFCFrame.crc_ok = ((NFCFrame.rolling_crc & 0xff) == NFCFrame.framebytes[NFCFrame.len-1] && (NFCFrame.rolling_crc >> 8) == NFCFrame.framebytes[NFCFrame.len-2]);
				NFCFrame.state = STATE_FULL;
				NFCFrame.rem_len = 0;
			}
			break;
		}
		case STATE_FULL:  //ignore byte. Don't forget to clear frame to receive next one...        
		default: 
			break;
	}
}

void HfSnoopISO18(uint32_t samplesToSkip, uint32_t triggersToSkip) {
    if (!crc_tabccitt_init)
        init_crcccitt_tab();
	
    int remFrames = (samplesToSkip) ? samplesToSkip : 0;

    Dbprintf("Snoop FelicaLiteS: Getting first %d frames, Skipping %d triggers.\n", samplesToSkip, triggersToSkip);
  
    LED_D_ON();
    // Select correct configs
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    // Set up the synchronous serial port
    FpgaSetupSsc();
    // connect Demodulated Signal to ADC:
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	BigBuf_free(); BigBuf_Clear();
	clear_trace();
    
    FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092|FPGA_HF_ISO18092_FLAG_NOMOD);
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8)  | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    SpinDelay(100);

    //the frame bits are slow enough. 
    int n = BigBuf_max_traceLen() / sizeof(uint8_t); // take all memory
	int numbts = 0;
    uint8_t *dest = (uint8_t *)BigBuf_get_addr();
    uint8_t *destend = dest + n-2;

    ResetNFCFrame();

    StartCountSspClk(); //for apx frame timing

    uint32_t endframe = GetCountSspClk();

    while (dest <= destend) {
        WDT_HIT();
		if( BUTTON_PRESS()) break;
				
        if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
            uint8_t dist = (uint8_t)(AT91C_BASE_SSC->SSC_RHR);
            ProcessNFCByte(dist);
            
			//to be sure we are in frame
            if (NFCFrame.state == STATE_GET_LENGTH) {
                //length is after 48 (PRE)+16 (SYNC) - 64 ticks +maybe offset? not 100% 
                uint16_t distance = GetCountSspClk() - endframe - 64 + (NFCFrame.byte_offset > 0 ? (8-NFCFrame.byte_offset) : 0);
                *dest = distance >> 8;
                dest++;
                *dest = (distance & 0xff);
                dest++;
            }
			//crc NOT checked
            if (NFCFrame.state == STATE_FULL) {
                endframe = GetCountSspClk();
                *dest = NFCFrame.crc_ok; //kind of wasteful
                dest++;
                for(int i=0; i < NFCFrame.len; i++) {
                    *dest = NFCFrame.framebytes[i];
                    dest++;
                    if (dest >= destend ) break;

                }

                remFrames--;
                if (remFrames <= 0) break;
                if (dest >= destend ) break;
				
                numbts += NFCFrame.len;
                
				ResetNFCFrame();
            }
        }
    }

    //reset framing
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    set_tracelen(numbts);

    LED_D_OFF();	
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    Dbprintf("Felica sniffing done, tracelen: %i, use hf list felica for annotations", BigBuf_get_traceLen());
	cmd_send(CMD_ACK,1,0,0,0,0);
}

// poll-0: 0xb2,0x4d,0x06,0x00,0xff,0xff,0x00,0x00,0x09,0x21,
// resp:  0xb2,0x4d,0x12,0x01,0x01,0x2e,0x3d,0x17,0x26,0x47,0x80,0x95,0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00,0xb3,0x7f,
// poll-1 (reply with available system codes - NFC Tag3 specs, IIRC): 0xb2,0x4d,0x06,0x00,0xff,0xff,0x01,0x00,0x3a,0x10
// resp: 0xb2,0x4d,0x14,0x01,  0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,  0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00,  0x88,0xb4,0x0c,0xe2,
// page-req:  0xb2,0x4d,0x10,0x06,  0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,  0x01,  0x0b,0x00,  0x01,  0x80,0x00,  0x2e,0xb3,
// page-req: 0x06, IDm(8), ServiceNum(1),Slist(2*num) BLocknum (1) BLockids(2-3*num) 
// page-resp: 0xb2,0x4d,0x1d,0x07,  0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,0xXX,  0x00,  0x00,  0x01,  0x10,0x04,0x01,0x00,0x0d,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x23,   0xcb,0x6e,

//builds a readblock frame for felica lite(s). Felica standart has a different file system, AFAIK
// 8-byte ndef, number of blocks, blocks numbers
// number of blocks limited to 4 for FelicaLite(S)
static void BuildFliteRdblk(uint8_t* ndef, int blocknum,uint16_t * blocks ) {

    if (blocknum > 4 || blocknum <= 0)
        Dbprintf("Invalid number of blocks, %d. Up to 4 are allowed.", blocknum);
	
    int c = 0, i = 0;
    frameSpace[c++] = 0xb2;
    frameSpace[c++] = 0x4d;
    c++; //set length later
    frameSpace[c++] = FELICA_RDBLK_REQ; //command number
    for (i=0; i <8; i++) //card IDm, from poll
     frameSpace[c++] = ndef[i];
    
    frameSpace[c++]= 0x01; //number of services
    frameSpace[c++]= (uint8_t)(((uint16_t)FLITE_SERVICE_RO)&0xff);//service code -big endian?
    frameSpace[c++]= (uint8_t)(((uint16_t)FLITE_SERVICE_RO)>>8);
    frameSpace[c++]= blocknum; //number of blocks
    for (i=0; i < blocknum; i++) {

		//3-byte block
		if (blocks[i] >= 256) {
           frameSpace[c++] = 0x00;
           frameSpace[c++] = (blocks[i] >> 8); //block number, little endian....
           frameSpace[c++] = (blocks[i] & 0xff);            
        } else {
            frameSpace[c++] = 0x80;
            frameSpace[c++] = blocks[i];
        }
    }
    frameSpace[2] = c-2; //set length
    SetcrcToFrame(frameSpace);
}

//legacy, technically.
static int manch_tbl_fill = 0;
static uint8_t manch_tbl[16] = {0};

static void fillManch() {
	for(uint8_t obs = 0; obs < 16; obs++) {
		uint8_t res = 0;
		uint8_t tmp = obs << 4;
		for(int j=0; j<4; j++) {
			res <<= 2;
			if (tmp & 0x80) 
				res += 2;
			else
				res += 1;
			tmp <<= 1;
		}
		manch_tbl[obs] = res;
	}
	manch_tbl_fill = 1;
}

static void TransmitFor18092_AsReader(uint8_t * frame, int len, uint32_t waitTill, uint8_t power, uint8_t highspeed) {
	if (!manch_tbl_fill)
		fillManch();
	
	volatile uint32_t b;
	int c;
	uint32_t ThisTransferTime = 0;

	FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | (power ? FPGA_HF_ISO18092_FLAG_READER : 0) | ( highspeed ? FPGA_HF_ISO18092_FLAG_424K : 0) );

	if (power)
		FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | FPGA_HF_ISO18092_FLAG_READER | (highspeed > 0) );
	else
		FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 );

	if (waitTill > 0) {
		while( (ThisTransferTime = GetCountSspClk()) < waitTill) 
			WDT_HIT();
	}
  
    //preamble
	for (c = 0; c < 6;) {
		if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = 0x00;
			c++;
		}
		if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			b = (uint16_t)(AT91C_BASE_SSC->SSC_RHR); (void)b;
		}
	}

	for (c = 0; c < len;) {
		if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY)) {
			AT91C_BASE_SSC->SSC_THR = frame[c];
			c++;
		}
		if (AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_RXRDY)) {
			b = (uint16_t)(AT91C_BASE_SSC->SSC_RHR); (void)b;
		}
	}

	while (!(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))) {};
	AT91C_BASE_SSC->SSC_THR = 0x00; //minimum delay

	while (!(AT91C_BASE_SSC->SSC_SR & (AT91C_SSC_TXRDY))) {};
	AT91C_BASE_SSC->SSC_THR = 0x00; //spin

	//disable
	if (power)
		FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 |FPGA_HF_ISO18092_FLAG_READER | 1);
	else
		FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | 1 );
}

#define R_POLL0_LEN    0x16
#define R_POLL1_LEN    0x18
#define R_READBLK_LEN  0x21
//simulate NFC Tag3 card - for now only poll response works
// second half (4 bytes)  of NDEF2 goes into nfcid2_0, first into nfcid2_1
void HfSimLite( uint64_t nfcid) {
	
	if (!crc_tabccitt_init)
		init_crcccitt_tab();
	
	if (!manch_tbl_fill)
		fillManch();

    int i, curlen = 0;
    uint8_t *curresp = 0;

	uint8_t ndef[8];
	num_to_bytes(nfcid, 8, ndef);

	//prepare our 3 responses...
    uint8_t resp_poll0[R_POLL0_LEN] = { 0xb2,0x4d,0x12,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00,0xb3,0x7f};
    uint8_t resp_poll1[R_POLL1_LEN] = { 0xb2,0x4d,0x14,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xf1,0x00,0x00,0x00,0x01,0x43,0x00, 0x88,0xb4,0xb3,0x7f};
    uint8_t resp_readblk[R_READBLK_LEN] = { 0xb2,0x4d,0x1d,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x10,0x04,0x01,0x00,0x0d,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x23,0xcb,0x6e};
	
	//NFC tag 3/ ISo technically. Many overlapping standards
    DbpString("Felica Lite-S sim start"); 
    Dbprintf("NDEF2 UID: %02x %02x %02x %02x %02x %02x %02x %02x",
		ndef[0], ndef[1], ndef[2], ndef[3],
		ndef[4], ndef[5], ndef[6], ndef[7]
	);
    
    //fill in blanks
    for( i=0; i<8; i++) {
        resp_poll0[i+4] = ndef[i];
        resp_poll1[i+4] = ndef[i];
        resp_readblk[i+4] = ndef[i];
    }
	
    //calculate and set CRC
    SetcrcToFrame(resp_poll0);
    SetcrcToFrame(resp_poll1);
    SetcrcToFrame(resp_readblk);

    // Select correct configs
    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    // Set up the synchronous serial port
    FpgaSetupSsc();
    // connect Demodulated Signal to ADC:
    SetAdcMuxFor(GPIO_MUXSEL_HIPKD);
	
    FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | FPGA_HF_ISO18092_FLAG_NOMOD);
    SpinDelay(100);
	
    //it might be possible to use MSB?
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8)  | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    
    ResetNFCFrame();
	
    StartCountSspClk(); // should work without now, this is mostly for debugging

	bool listenmode = true;
	uint32_t frtm = GetCountSspClk();
    for(;;) {
        WDT_HIT();

        if (listenmode) {
            //waiting for request...
            if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {

				uint8_t dist = (uint8_t)(AT91C_BASE_SSC->SSC_RHR);
				frtm = GetCountSspClk();
				ProcessNFCByte(dist);
				
                if (NFCFrame.state==STATE_FULL) {

                    if (NFCFrame.crc_ok) {
                       
                        if (NFCFrame.framebytes[2] == 6 && NFCFrame.framebytes[3] == 0) {

							//polling... there are two types of polling we answer to
							if (NFCFrame.framebytes[6] == 0) {
								curresp = resp_poll0;
								curlen = R_POLL0_LEN;
								listenmode = false;
							}
							if (NFCFrame.framebytes[6]==1) {
								curresp = resp_poll1;
								curlen = R_POLL1_LEN;
								listenmode = true;
							}
                        }
						
                        if (NFCFrame.framebytes[2] > 5 && NFCFrame.framebytes[3] == 0x06) {
                            //we should rebuild it depending on page size, but...
                            //Let's see first
                            curresp = resp_readblk;
                            curlen = R_READBLK_LEN;
                            listenmode = false;
                        }
                        //clear frame
                        ResetNFCFrame();
                    } else {
                        //frame invalid, clear it out to allow for the next one
						ResetNFCFrame();
					}
				}
			}
		}
		if (!listenmode) {
			//trying to answer... here to  start answering immediately.
			//this one is a bit finicky. Seems that being a bit late is better than earlier
			TransmitFor18092_AsReader(curresp, curlen, frtm+512, 0, 0);

			//switch back
			FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | FPGA_HF_ISO18092_FLAG_NOMOD);

			ResetNFCFrame();
			listenmode = true;
			curlen = 0;
			curresp = NULL;
        }
		if( BUTTON_PRESS()) break;
    }
    
    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    DbpString("Felica Lite-S sim end");
}

int WaitForFelicaReply(int maxbytes) {
	int bcnt = 0;
	ResetNFCFrame();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | FPGA_HF_ISO18092_FLAG_NOMOD | FPGA_HF_ISO18092_FLAG_READER);
	
	for (; bcnt < maxbytes; ) {
		if (AT91C_BASE_SSC->SSC_SR & AT91C_SSC_RXRDY) {
			uint8_t dist = (uint8_t)(AT91C_BASE_SSC->SSC_RHR);
			
			ProcessNFCByte(dist);
			bcnt++;
			if (NFCFrame.state == STATE_FULL) {
				if (NFCFrame.crc_ok) {
					return 1;
				} else {
					Dbprintf("Got frame %d with wrong crc, crc %02x %02x"
						, NFCFrame.framebytes[3]
						, (NFCFrame.rolling_crc & 0xff)
						, (NFCFrame.rolling_crc >> 8)
					);
					Dbhexdump(25, NFCFrame.framebytes, false);
					return 0;
				}
				break ;
			}
		} 
	}
	return 0;
}

void HfDumpFelicaLiteS() {

	// setup device.
	FpgaDownloadAndGo(FPGA_BITSTREAM_HF);

	// connect Demodulated Signal to ADC:
	SetAdcMuxFor(GPIO_MUXSEL_HIPKD);

	// Set up the synchronous serial port
	FpgaSetupSsc();
	
	// allocate command receive buffer
	BigBuf_free(); BigBuf_Clear();

	LED_D_ON();
	
	uint8_t ndef[8];
	uint8_t poll[10] = { 0xb2,0x4d,0x06,0x00,0xff,0xff,0x00,0x00,0x09,0x21};
	uint16_t liteblks[28] = {0x00, 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x90,0x91,0x92,0xa0};
		
    if (!crc_tabccitt_init)
        init_crcccitt_tab();

    if (!manch_tbl_fill)
        fillManch();
	
    ResetNFCFrame();

	FpgaWriteConfWord(FPGA_MAJOR_MODE_ISO18092 | FPGA_HF_ISO18092_FLAG_READER |FPGA_HF_ISO18092_FLAG_NOMOD);

	AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8)  | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
	SpinDelay(100);

	// Start the timer
	StartCountSspClk();

	int c;
	int cnt = 0;
	int cntfails = 0;
	uint8_t *dest = (uint8_t *)BigBuf_get_addr();

	while (!BUTTON_PRESS() && !usb_poll_validate_length()) {
		
		WDT_HIT();
		
		TransmitFor18092_AsReader(poll, 10, GetCountSspClk()+8,1,0);
		
		if (WaitForFelicaReply(512) && NFCFrame.framebytes[3] == FELICA_POLL_ACK) {
			
			for (c=0; c < 8; c++)
				ndef[c] = NFCFrame.framebytes[c+4];
	
			for (c=0; c < 28;) {  
				BuildFliteRdblk(ndef, 1, &liteblks[c]);
				
				TransmitFor18092_AsReader(frameSpace, frameSpace[2]+4, GetCountSspClk()+8, 1, 0);
				
				if (WaitForFelicaReply(1024) && NFCFrame.framebytes[3] == FELICA_RDBLK_ACK) {

					dest[cnt++] = liteblks[c];

					uint8_t * fb = NFCFrame.framebytes;
					dest[cnt++] = fb[12];
					dest[cnt++] = fb[13];

					for(uint8_t j=0; j < 16; j++)
						dest[cnt++] = fb[15+j];

					c++;
					cntfails = 0;
				} else {
					cntfails++;
					if (cntfails > 12) {
						c++;
						cntfails = 0;
					}
				}
			}
			break; 
		}
		//SpinDelay(500);      
	}
	
	//Resetting Frame mode (First set in fpgaloader.c)	
    AT91C_BASE_SSC->SSC_RFMR = SSC_FRAME_MODE_BITS_IN_WORD(8) | AT91C_SSC_MSBF | SSC_FRAME_MODE_WORDS_PER_TRANSFER(0);
    //setting tracelen - important!  it was set by buffer overflow before
    set_tracelen(cnt);

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	cmd_send(CMD_ACK,1,0,0,0,0);
}
