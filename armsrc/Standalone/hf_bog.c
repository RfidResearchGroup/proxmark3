//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for standalone HF Sniff (and ULC/NTAG/ULEV1 pwd storing)
//-----------------------------------------------------------------------------
#include "hf_bog.h"

#define DELAY_READER_AIR2ARM_AS_SNIFFER (2 + 3 + 8) 
#define DELAY_TAG_AIR2ARM_AS_SNIFFER (3 + 14 + 8) 
#define MAX_PWDS_PER_SESSION 15

uint8_t ReadCounterFromFlash() {
	uint8_t mem = 0;

	uint8_t isok = Flash_ReadData(0, &mem, 1);
	if (isok == 1)
	{
		return mem;
	}
	
	Dbprintf("Reading of counter from flashmem failed");
	return -1;
}

uint8_t* ReadDataFromFlash(uint8_t datacnt) {

    uint16_t isok = 0;
	
	if (!datacnt)
	{
		uint8_t *tmp = BigBuf_malloc(4);
		for (int i=0;i<4;i++)
			tmp[i] = 0x00;
		return tmp;
	}
	
	size_t size = (datacnt + 1) * 4;
	uint8_t *mem = BigBuf_malloc(size);
	
	isok = Flash_ReadData(0, mem, (datacnt + 1) * 4);
	if (isok == ((datacnt + 1) * 4))
	{
		Dbprintf("[OK] Data recovered from flashmem");
		return mem;
	}

	Dbprintf("FlashMem reading failed | isok = %d", isok);
	SpinDelay(100);
	return 0;
}

/*
void WriteDataToFlash(uint8_t *data, size_t size)
{
    uint8_t isok = 0;
	
	isok = Flash_WriteData(0, data, size);

	if (!isok)
	{
		Dbprintf("FlashMem write failed");
		SpinDelay(100);

		return;
	}

    Dbprintf("[OK] Data written to flash!");
}
*/

void EraseMemory()
{
    if (!FlashInit()){
        return;
    }
    
    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();
    Flash_Erase4k(0,0);

    Dbprintf("[OK] Erased flash!");
    FlashStop();
	SpinDelay(100);
}


void WriteDataToFlash(uint8_t* data, size_t size)
{
    uint8_t isok = 0;
    uint16_t res = 0;
    uint32_t len = size;
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining = len;

    uint8_t buff[PAGESIZE];

    if (!FlashInit()){
        return;
    }
    
    Flash_CheckBusy(BUSY_TIMEOUT);
    Flash_WriteEnable();
    Flash_Erase4k(0,0);

    while (bytes_remaining > 0)
    {
		Flash_CheckBusy(BUSY_TIMEOUT);
		Flash_WriteEnable();

        uint32_t bytes_in_packet = MIN(FLASH_MEM_BLOCK_SIZE, bytes_remaining);

        memcpy(buff, data + bytes_sent, bytes_in_packet);

        bytes_remaining -= bytes_in_packet;
        res = Flash_WriteDataCont(bytes_sent, buff, bytes_in_packet);
        bytes_sent += bytes_in_packet;

        isok = (res == bytes_in_packet) ? 1 : 0;

        if (!isok)
        {
            Dbprintf("FlashMem write failed [offset %u]", bytes_sent);
            SpinDelay(100);

            return;
        }
    }

    Dbprintf("[OK] Data written to flash! [0-to offset %u]", bytes_sent);
    FlashStop();

    return;
}

void RAMFUNC SniffAndStore(uint8_t param) {
	
	// Array to store the authpwds
	uint8_t *capturedPwds = BigBuf_malloc(4 * MAX_PWDS_PER_SESSION);
	
	SpinDelay(500);

	/* This is actually copied from SniffIso14443a */
	
	iso14443a_setup(FPGA_HF_ISO14443A_SNIFFER);
	
	// Allocate memory from BigBuf for some buffers
	// free all previous allocations first
	BigBuf_free(); BigBuf_Clear_ext(false);
	clear_trace();
	set_tracing(true);
	
	// The command (reader -> tag) that we're receiving.
	uint8_t *receivedCmd = BigBuf_malloc(MAX_FRAME_SIZE);
	uint8_t *receivedCmdPar = BigBuf_malloc(MAX_PARITY_SIZE);
	
	// The response (tag -> reader) that we're receiving.
	uint8_t *receivedResp = BigBuf_malloc(MAX_FRAME_SIZE);
	uint8_t *receivedRespPar = BigBuf_malloc(MAX_PARITY_SIZE);
	
	// The DMA buffer, used to stream samples from the FPGA
	uint8_t *dmaBuf = BigBuf_malloc(DMA_BUFFER_SIZE);
	uint8_t *data = dmaBuf;

	uint8_t previous_data = 0;
	int dataLen = 0;
	bool TagIsActive = false;
	bool ReaderIsActive = false;
	
	// Set up the demodulator for tag -> reader responses.
	DemodInit(receivedResp, receivedRespPar);
	
	// Set up the demodulator for the reader -> tag commands
	UartInit(receivedCmd, receivedCmdPar);
	
	// Setup and start DMA.
	if ( !FpgaSetupSscDma((uint8_t*) dmaBuf, DMA_BUFFER_SIZE) ){
		if (MF_DBGLEVEL > 1) Dbprintf("FpgaSetupSscDma failed. Exiting"); 
		return;
	}
	
	tUart* uart = GetUart();
	tDemod* demod = GetDemod();
	
	// We won't start recording the frames that we acquire until we trigger;
	// a good trigger condition to get started is probably when we see a
	// response from the tag.
	// triggered == false -- to wait first for card
	bool triggered = !(param & 0x03); 
	
	uint32_t rsamples = 0;
	
	// Current captured passwords counter
	uint8_t auth_attempts = 0;

	SpinDelay(50);
	
	// loop and listen
	while (!BUTTON_PRESS()) {
        WDT_HIT();
        LED_A_ON();
		
		int register readBufDataP = data - dmaBuf;
		int register dmaBufDataP = DMA_BUFFER_SIZE - AT91C_BASE_PDC_SSC->PDC_RCR;
		if (readBufDataP <= dmaBufDataP)
			dataLen = dmaBufDataP - readBufDataP;
		else
			dataLen = DMA_BUFFER_SIZE - readBufDataP + dmaBufDataP;
		
		// test for length of buffer
		if (dataLen > DMA_BUFFER_SIZE) { // TODO: Check if this works properly
			Dbprintf("[!] blew circular buffer! | datalen %u", dataLen);
			break;
		}
		if (dataLen < 1) continue;

		// primary buffer was stopped( <-- we lost data!
		if (!AT91C_BASE_PDC_SSC->PDC_RCR) {
			AT91C_BASE_PDC_SSC->PDC_RPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RCR = DMA_BUFFER_SIZE;
			//Dbprintf("[-] RxEmpty ERROR | data length %d", dataLen); // temporary
		}
		// secondary buffer sets as primary, secondary buffer was stopped
		if (!AT91C_BASE_PDC_SSC->PDC_RNCR) {
			AT91C_BASE_PDC_SSC->PDC_RNPR = (uint32_t) dmaBuf;
			AT91C_BASE_PDC_SSC->PDC_RNCR = DMA_BUFFER_SIZE;
		}

		LED_A_OFF();
		
		// Need two samples to feed Miller and Manchester-Decoder
		if (rsamples & 0x01) {

			if (!TagIsActive) {		// no need to try decoding reader data if the tag is sending
				uint8_t readerdata = (previous_data & 0xF0) | (*data >> 4);
				if (MillerDecoding(readerdata, (rsamples-1)*4)) {
					LED_C_ON();

					// check - if there is a short 7bit request from reader
					if ((!triggered) && (param & 0x02) && (uart->len == 1) && (uart->bitCount == 7)) triggered = true;

					if (triggered) {
						if ((receivedCmd) && ((receivedCmd[0] == MIFARE_ULEV1_AUTH) || (receivedCmd[0] == MIFARE_ULC_AUTH_1))) {
							Dbprintf("PWD-AUTH KEY: 0x%02x%02x%02x%02x", receivedCmd[1], receivedCmd[2], receivedCmd[3], receivedCmd[4]);
							
							// temporarily save the captured pwd in our array
							memcpy(&capturedPwds[4 * auth_attempts], receivedCmd+1, 4);
							auth_attempts++;
						}
						
						if (!LogTrace(receivedCmd, 
										uart->len, 
										uart->startTime*16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
										uart->endTime*16 - DELAY_READER_AIR2ARM_AS_SNIFFER,
										uart->parity, 
										true)) break;
					}
					/* ready to receive another command. */
					UartReset();
					/* reset the demod code, which might have been */
					/* false-triggered by the commands from the reader. */
					DemodReset();
					LED_B_OFF();
				}
				ReaderIsActive = (uart->state != STATE_UNSYNCD);
			}

			// no need to try decoding tag data if the reader is sending - and we cannot afford the time
			if (!ReaderIsActive) {		
				uint8_t tagdata = (previous_data << 4) | (*data & 0x0F);
				if (ManchesterDecoding(tagdata, 0, (rsamples-1)*4)) {
					LED_B_ON();

					if (!LogTrace(receivedResp, 
									demod->len, 
									demod->startTime*16 - DELAY_TAG_AIR2ARM_AS_SNIFFER, 
									demod->endTime*16 - DELAY_TAG_AIR2ARM_AS_SNIFFER,
									demod->parity,
									false)) break;

					if ((!triggered) && (param & 0x01)) triggered = true;

					// ready to receive another response.
					DemodReset();
					// reset the Miller decoder including its (now outdated) input buffer
					UartReset();
					//UartInit(receivedCmd, receivedCmdPar);
					LED_C_OFF();
				} 
				TagIsActive = (demod->state != DEMOD_UNSYNCD);
			}
		}

		previous_data = *data;
		rsamples++;
		data++;
		if (data == dmaBuf + DMA_BUFFER_SIZE) {
			data = dmaBuf;
		}
	} // end main loop

	FpgaDisableSscDma();
	set_tracing(false);
	
	Dbprintf("Stopped sniffing");
	
	SpinDelay(200);
	
	// Write stuff to flash
	if (auth_attempts > 0) {
		Dbprintf("[!] auth_attempts = %u", auth_attempts);
		
		// Read from flash the counter of pwds (to be used as flash mem offset)
		uint8_t pwdcnt = 0;
		pwdcnt = ReadCounterFromFlash();
		if (pwdcnt == 255) {
			// Same as zero
			pwdcnt = 0;
		}
		Dbprintf("[!] PWDs Offset = %u", pwdcnt);
		
		uint8_t *previousdata = ReadDataFromFlash(pwdcnt);
		
		// total size = (pwdcnt+1)*4 + 4 * auth_attempts
		size_t total_size = (pwdcnt+1)*4 + 4 * auth_attempts;
		// create new bigbuf to hold all data
		uint8_t *total_data = BigBuf_malloc(total_size);
		
		// Add the previousdata array into total_data array
		memcpy(total_data, previousdata, sizeof(*previousdata) * ((pwdcnt+1)*4));
		
		// Copy bytes of capturedPwds immediately following bytes of previousdata
		memcpy(total_data + ((pwdcnt+1)*4), capturedPwds, sizeof(*capturedPwds) * (4 * auth_attempts));
		
		// change the counter byte
		//memset (total_data,pwdcnt + auth_attempts,1);
		total_data[0] = (uint8_t)(pwdcnt + auth_attempts);
		
		//EraseMemory();
		
		//for (int i=0;i<(pwdcnt+1)*4 + 4 * auth_attempts;i++)
		//	Dbprintf("[!] total_data[%d] = 0x%02x", i, total_data[i]);
		
		//Flash_WriteData(0, total_data, (pwdcnt+1)*4 + 4 * auth_attempts);
		WriteDataToFlash(total_data, (pwdcnt+1)*4 + 4 * auth_attempts);
		
		SpinDelay(200);
	}
}

void RunMod()
{
	Dbprintf("Sniffing started");
    SpinDelay(500);
	
	// param:
	// bit 0 - trigger from first card answer
	// bit 1 - trigger from first reader 7-bit request	
	SniffAndStore(0);
	
	LEDsoff();
	
	SpinDelay(300);
}

