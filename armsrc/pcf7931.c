#include "pcf7931.h"

#define T0_PCF 8 //period for the pcf7931 in us
#define ALLOC 16

int DemodPCF7931(uint8_t **outBlocks) {

    uint8_t bits[256] = {0x00};
	uint8_t blocks[8][16];
    uint8_t *dest = BigBuf_get_addr();
    
	int GraphTraceLen = BigBuf_max_traceLen();
	if (  GraphTraceLen > 18000 )
		GraphTraceLen = 18000;
		
	int i, j, lastval, bitidx, half_switch;
	int clock = 64;
	int tolerance = clock / 8;
	int pmc, block_done;
	int lc, warnings = 0;
	int num_blocks = 0;
	int lmin=128, lmax=128;
	uint8_t dir;
	//clear read buffer
	BigBuf_Clear_keep_EM();

	LFSetupFPGAForADC(95, true);
	DoAcquisition_default(0, true);

	lmin = 64;
	lmax = 192;

	i = 2;

	/* Find first local max/min */
    if(dest[1] > dest[0]) {
		while(i < GraphTraceLen) {
            if( !(dest[i] > dest[i-1]) && dest[i] > lmax)
				break;
			i++;
		}
		dir = 0;
	}
	else {
		while(i < GraphTraceLen) {
            if( !(dest[i] < dest[i-1]) && dest[i] < lmin)
				break;
			i++;
		}
		dir = 1;
	}

	lastval = i++;
	half_switch = 0;
	pmc = 0;
	block_done = 0;

	for (bitidx = 0; i < GraphTraceLen; i++)
	{
        if ( (dest[i-1] > dest[i] && dir == 1 && dest[i] > lmax) || (dest[i-1] < dest[i] && dir == 0 && dest[i] < lmin))
		{
			lc = i - lastval;
			lastval = i;

			// Switch depending on lc length:
			// Tolerance is 1/8 of clock rate (arbitrary)
			if (ABS(lc-clock/4) < tolerance) {
				// 16T0
				if((i - pmc) == lc) { /* 16T0 was previous one */
					/* It's a PMC ! */
					i += (128+127+16+32+33+16)-1;
					lastval = i;
					pmc = 0;
					block_done = 1;
				}
				else {
					pmc = i;
				}
			} else if (ABS(lc-clock/2) < tolerance) {
				// 32TO
				if((i - pmc) == lc) { /* 16T0 was previous one */
					/* It's a PMC ! */
					i += (128+127+16+32+33)-1;
					lastval = i;
					pmc = 0;
					block_done = 1;
				}
				else if(half_switch == 1) {
                    bits[bitidx++] = 0;
					half_switch = 0;
				}
				else
					half_switch++;
			} else if (ABS(lc-clock) < tolerance) {
				// 64TO
                bits[bitidx++] = 1;
			} else {
				// Error
				warnings++;
				if (warnings > 10)
				{
					Dbprintf("Error: too many detection errors, aborting...");
					return 0;
				}
			}

			if(block_done == 1) {
				if(bitidx == 128) {
					for(j=0; j<16; j++) {
                        blocks[num_blocks][j] = 128*bits[j*8+7]+
                                64*bits[j*8+6]+
                                32*bits[j*8+5]+
                                16*bits[j*8+4]+
                                8*bits[j*8+3]+
                                4*bits[j*8+2]+
                                2*bits[j*8+1]+
                                bits[j*8];
						
					}
					num_blocks++;
				}
				bitidx = 0;
				block_done = 0;
				half_switch = 0;
			}
			if(i < GraphTraceLen)
                dir =(dest[i-1] > dest[i]) ? 0 : 1;
		}
		if(bitidx==255)
			bitidx=0;
		warnings = 0;
		if(num_blocks == 4) break;
	}
    memcpy(outBlocks, blocks, 16*num_blocks);
	return num_blocks;
}

int IsBlock0PCF7931(uint8_t *Block) {
	// Assume RFU means 0 :)
	if((memcmp(Block, "\x00\x00\x00\x00\x00\x00\x00\x01", 8) == 0) && memcmp(Block+9, "\x00\x00\x00\x00\x00\x00\x00", 7) == 0) // PAC enabled
		return 1;
	if((memcmp(Block+9, "\x00\x00\x00\x00\x00\x00\x00", 7) == 0) && Block[7] == 0) // PAC disabled, can it *really* happen ?
		return 1;
	return 0;
}

int IsBlock1PCF7931(uint8_t *Block) {
	// Assume RFU means 0 :)
	if( Block[10] == 0 && 
	    Block[11] == 0 && 
		Block[12] == 0 && 
		Block[13] == 0)
		 if ( (Block[14] & 0x7f) <= 9 && Block[15] <= 9)
			return 1;
	return 0;
}

void ReadPCF7931() {
	uint8_t Blocks[8][17];
	uint8_t tmpBlocks[4][16];
	int i, j, ind, ind2, n;
	int num_blocks = 0;
	int max_blocks = 8;
	int ident = 0;
	int error = 0;
	int tries = 0;

	memset(Blocks, 0, 8*17*sizeof(uint8_t));

	do {
		memset(tmpBlocks, 0, 4*16*sizeof(uint8_t));
		n = DemodPCF7931((uint8_t**)tmpBlocks);
		if(!n)
			error++;
		if(error==10 && num_blocks == 0) {
			Dbprintf("Error, no tag or bad tag");
			return;
		}
		else if (tries==20 || error==10) {
			Dbprintf("Error reading the tag");
			Dbprintf("Here is the partial content");
			goto end;
		}

		for(i=0; i<n; i++)
			Dbprintf("(dbg) %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
					 tmpBlocks[i][0], tmpBlocks[i][1], tmpBlocks[i][2], tmpBlocks[i][3], tmpBlocks[i][4], tmpBlocks[i][5], tmpBlocks[i][6], tmpBlocks[i][7],
					tmpBlocks[i][8], tmpBlocks[i][9], tmpBlocks[i][10], tmpBlocks[i][11], tmpBlocks[i][12], tmpBlocks[i][13], tmpBlocks[i][14], tmpBlocks[i][15]);
		if(!ident) {
			for(i=0; i<n; i++) {
				if(IsBlock0PCF7931(tmpBlocks[i])) {
					// Found block 0 ?
					if(i < n-1 && IsBlock1PCF7931(tmpBlocks[i+1])) {
						// Found block 1!
						// \o/
						ident = 1;
						memcpy(Blocks[0], tmpBlocks[i], 16);
						Blocks[0][ALLOC] = 1;
						memcpy(Blocks[1], tmpBlocks[i+1], 16);
						Blocks[1][ALLOC] = 1;
						max_blocks = MAX((Blocks[1][14] & 0x7f), Blocks[1][15]) + 1;
						// Debug print
						Dbprintf("(dbg) Max blocks: %d", max_blocks);
						num_blocks = 2;
						// Handle following blocks
						for(j=i+2, ind2=2; j!=i; j++, ind2++, num_blocks++) {
							if(j==n) j=0;
							if(j==i) break;
							memcpy(Blocks[ind2], tmpBlocks[j], 16);
							Blocks[ind2][ALLOC] = 1;
						}
						break;
					}
				}
			}
		}
		else {
			for(i=0; i<n; i++) { // Look for identical block in known blocks
				if(memcmp(tmpBlocks[i], "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16)) { // Block is not full of 00
					for(j=0; j<max_blocks; j++) {
						if(Blocks[j][ALLOC] == 1 && !memcmp(tmpBlocks[i], Blocks[j], 16)) {
							// Found an identical block
							for(ind=i-1,ind2=j-1; ind >= 0; ind--,ind2--) {
								if(ind2 < 0)
									ind2 = max_blocks;
								if(!Blocks[ind2][ALLOC]) { // Block ind2 not already found
									// Dbprintf("Tmp %d -> Block %d", ind, ind2);
									memcpy(Blocks[ind2], tmpBlocks[ind], 16);
									Blocks[ind2][ALLOC] = 1;
									num_blocks++;
									if(num_blocks == max_blocks) goto end;
								}
							}
							for(ind=i+1,ind2=j+1; ind < n; ind++,ind2++) {
								if(ind2 > max_blocks)
									ind2 = 0;
								if(!Blocks[ind2][ALLOC]) { // Block ind2 not already found
									// Dbprintf("Tmp %d -> Block %d", ind, ind2);
									memcpy(Blocks[ind2], tmpBlocks[ind], 16);
									Blocks[ind2][ALLOC] = 1;
									num_blocks++;
									if(num_blocks == max_blocks) goto end;
								}
							}
						}
					}
				}
			}
		}
		tries++;
		if (BUTTON_PRESS()) return;
	} while (num_blocks != max_blocks);
 end:
	Dbprintf("-----------------------------------------");
	Dbprintf("Memory content:");
	Dbprintf("-----------------------------------------");
	for(i=0; i<max_blocks; i++) {
		if(Blocks[i][ALLOC]==1)
			Dbprintf("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
					 Blocks[i][0], Blocks[i][1], Blocks[i][2], Blocks[i][3], Blocks[i][4], Blocks[i][5], Blocks[i][6], Blocks[i][7],
					Blocks[i][8], Blocks[i][9], Blocks[i][10], Blocks[i][11], Blocks[i][12], Blocks[i][13], Blocks[i][14], Blocks[i][15]);
		else
			Dbprintf("<missing block %d>", i);
	}
	Dbprintf("-----------------------------------------");

	cmd_send(CMD_ACK,0,0,0,0,0);
}


/* Write on a byte of a PCF7931 tag
 * @param address : address of the block to write
   @param byte : address of the byte to write
    @param data : data to write
 */
void WritePCF7931(uint8_t pass1, uint8_t pass2, uint8_t pass3, uint8_t pass4, uint8_t pass5, uint8_t pass6, uint8_t pass7, uint16_t init_delay, int32_t l, int32_t p, uint8_t address, uint8_t byte, uint8_t data)
{
	uint32_t tab[1024] = {0}; // data times frame
	uint32_t u = 0;
	uint8_t parity = 0;
	bool comp = 0;

	//BUILD OF THE DATA FRAME

	//alimentation of the tag (time for initializing)
	AddPatternPCF7931(init_delay, 0, 8192/2*T0_PCF, tab);

	//PMC
	Dbprintf("Initialization delay : %d us", init_delay);
	AddPatternPCF7931(8192/2*T0_PCF + 319*T0_PCF+70, 3*T0_PCF, 29*T0_PCF, tab);

	Dbprintf("Offsets : %d us on the low pulses width, %d us on the low pulses positions", l, p);

	//password indication bit
	AddBitPCF7931(1, tab, l, p);

	//password (on 56 bits)
	Dbprintf("Password (LSB first on each byte) : %02x %02x %02x %02x %02x %02x %02x", pass1,pass2,pass3,pass4,pass5,pass6,pass7);
	AddBytePCF7931(pass1, tab, l, p);
	AddBytePCF7931(pass2, tab, l, p);
	AddBytePCF7931(pass3, tab, l, p);
	AddBytePCF7931(pass4, tab, l, p);
	AddBytePCF7931(pass5, tab, l, p);
	AddBytePCF7931(pass6, tab, l, p);
	AddBytePCF7931(pass7, tab, l, p);


	//programming mode (0 or 1)
	AddBitPCF7931(0, tab, l, p);

	//block adress on 6 bits
	Dbprintf("Block address : %02x", address);
	for (u=0; u<6; u++)
	{
		if (address&(1<<u)) {	// bit 1
			 parity++;
			 AddBitPCF7931(1, tab, l, p);
		} else{					// bit 0
			 AddBitPCF7931(0, tab, l, p);
		}
	}

	//byte address on 4 bits
	Dbprintf("Byte address : %02x", byte);
	for (u=0; u<4; u++)
	{
		if (byte&(1<<u)) {	// bit 1
			 parity++;
			 AddBitPCF7931(1, tab, l, p);
		} else{				// bit 0
			 AddBitPCF7931(0, tab, l, p);
		}
	}

	//data on 8 bits
	Dbprintf("Data : %02x", data);
	for (u=0; u<8; u++)
	{
		if (data&(1<<u)) {	// bit 1
			 parity++;
			 AddBitPCF7931(1, tab, l, p);
		} else{				//bit 0
			 AddBitPCF7931(0, tab, l, p);
		}
	}


	//parity bit
	if((parity%2)==0){
	 	AddBitPCF7931(0, tab, l, p); //even parity
	}else{
		AddBitPCF7931(1, tab, l, p);//odd parity
	}

	//time access memory
	AddPatternPCF7931(5120+2680, 0, 0, tab);

	//conversion of the scale time
	for(u=0;u<500;u++){
		tab[u]=(tab[u] * 3)/2;
	}

	//compensation of the counter reload
	while (!comp){
		comp = 1;
		for(u=0;tab[u]!=0;u++){
			if(tab[u] > 0xFFFF){
			  tab[u] -= 0xFFFF;
			  comp = 0;
			}
		}
	}

	SendCmdPCF7931(tab);
}



/* Send a trame to a PCF7931 tags
 * @param tab : array of the data frame
 */

void SendCmdPCF7931(uint32_t * tab){
	uint16_t u=0, tempo=0;

	Dbprintf("Sending data frame...");

	FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

	FpgaSendCommand(FPGA_CMD_SET_DIVISOR, 95); //125Khz

	FpgaWriteConfWord(FPGA_MAJOR_MODE_LF_PASSTHRU );
	
	LED_A_ON();

	// steal this pin from the SSP and use it to control the modulation
	AT91C_BASE_PIOA->PIO_PER = GPIO_SSC_DOUT;
	AT91C_BASE_PIOA->PIO_OER = GPIO_SSC_DOUT;

	//initialization of the timer
	AT91C_BASE_PMC->PMC_PCER |= (0x1 << AT91C_ID_TC0);
	AT91C_BASE_TCB->TCB_BMR = AT91C_TCB_TC0XC0S_NONE | AT91C_TCB_TC1XC1S_TIOA0 | AT91C_TCB_TC2XC2S_NONE;
	AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS; // timer disable
	AT91C_BASE_TC0->TC_CMR = AT91C_TC_CLKS_TIMER_DIV3_CLOCK;  //clock at 48/32 MHz
	AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKEN;
	AT91C_BASE_TCB->TCB_BCR = 1;


	tempo = AT91C_BASE_TC0->TC_CV;
	for( u = 0; tab[u] != 0; u += 3){

		// modulate antenna
		HIGH(GPIO_SSC_DOUT);
		while(tempo != tab[u]) tempo = AT91C_BASE_TC0->TC_CV;		

		// stop modulating antenna
		LOW(GPIO_SSC_DOUT);
		while(tempo != tab[u+1]) tempo = AT91C_BASE_TC0->TC_CV;

		// modulate antenna
		HIGH(GPIO_SSC_DOUT);
		while(tempo != tab[u+2]) tempo = AT91C_BASE_TC0->TC_CV;		
	}

	LED_A_OFF();
	FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
	SpinDelay(200);

	AT91C_BASE_TC0->TC_CCR = AT91C_TC_CLKDIS; // timer disable
	LED(0xFFFF, 1000);
}


/* Add a byte for building the data frame of PCF7931 tags 
 * @param b : byte to add
 * @param tab : array of the data frame
 * @param l : offset on low pulse width
 * @param p : offset on low pulse positioning
 */

bool AddBytePCF7931(uint8_t byte, uint32_t * tab, int32_t l, int32_t p){

	uint32_t u;
	for ( u=0; u<8; u++)
	{
		if (byte&(1<<u)) {	//bit à 1
			if( AddBitPCF7931(1, tab, l, p)==1) return 1;
		} else { //bit à 0
			if (AddBitPCF7931(0, tab, l, p)==1) return 1;
		}
	}
	return 0;
}

/* Add a bits for building the data frame of PCF7931 tags 
 * @param b : bit to add
 * @param tab : array of the data frame
 * @param l : offset on low pulse width
 * @param p : offset on low pulse positioning
 */
bool AddBitPCF7931(bool b, uint32_t * tab, int32_t l, int32_t p){
	uint8_t u = 0;

	//we put the cursor at the last value of the array
	for ( u = 0; tab[u] != 0; u += 3 ) { } 
	
	if ( b == 1 ) {	//add a bit 1
		if ( u == 0 ) 
			tab[u] = 34 * T0_PCF + p;
		else
			tab[u] = 34 * T0_PCF + tab[u-1] + p;

		tab[u+1] =  6 * T0_PCF + tab[u] + l;
		tab[u+2] = 88 * T0_PCF + tab[u+1] - l - p;
		return 0;
	} else { 		//add a bit 0

		if ( u == 0 )
			tab[u] = 98 * T0_PCF + p;
		else
			tab[u] = 98 * T0_PCF + tab[u-1] + p;

		tab[u+1] =  6 * T0_PCF + tab[u] + l;
		tab[u+2] = 24 * T0_PCF + tab[u+1] - l - p;
		return 0;
	}
	return 1;
}

/* Add a custom pattern in the data frame
 * @param a : delay of the first high pulse
 * @param b : delay of the low pulse
 * @param c : delay of the last high pulse
 * @param tab : array of the data frame
 */
bool AddPatternPCF7931(uint32_t a, uint32_t b, uint32_t c, uint32_t * tab){
	uint32_t u = 0;
	for(u = 0; tab[u] != 0; u += 3){} //we put the cursor at the last value of the array

	tab[u]   = (u == 0) ? a : a + tab[u-1];
	tab[u+1] = b + tab[u];
	tab[u+2] = c + tab[u+1];

	return 0;
}