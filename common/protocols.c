#include <strings.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include "protocols.h"
#ifndef ON_DEVICE
#include "ui.h"
#define prnt PrintAndLog
#endif



typedef struct {
	uint8_t app_limit;      //[8]
	uint8_t otp[2];         //[9-10]
	uint8_t block_writelock;//[11]
	uint8_t chip_config;    //[12]
	uint8_t mem_config;     //[13]
	uint8_t eas;            //[14]
	uint8_t fuses;          //[15]
}picopass_conf_block;


typedef struct {
	uint8_t csn[8];
	picopass_conf_block conf;
	uint8_t epurse[8];
	uint8_t key_d[8];
	uint8_t key_c[8];
	uint8_t app_issuer_area[8];

}picopass_hdr;


//#define prnt printf
/*void prnt(char *fmt,...)
{
	va_list argptr;
	va_start(argptr, fmt);
	vprintf(fmt, argptr);
	printf("          "); // cleaning prompt
	va_end(argptr);
	printf("\n");
}
*/
uint8_t isset(uint8_t val, uint8_t mask)
{
	return (val & mask);
}

uint8_t notset(uint8_t val, uint8_t mask){
	return !(val & mask);
}

void fuse_config(const picopass_hdr *hdr)
{
	uint8_t fuses = hdr->conf.fuses;

	if (isset(fuses,FUSE_FPERS))prnt("	Mode: Personalization [Programmable]");
	else prnt("	Mode: Application [Locked]");

	if (isset(fuses, FUSE_CODING1))
		prnt("	Coding: RFU");
	else
	{
		if( isset( fuses , FUSE_CODING0)) prnt("	Coding: ISO 14443-2 B/ISO 15693");
		else prnt("	Coding: ISO 14443B only");
	}
	if( isset (fuses,FUSE_CRYPT1 | FUSE_CRYPT0 )) prnt("	Crypt: Secured page, keys not locked");
	if( isset (fuses,FUSE_CRYPT1) && notset( fuses, FUSE_CRYPT0 )) prnt("	Crypt: Secured page, keys not locked");
	if( notset (fuses,FUSE_CRYPT1) && isset( fuses, FUSE_CRYPT0 )) prnt("	Crypt: Non secured page");
	if( notset (fuses,FUSE_CRYPT1) && notset( fuses, FUSE_CRYPT0 )) prnt("	Crypt: No auth possible. Read only if RA is enabled");

	if( isset( fuses, FUSE_RA)) prnt("	RA: Read access enabled");
	else prnt("	RA: Read access not enabled");
}

void getMemConfig(uint8_t mem_cfg, uint8_t chip_cfg, uint8_t *max_blk, uint8_t *app_areas, uint8_t *kb) {
	// mem-bit 5, mem-bit 7, chip-bit 4: defines chip type
	if(isset(chip_cfg, 0x10) && notset(mem_cfg, 0x80) && notset(mem_cfg, 0x20)) {
		*kb = 2;
		*app_areas = 2;
		*max_blk = 31;
	} else if(isset(chip_cfg, 0x10) && isset(mem_cfg, 0x80) && notset(mem_cfg, 0x20)) {
		*kb = 16;
		*app_areas = 2;
		*max_blk = 255; //16kb
	} else if(notset(chip_cfg, 0x10) && notset(mem_cfg, 0x80) && notset(mem_cfg, 0x20)) {
		*kb = 16;
		*app_areas = 16;
		*max_blk = 255; //16kb
	} else if(isset(chip_cfg, 0x10) && isset(mem_cfg, 0x80) && isset(mem_cfg, 0x20)) {
		*kb = 32;
		*app_areas = 3;
		*max_blk = 255; //16kb
	} else if(notset(chip_cfg, 0x10) && notset(mem_cfg, 0x80) && isset(mem_cfg, 0x20)) {
		*kb = 32;
		*app_areas = 17;
		*max_blk = 255; //16kb
	} else {
		*kb = 32;
		*app_areas = 2;
		*max_blk = 255;
	}
}

void mem_app_config(const picopass_hdr *hdr)
{
	uint8_t mem = hdr->conf.mem_config;
	uint8_t chip = hdr->conf.chip_config;
	uint8_t applimit = hdr->conf.app_limit;
	if (applimit < 6) applimit = 26;
	uint8_t kb = 2;
	uint8_t app_areas = 2;
	uint8_t max_blk = 31;
	getMemConfig(mem, chip, &max_blk, &app_areas, &kb);
	prnt("  Mem: %u KBits/%u App Areas (%u * 8 bytes) [%02X]", kb, app_areas, max_blk, mem);
	prnt("	AA1: blocks 06-%02X", applimit);
	prnt("	AA2: blocks %02X-%02X", applimit+1, max_blk);
}
void print_picopass_info(const picopass_hdr *hdr)
{
	fuse_config(hdr);
	mem_app_config(hdr);
}
void printIclassDumpInfo(uint8_t* iclass_dump)
{
//	picopass_hdr hdr;
//	memcpy(&hdr, iclass_dump, sizeof(picopass_hdr));
	print_picopass_info((picopass_hdr *) iclass_dump);
}

/*
void test()
{
	picopass_hdr hdr = {0x27,0xaf,0x48,0x01,0xf9,0xff,0x12,0xe0,0x12,0xff,0xff,0xff,0x7f,0x1f,0xff,0x3c};
	prnt("Picopass configuration:");
	print_picopass_info(&hdr);
}
int main(int argc, char *argv[])
{
	test();
	return 0;
}
*/
