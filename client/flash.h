struct partition {
	int start;
	int end;
	int precious;
	const char *name;
};

void FlushPrevious(int translate);
void GotByte(uint32_t where, uint8_t which, int start_addr, int end_addr, int translate);
unsigned int EnterFlashState(void);
int PrepareFlash(struct partition *p, const char *filename, unsigned int state);
int find_next_area(const char *str, int *offset, int *length);

#define PHYSICAL_FLASH_START 0x100000
void do_flash(char **argv);
