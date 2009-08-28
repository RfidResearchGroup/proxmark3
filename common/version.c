#define VERSION "$Id $"
static const struct __attribute__((packed)) {
    const char string[48];
    unsigned int length;
    unsigned int magic;
} version __attribute__((unused,section("versioninformation"))) = {
    VERSION,
    sizeof(VERSION),
    0x48151623,
};
