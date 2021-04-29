#ifndef EMOJIS_ALT_H__
#define EMOJIS_ALT_H__

typedef struct emoji_alt_s {
    const char *alias;
    const char *alttext;
} emoji_alt_t;
// emoji_alt_t array are expected to be NULL terminated

static emoji_alt_t EmojiAltTable[] = {
    {":wink:", ";)"},
    {NULL, NULL}
};

#endif
