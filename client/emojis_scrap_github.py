#!/usr/bin/env python3

# Mostly derived from https://github.com/mrowa44/emojify Copyright (c) 2015 Justyna Rachowicz

from urllib.request import urlopen
import json


EMOJI_JSON_URL = 'https://raw.githubusercontent.com/github/gemoji/master/db/emoji.json'

def print_emoji(emoji_json):
    for alias in emoji_json['aliases']:
        print('    {{":{0}:", "{1}"}}, // {2}'.format(alias, 

''.join('\\x{:02x}'.format(b) for b in emoji_json['emoji'].encode('utf8')),

emoji_json['emoji']))

print(
"""#ifndef EMOJIS_H__
#define EMOJIS_H__

typedef struct emoji_s {
    const char *alias;
    const char *emoji;
} emoji_t;
// emoji_t array are expected to be NULL terminated

static emoji_t EmojiTable[] = {""")

with urlopen(EMOJI_JSON_URL) as conn:
    emojis_json = json.loads(conn.read().decode('utf-8'))
    for emoji_json in emojis_json:
        print_emoji(emoji_json)

print("""    {NULL, NULL}
};
#endif""")
