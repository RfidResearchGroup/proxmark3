#!/usr/bin/env python3

# python3 -m pip install pandas, lxml, html5lib 
import sys
import pandas as pd
import requests
import re

ATR_URL = 'https://www.eftlab.co.uk/knowledge-base/171-atr-list-full/'

def print_atr(df):
    for i in df.index:

        a = df['atr'][i];
        b = df['desc'][i];

        if type(a) is not str or type(b) is not str:
            continue

        a = a.replace(' ','')
        a = a.replace('…', '..')

        if (len(a) == 0 or len(b) == 0):
            continue


        b = b.replace('\\', '\\\\')
        b = b.replace('’', '\'')
        b = b.replace('‘', '\'')
        b = b.replace('“', '\'')
        b = b.replace('”', '\'')
        b = b.replace('ó', 'o')
        b = b.replace('ú', 'u')
        b = b.replace('–', '-')
        b = b.replace('—', '-')        
        b = b.replace('€', '')
        b = b.replace('Č', 'C')
        b = b.replace('á', 'a')
        b = b.replace('ř', 'r')
        b = b.replace('ę', 'e')
        b = b.replace('ł', 'l')
        b = b.replace('İ', 'I')
        b = b.replace('…', '...')
        
        #b = re.sub('[^A-Za-zs ]+', '', b)

        print(f'    {{ "{a}", "{b}" }},')



def main():

    # making sure we print UTF-8
    sys.stdout = open(1, 'w', encoding='utf-8', closefd=False)

    r = requests.get(ATR_URL)
    r.status_code
    list_atr = pd.read_html(r.text, header=0, keep_default_na=False)
    df = list_atr[0]
    df.columns = ['atr', 'desc']
    df = df.astype('string')

    print(
    """#ifndef ATRS_H__

#define ATRS_H__

#include <stddef.h>

typedef struct atr_s {
    const char *bytes;
    const char *desc;
} atr_t;

const char *getAtrInfo(const char *atr_str);

// atr_t array are expected to be NULL terminated
const static atr_t AtrTable[] = {
    { "3BDF18FFC080B1FE751F033078464646462026204963656D616E1D", "Cardhelper by 0xFFFF and Iceman" },""")

    print_atr(df)

    print("""    {NULL, "N/A"}
};

#endif""")

if __name__ == "__main__":
    main()
