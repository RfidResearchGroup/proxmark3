#!/usr/bin/env python3

# python3 -m pip install pandas, lxml, html5lib 
import sys
import pandas as pd
import requests

ATR_URL = 'https://www.eftlab.co.uk/knowledge-base/171-atr-list-full/'

def print_atr(df):
    for i in df.index:

        a = df['atr'][i];
        b = df['desc'][i];

        if type(a) is not str or type(b) is not str:
            continue
        a = a.replace(' ','')

        if (len(a) == 0 or len(b) == 0):
            continue

        b = b.replace('\\', '\\\\')

        print(f'    {{ "{a}", "{b}" }},')



def main():
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
    static atr_t AtrTable[] = {""")

    print_atr(df)

    print("""    {NULL, "no ATR info available"}
    };

    #endif""")

if __name__ == "__main__":
    main()
