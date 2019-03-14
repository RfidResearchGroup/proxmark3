//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Hitag2, HitagS
//
// (c) 2012 Roel Verdult
// (c) 2016 Oguzhan Cicek, Hendrik Schwartke, Ralf Spenneberg
//     <info@os-s.de>
//-----------------------------------------------------------------------------


#ifndef HITAG_H__
#define HITAG_H__

#ifdef _MSC_VER
#define PACKED
#else
#define PACKED __attribute__((packed))
#endif

typedef enum {
    RHTSF_CHALLENGE           = 01,
    RHTSF_KEY                 = 02,
    WHTSF_CHALLENGE           = 03,
    WHTSF_KEY                 = 04,
    RHT2F_PASSWORD            = 21,
    RHT2F_AUTHENTICATE        = 22,
    RHT2F_CRYPTO              = 23,
    WHT2F_CRYPTO              = 24,
    RHT2F_TEST_AUTH_ATTEMPTS  = 25,
    RHT2F_UID_ONLY            = 26,
} hitag_function;

typedef struct {
    uint8_t password[4];
} PACKED rht2d_password;

typedef struct {
    uint8_t NrAr[8];
    uint8_t data[4];
} PACKED rht2d_authenticate;

typedef struct {
    uint8_t key[6];
    uint8_t data[4];
} PACKED rht2d_crypto;

typedef union {
    rht2d_password     pwd;
    rht2d_authenticate auth;
    rht2d_crypto       crypto;
} hitag_data;


//---------------------------------------------------------
// Hitag S
//---------------------------------------------------------
// protocol-state
typedef enum PROTO_STATE {
    HT_READY = 0,
    HT_INIT,
    HT_AUTHENTICATE,
    HT_SELECTED,
    HT_QUIET,
    HT_TTF,
    HT_FAIL
} PSTATE;

typedef enum TAG_STATE {
    HT_NO_OP = 0,
    HT_READING_PAGE,
    HT_WRITING_PAGE_ACK,
    HT_WRITING_PAGE_DATA,
    HT_WRITING_BLOCK_DATA
} TSATE;

//number of start-of-frame bits
typedef enum SOF_TYPE {
    HT_STANDARD = 0,
    HT_ADVANCED,
    HT_FAST_ADVANCED,
    HT_ONE,
    HT_NO_BITS
} stype;

struct hitagS_tag {
    PSTATE   pstate;  //protocol-state
    TSATE    tstate;  //tag-state
    uint32_t uid;
    uint8_t  pages[64][4];
    uint64_t key;
    uint8_t  pwdl0, pwdl1, pwdh0;
    //con0
    int      max_page;
    stype    mode;
    //con1
    bool     auth;   //0=Plain 1=Auth
    bool     TTFC;   //Transponder Talks first coding. 0=Manchester 1=Biphase
    int      TTFDR;  //data rate in TTF Mode
    int      TTFM;   //the number of pages that are sent to the RWD
    bool     LCON;   //0=con1/2 read write 1=con1 read only and con2 OTP
    bool     LKP;    //0=page2/3 read write 1=page2/3 read only in Plain mode and no access in authenticate mode
    //con2
    //0=read write 1=read only
    bool     LCK7;   //page4/5
    bool     LCK6;   //page6/7
    bool     LCK5;   //page8-11
    bool     LCK4;   //page12-15
    bool     LCK3;   //page16-23
    bool     LCK2;   //page24-31
    bool     LCK1;   //page32-47
    bool     LCK0;   //page48-63
};

#endif
