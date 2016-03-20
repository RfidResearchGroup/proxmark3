//Data elements for EMV transactions.
#include <stdint.h>
#ifndef __EMVDATAELS_H
#define __EMVDATAELS_H
#include "emvdataels.h"
//Known AIDs

typedef struct{
uint8_t tag[2];
char description[255];
}tagdescription;

const uint8_t AID_VISA[]    =   {0xa0,0x00,0x00,0x00,0x03};
const uint8_t AID_VISA_DB[] =   {0xa0,0x00,0x00,0x00,0x03,0x10,0x10};
const uint8_t AID_VISA_C[]  =   {0xa0,0x00,0x00,0x00,0x03,0x10,0x10,0x01};
const uint8_t AID_VISA_D[]  =   {0xa0,0x00,0x00,0x00,0x03,0x10,0x10,0x02};
const uint8_t AID_VISA_E[]  =   {0xa0,0x00,0x00,0x00,0x03,0x20,0x10};
const uint8_t AID_VISA_I[]  =   {0xa0,0x00,0x00,0x00,0x03,0x30,0x10};
const uint8_t AID_VISA_P[]  =   {0xa0,0x00,0x00,0x00,0x03,0x80,0x10};
const uint8_t AID_VISA_ATM[]=   {0xa0,0x00,0x00,0x00,0x03,0x99,0x99,0x10};
const uint8_t AID_MASTERCARD[]= {0xa0,0x00,0x00,0x00,0x04,0x10,0x10};
const uint8_t AID_MAESTRO[] =   {0xa0,0x00,0x00,0x00,0x04,0x30,0x60};
const uint8_t AID_MAESTRO_UK[]= {0xa0,0x00,0x00,0x00,0x05,0x00,0x01};
const uint8_t AID_MAESTRO_TEST[]={0xb0,0x12,0x34,0x56,0x78};
const uint8_t AID_SELF_SERVICE[]={0xa0,0x00,0x00,0x00,0x24,0x01};
const uint8_t AID_AMEX[]      = {0xa0,0x00,0x00,0x00,0x25};
const uint8_t AID_EXPRESSPAY[]= {0xa0,0x00,0x00,0x00,0x25,0x01,0x07,0x01};
const uint8_t AID_LINK[]      = {0xa0,0x00,0x00,0x00,0x29,0x10,0x10};
const uint8_t AID_ALIAS[]     = {0xa0,0x00,0x00,0x00,0x29,0x10,0x10};

//Master data file for PSE
//const uint8_t DF_PSE[]      =   {0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31};
const uint8_t DF_PSE[]      =   {0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31};

//TAGS

//SW1 return values
const uint8_t SW1_RESPONSE_BYTES[] = {0x61};
const uint8_t SW1_WRONG_LENGTH[] = {0x6c};
const uint8_t SW12_OK[] = {0x90,0x00};
const uint8_t SW12_NOT_SUPPORTED[] = {0x6a,0x81};
const uint8_t SW12_NOT_FOUND[] = {0x6a,0x82};
const uint8_t SW12_COND_NOT_SAT[] = {0x69,0x83};
const uint8_t PIN_BLOCKED[] = {0x69,0x84};
const uint8_t PIN_BLOCKED2[] = {0x69,0x84};
const uint8_t PIN_WRONG[] = {0x63};

const tagdescription EMV_TAG_LIST[] = {
    {"\x4f\x00","Application Identifier (AID)"},
    {"\x50\x00","Application Label"},
    {"\x57\x00","Track 2 Equivalent Data"},
    {"\x5a\x00","Application Primary Account Number (PAN)"},
    {"\x6f\x00","File Control Information (FCI) Template"},
    {"\x70\x00","Record Template"},
    {"\x77\x00","response message template format 2"},
    {"\x80\x00","response message template format 1"},
    {"\x82\x00","application interchange profile"},
    {"\x83\x00","command template"},
    {"\x84\x00","df name"},
    {"\x86\x00","issuer script command"},
    {"\x87\x00","application priority indicator"},
    {"\x88\x00","short file identifier"},
    {"\x8a\x00","authorisation response code"},
    {"\x8c\x00","card risk management data object list 1 (cdol1)"},
    {"\x8d\x00","card risk management data object list 2 (cdol2)"},
    {"\x8e\x00","cardholder verification method (cvm) list"},
    {"\x8f\x00","certification authority public key index"},
    {"\x93\x00","signed static application data"},
    {"\x94\x00","application file locator"},
    {"\x95\x00","terminal verification results"},
    {"\x97\x00","transaction certificate data object list (tdol)",},
    {"\x9c\x00","transaction type"},
    {"\x9d\x00","directory definition file"},
    {"\xa5\x00","proprietary information"},
    {"\x5f\x20","cardholder name"},
    {"\x5f\x24","application expiration date yymmdd"},
    {"\x5f\x25","application effective date yymmdd"},
    {"\x5f\x28","issuer country code"},
    {"\x5f\x2a","transaction currency code"},
    {"\x5f\x2d","language preference"},
    {"\x5f\x30","service code"},
    {"\x5f\x34","application primary account number (pan) sequence number"},
    {"\x5f\x50","issuer url"},
    {"\x92\x00","issuer public key remainder"},
    {"\x9a\x00","transaction date"},
    {"\x9f\x02","amount, authorised (numeric)"},
    {"\x9f\x03","amount, other (numeric)"},
    {"\x9f\x04","amount, other (binary)"},
    {"\x9f\x05","application discretionary data"},
    {"\x9f\x07","application usage control"},
    {"\x9f\x08","application version number"},
    {"\x9f\x0d","issuer action code - default"},
    {"\x9f\x0e","issuer action code - denial"},
    {"\x9f\x0f","issuer action code - online"},
    {"\x9f\x11","issuer code table index"},
    {"\x9f\x12","application preferred name"},
    {"\x9f\x1a","terminal country code"},
    {"\x9f\x1f","track 1 discretionary data"},
    {"\x9f\x20","track 2 discretionary data"},
    {"\x9f\x26","application cryptogram"},
    {"\x9f\x32","issuer public key exponent"},
    {"\x9f\x36","application transaction counter"},
    {"\x9f\x37","unpredictable number"},
    {"\x9f\x38","processing options data object list (pdol)"},
    {"\x9f\x42","application currency code"},
    {"\x9f\x44","application currency exponent"},
    {"\x9f\x4a","static data authentication tag list"},
    {"\x9f\x4d","log entry"},
    {"\x9f\x66","card production life cycle"},
    {"\xbf\x0c","file control information (fci) issuer discretionary data"}
};

//AIP bitmasks details
#define AIP_CHIP_SUPPORTED 0x80
#define AIP_MSR_SUPPORTED 0x40

#define AIP_SDA_SUPPORTED 0x40
#define AIP_DDA_SUPPORTED 0x20
#define AIP_CARDHOLDER_VERIFICATION 0x10
#define AIP_TERMINAL_RISK 0x08
#define AIP_ISSUER_AUTH 0x04
#define AIP_CDA_SUPPORTED 0x01
 
//human readable error messages


#endif //__EMVDATAELS_H
