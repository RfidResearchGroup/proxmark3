# cliparser - proxmark3-rrg

## cliparser setup and use

*** Draft notes - needs work ***

Note: the parser will format and color and layout as needed.

## design comments
* where possiable all options should be lowercase.  
* extended options preceeded with -- should be short  
* options provided directly (without an option identifier) should be avoided.  
* -vv for extra verbos should be avoided; use of debug level is prefered.  
* with --options the equal is not needed (will work with and without) so dont use '='  
  e.g. cmd --cn 12345

## common options
    -h --help       : help
    --cn            : card number
    --fn            : facility number
    --q5            : target is lf q5 card
    --raw           : raw data
    -k --key        : key supplied
    -n --keyno      : key number to use
    -v --verbose    : flag when output should provide more information, not conidered debug.
    -1 --buffer     : use the sample buffer

### setup the parser data structure
Header file to include

    #include "cliparser.h"

In the command function, setup the context

    CLIParserContext *ctx;


### define the text
CLIParserInit (\<context\>, \<description\>, \<notes\n examples ... \>);

use -> to seperate example and example comment and \\n to seperate examples.
e.g. lf indala clone -r a0000000a0002021 -> this uses .....

    CLIParserInit(&ctx, "lf indala clone",                          
                  "clone INDALA UID to T55x7 or Q5/T5555 tag",      
                  "lf indala clone --heden 888\n"                   
                  "lf indala clone --fc 123 --cn 1337\n"
                  "lf indala clone -r a0000000a0002021\n"
                  "lf indala clone -l -r 80000001b23523a6c2e31eba3cbee4afb3c6ad1fcf649393928c14e5");

### define the options

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("l", "long", "optional - long UID 224 bits"),                
        arg_int0("c", "heden", "<decimal>", "Cardnumber for Heden 2L format"),  
        arg_strx0("r", "raw", "<hex>", "raw bytes"),                          
        arg_lit0("q", "Q5", "optional - specify writing to Q5/T5555 tag"),
        arg_int0(NULL, "fc", "<decimal>", "Facility Code (26 bit format)"),
        arg_int0(NULL, "cn", "<decimal>", "Cardnumber (26 bit format)"),
        arg_param_end
    };
    
**Notes:**  
booleen : arg_lit0 ("\<short option\>", "\<long option\>", \["\<format\>",\] \<"description"\>)  

**integer**  
    optional integer : arg_int0 ("\<short option\>", "\<long option\>", \["\<format\>",\] \<"description"\>)\
    required integer : arg_int1 ("\<short option\>", "\<long option\>", \["\<format\>",\] \<"description"\>)

**Strings 0 or 1**  
     optional string : arg_str0("\<short option\>", "\<long option\>", \["\<format\>",\] \<"description"\>)\
     required string : arg_str1("\<short option\>", "\<long option\>", \["\<format\>",\] \<"description"\>)

**Strings x to 250**  
    optional string : arg_strx0 ("\<short option\>", "\<long option\>", \["\<format\>",\] \<"description"\>)\
    required string : arg_strx1 ("\<short option\>", "\<long option\>", \["\<format\>",\] \<"description"\>)

**if an option does not have a short or long option, use NULL in its place**
        
### show the menu
CLIExecWithReturn(\<context\>, \<command line to parse\>, \<arg/opt table\>, \<return on error\>);

    CLIExecWithReturn(ctx, Cmd, argtable, false);

### clean up
Once you have extracted the options, cleanup the context.

   CLIParserFree(ctx);

### retreiving options
**bool option**  
arg_get_lit(\<context\>, \<opt index\>);

    is_long_uid = arg_get_lit(ctx, 1);

**int option**  
arg_get_int_def(\<context\>, \<opt index\>, \<default value\>);

    cardnumber = arg_get_int_def(ctx, 2, -1);

**hex option**  
CLIGetHexWithReturn(\<context\>, \<opt index\>, \<store variable\>, \<ptr to stored length\>);
    ?? as an array of uint_8 ??
    
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);

**hex option returning ???**  

    uint8_t key[24] = {0};
    int keylen = 0;
    int res_klen = CLIParamHexToBuf(arg_get_str(ctx, 3), key, 24, &keylen);
    quick test : seems res_keylen == 0 when ok so not key len ??? 

**string option**  
CLIGetStrWithReturn(\<context\>,\<opt index\>, \<unsigned char \*\>, \<int \*\>);

    uint8_t Buffer[100];
    int BufLen;
    CLIGetStrWithReturn(ctx,7, Buffer, &BufLen);

