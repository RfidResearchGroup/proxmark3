# Note on Cliparser
<a id="Top"></a>


# Table of Contents
- [Note on Cliparser](#note-on-cliparser)
- [Table of Contents](#table-of-contents)
  - [cliparser setup and use](#cliparser-setup-and-use)
  - [design comments](#design-comments)
  - [common options](#common-options)
  - [How to implement in source code](#how-to-implement-in-source-code)
    - [setup the parser data structure](#setup-the-parser-data-structure)
    - [define the context](#define-the-context)
    - [define the options](#define-the-options)
    - [Notes:](#notes)
      - [bool option.  true if supplied](#bool-option--true-if-supplied)
      - [integer that is optional](#integer-that-is-optional)
      - [integer that is required](#integer-that-is-required)
      - [double that is optional](#double-that-is-optional)
      - [double that is required](#double-that-is-required)
      - [String option that is optional and only one instance can be provided](#string-option-that-is-optional-and-only-one-instance-can-be-provided)
      - [String option that is required and only one instance can be provided](#string-option-that-is-required-and-only-one-instance-can-be-provided)
      - [String option that is optional and can have up to 250 instances provided](#string-option-that-is-optional-and-can-have-up-to-250-instances-provided)
      - [String option that is required/at least one instance and can have up to 250 instances](#string-option-that-is-requiredat-least-one-instance-and-can-have-up-to-250-instances)
      - [unsigned integer optional](#unsigned-integer-optional)
      - [unsigned integer required](#unsigned-integer-required)
    - [show the menu](#show-the-menu)
    - [clean up](#clean-up)
    - [retrieving options](#retrieving-options)



The old style with mixed custom commandline parsing of user parameters or options was messy and confusing.  You can find all kinds in the Proxmark3 client.
Samples
```
data xxxx h
script run x.lua -h
hf 14a raw -h
hf 14b raw -ss
lf search 1
lf config h H
```
even the external tools which we collected into this repo,  under folder */tools/* folder uses their own argument parsing.


In order to counter this and unify it,  there was discussion over at the official repository a few years ago [link to issue](https://github.com/Proxmark/proxmark3/issues/467) and there it became clear a change is needed. Among the different solutions suggested @merlokk's idea of using the lib cliparser was agreed upon. The lib was adapted and implemented for commands like

```
[usb] pm3 --> emv
[usb] pm3 --> hf fido
```

And then it fell into silence since it wasn't well documented how to use the cliparser. Looking at source code wasn't very efficient. However the need of a better cli parsing was still there.

Fast forward today, where more commands has used the cliparser but it still wasn't the natural way when adding a new client command to the Proxmark3 client.
After more discussions among @doegox, @iceman1001 and @mrwalker the concept became more clear on how to use the cliparser lib in the _preferred_ way.

The aftermath was a design and layout specified which lead to a simpler implementation of the cliparser in the client source code while still unifying all helptexts with the new colours support and a defined layout. As seen below, the simplicity and clearness.

![sample of new style helptext](http://www.icedev.se/proxmark3/helptext.png)


Furthermore @mrwalker offered to take notes and thus this document was created.

This is the _new_ and _preferred_ way to implement _helptext_ and _cli parsing_ for Proxmark3 client commands and it's external tools.


## cliparser setup and use
^[Top](#top)

The parser will format and color and layout as needed.
It will also add the `-h --help` option automatic.

## design comments
^[Top](#top)

* where possible all options should be lowercase.
* extended options preceded with -- should be short
* options provided directly (without an option identifier) should be avoided.
* -vv for extra verbose should be avoided; use of debug level is preferred.
* with --options the equal is not needed (will work with and without) so don't use '='
  e.g. cmd --cn 12345



## common options
^[Top](#top)

    -h --help       : help
    --cn            : card number
    --fn            : facility number
    --q5            : target is LF T5555/Q5 card
    --em            : target is LF EM4305/4469 card
    --raw           : raw data
    -d --data       : hex data supplied
    -f --file       : filename supplied
    -k --key        : key supplied
    -n --keyno      : key number to use
    -p --pwd        : password supplied
    -v --verbose    : flag when output should provide more information, not considered debug.
    -1 --buffer     : use the sample buffer



## How to implement in source code
^[Top](#top)

### setup the parser data structure
^[Top](#top)

Header file to include

    #include "cliparser.h"

In the command function, setup the context

    CLIParserContext *ctx;


### define the context
^[Top](#top)

`CLIParserInit (\<context\>, \<description\>, \<notes\n examples ... \>);`

use -> to separate example and example comment and \\n to separate examples.
e.g. lf indala clone -r a0000000a0002021 -> this uses .....

    CLIParserInit(&ctx, "lf indala clone",
                  "clone INDALA UID to T55x7 or Q5/T5555 tag",
                  "lf indala clone --heden 888\n"
                  "lf indala clone --fc 123 --cn 1337\n"
                  "lf indala clone -r a0000000a0002021\n"
                  "lf indala clone -l -r 80000001b23523a6c2e31eba3cbee4afb3c6ad1fcf649393928c14e5");

### define the options
^[Top](#top)

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("l", "long", "optional - long UID 224 bits"),
        arg_int0("c", "heden", "<decimal>", "Cardnumber for Heden 2L format"),
        arg_str0("r", "raw", "<hex>", "raw bytes"),
        arg_lit0("q", "Q5", "optional - specify writing to Q5/T5555 tag"),
        arg_int0(NULL, "fc", "<decimal>", "Facility Code (26 bit format)"),
        arg_int0(NULL, "cn", "<decimal>", "Cardnumber (26 bit format)"),
        arg_param_end
    };

_All options has a parameter index,  since `-h --help` is added automatic, it will be assigned index 0.
Hence all options you add will start at index 1 and upwards. It added in the define "arg_param_begin_

### Notes:
^[Top](#top)

#### bool option.  true if supplied
`bool : arg_lit0 ("<short option>", "<long option>", <"description">)`

#### integer that is optional
`optional integer : arg_int0 ("<short option>", "<long option>", "<format>", <"description">)`

#### integer that is required
`required integer : arg_int1 ("<short option>", "<long option>", "<format>", <"description">)`

#### double that is optional
`optional double : arg_dbl0 ("<short option>", "<long option>", "<format>", <"description">)`

#### double that is required
`required double : arg_dbl1 ("<short option>", "<long option>", "<format>", <"description">)`

#### String option that is optional and only one instance can be provided
`optional string : arg_str0 ("<short option>", "<long option>", "<format>", <"description">)`

#### String option that is required and only one instance can be provided
`required string : arg_str1 ("<short option>", "<long option>", "<format>", <"description">)`

#### String option that is optional and can have up to 250 instances provided
`optional string : arg_strx0 ("<short option>", "<long option>", "<format>", <"description">)`

#### String option that is required/at least one instance and can have up to 250 instances
`required string : arg_strx1 ("<short option>", "<long option>", "<format>", <"description">)`

Unsigned values, like  u32 and u64 can be accomplished with

#### unsigned integer optional
`optional unsigned : arg_u64_0 ("<short option>", "<long option>", "<format>", <"description">)`

#### unsigned integer required
`required unsigned : arg_u64_1 ("<short option>", "<long option>", "<format>", <"description">)`


**if an option does not have a short or long option, use NULL in its place**


### show the menu
^[Top](#top)

`CLIExecWithReturn(\<context\>, \<command line to parse\>, \<arg/opt table\>, \<return on error\>);`

    CLIExecWithReturn(ctx, Cmd, argtable, false);

### clean up
^[Top](#top)

Once you have extracted the options, cleanup the context.

    CLIParserFree(ctx);

### retrieving options
^[Top](#top)

The parser will format and color and layout as needed.
It will also add the `-h --help` option automatic.


**bool option**
arg_get_lit(\<context\>, \<opt index\>);

    is_long_uid = arg_get_lit(ctx, 1);

**int option**
arg_get_int_def(\<context\>, \<opt index\>, \<default value\>);

    cardnumber = arg_get_int_def(ctx, 2, -1);


**uint32**
arg_get_u32_def(\<context\>, \<opt index\>, \<default value\>);

    cardnumber = arg_get_u32_def(ctx, 2, 0);

**uint64**
arg_get_u64_def(\<context\>, \<opt index\>, \<default value\>);

    cardnumber = arg_get_u64_def(ctx, 2, 0);


**hex option with return**
CLIGetHexWithReturn(\<context\>, \<opt index\>, \<store variable\>, \<ptr to stored length\>);
    ?? as an array of uint_8 ??
    If failed to retrieve hexbuff, it will exit fct

    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);


**hex option**

    uint8_t key[24] = {0};
    int keylen = 0;
    int res_klen = CLIParamHexToBuf(arg_get_str(ctx, 3), key, 24, &keylen);

    quick test : seems res_keylen == 0 when ok so not key len ???

**string option return**
CLIGetStrWithReturn(\<context\>,\<opt index\>, \<uint8_t \*\>, \<int \*\>);
    If failed to retrieve string, it will exit fct

    uint8_t buffer[100];
    int slen = sizeof(buffer); // <- slen MUST be the maximum number of characters that you want returned. e.g. Buffer Size
    CLIGetStrWithReturn(ctx, 1, buffer, &slen);

**string option**     
Getting a char array 

    int slen = 0;
    char format[16] = {0};
    int res = CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)format, sizeof(format), &slen);

    quick test : seem res == 0, then ok.  compare res == slen to see how many chars 