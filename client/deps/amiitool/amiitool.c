/*
 * (c) 2015-2017 Marcos Del Sol Vives
 * (c) 2016      javiMaD
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <string.h>
#include "src/fileutils.h"
#include "amiibo.h"
#include "getopt.h"

#define NTAG215_SIZE 540

static char *self;

void amiitool_usage(void) {
    fprintf(stderr,
            /*"amiitool build %i (commit %s-%08x)\n"*/
            "by Marcos Del Sol Vives <marcos@dracon.es>\n"
            "\n"
            "Usage: %s (-e|-d|-c) -k keyfile [-i input] [-s input2] [-o output]\n"
            "   -e encrypt and sign amiibo\n"
            "   -d decrypt and test amiibo\n"
            "   -c decrypt, copy AppData and encrypt amiibo\n"
            "   -k key set file. For retail amiibo, use \"retail unfixed\" key set\n"
            "   -i input file. If not specified, stdin will be used.\n"
            "   -s input save file, save from this file will replace input file ones.\n"
            "   -o output file. If not specified, stdout will be used.\n"
            "   -l decrypt files with invalid signatures.\n",
            self
           );
}

int main(int argc, char **argv) {
    self = argv[0];

    char *infile = NULL;
    char *savefile = NULL;
    char *outfile = NULL;
    char *keyfile = NULL;
    char op = '\0';
    bool lenient = false;

    int c;
    while ((c = getopt(argc, argv, "edci:s:o:k:l")) != -1) {
        switch (c) {
            case 'e':
            case 'd':
            case 'c':
                op = c;
                break;
            case 'i':
                infile = optarg;
                break;
            case 'k':
                keyfile = optarg;
                break;
            case 's':
                savefile = optarg;
                break;
            case 'o':
                outfile = optarg;
                break;
            case 'l':
                lenient = true;
                break;
            default:
                amiitool_usage();
                return 2;
        }
    }

    if (op == '\0' || keyfile == NULL) {
        amiitool_usage();
        return 1;
    }

    nfc3d_amiibo_keys amiiboKeys = {0};
    if (! LoadAmiikey(amiiboKeys, keyfile))
        return 5;

    uint8_t original[NTAG215_SIZE];
    uint8_t modified[NFC3D_AMIIBO_SIZE];

    FILE *f = stdin;
    if (infile) {
        f = fopen(infile, "rb");
        if (!f) {
            fprintf(stderr, "Could not open input file\n");
            return 3;
        }
    }
    size_t readPages = fread(original, 4, NTAG215_SIZE / 4, f);
    if (readPages < NFC3D_AMIIBO_SIZE / 4) {
        fprintf(stderr, "Could not read from input\n");
        fclose(f);
        return 3;
    }
    fclose(f);


    if (op == 'e') {
        nfc3d_amiibo_pack(&amiiboKeys, original, modified);
    } else if (op == 'd') {
        if (!nfc3d_amiibo_unpack(&amiiboKeys, original, modified)) {
            fprintf(stderr, "!!! WARNING !!!: Tag signature was NOT valid\n");
            if (!lenient) {
                return 6;
            }
        }
    } else { /* copy */
        uint8_t plain_base[NFC3D_AMIIBO_SIZE];
        uint8_t plain_save[NFC3D_AMIIBO_SIZE];

        if (!nfc3d_amiibo_unpack(&amiiboKeys, original, plain_base)) {
            fprintf(stderr, "!!! WARNING !!!: Tag signature was NOT valid\n");
            if (!lenient) {
                return 6;
            }
        }
        if (savefile) {
            f = fopen(savefile, "rb");
            if (!f) {
                fprintf(stderr, "Could not open save file\n");
                return 3;
            }
        }
        readPages = fread(original, 4, NTAG215_SIZE / 4, f);
        if (readPages < NFC3D_AMIIBO_SIZE / 4) {
            fprintf(stderr, "Could not read from save\n");
            fclose(f);
            return 3;
        }
        fclose(f);

        if (!nfc3d_amiibo_unpack(&amiiboKeys, original, plain_save)) {
            fprintf(stderr, "!!! WARNING !!!: Tag signature was NOT valid\n");
            if (!lenient) {
                return 6;
            }
        }

        nfc3d_amiibo_copy_app_data(plain_save, plain_base);
        nfc3d_amiibo_pack(&amiiboKeys, plain_base, modified);
    }

    f = stdout;
    if (outfile) {
        f = fopen(outfile, "wb");
        if (!f) {
            fprintf(stderr, "Could not open output file\n");
            return 4;
        }
    }
    if (fwrite(modified, NFC3D_AMIIBO_SIZE, 1, f) != 1) {
        fprintf(stderr, "Could not write to output\n");
        fclose(f);
        return 4;
    }
    if (readPages > NFC3D_AMIIBO_SIZE / 4) {
        if (fwrite(original + NFC3D_AMIIBO_SIZE, readPages * 4 - NFC3D_AMIIBO_SIZE, 1, f) != 1) {
            fprintf(stderr, "Could not write to output:\n");
            fclose(f);
            return 4;
        }
    }
    fclose(f);
    return 0;
}
