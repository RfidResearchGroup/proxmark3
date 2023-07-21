//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// asn.1 utils
//-----------------------------------------------------------------------------

#include "asn1utils.h"
#include <ctype.h>
#include <stdlib.h>
#include <mbedtls/asn1.h>
#include <string.h>       // memcpy
#include "ui.h"           // Print...
#include "commonutil.h"   // ARRAYLEN
#include "emv/tlv.h"
#include "asn1dump.h"
#include "util.h"


int ecdsa_asn1_get_signature(uint8_t *signature, size_t signaturelen, uint8_t *rval, uint8_t *sval) {

    if (!signature || !signaturelen || !rval || !sval) {
        return PM3_EINVARG;
    }

    uint8_t *p = calloc(sizeof(uint8_t), signaturelen);
    if (p == NULL) {
        return PM3_EMALLOC;
    }

    memcpy(p, signature, signaturelen);
    uint8_t *p_tmp = p;
    const uint8_t *end = p + signaturelen;

    int res = PM3_SUCCESS;
    size_t len = 0;
    mbedtls_mpi xmpi;

    if ((res = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) == 0) {
        mbedtls_mpi_init(&xmpi);
        res = mbedtls_asn1_get_mpi(&p, end, &xmpi);
        if (res) {
            mbedtls_mpi_free(&xmpi);
            goto exit;
        }

        res = mbedtls_mpi_write_binary(&xmpi, rval, 32);
        mbedtls_mpi_free(&xmpi);
        if (res)
            goto exit;

        mbedtls_mpi_init(&xmpi);
        res = mbedtls_asn1_get_mpi(&p, end, &xmpi);
        if (res) {
            mbedtls_mpi_free(&xmpi);
            goto exit;
        }

        res = mbedtls_mpi_write_binary(&xmpi, sval, 32);
        mbedtls_mpi_free(&xmpi);
        if (res)
            goto exit;

        // check size
        if (end != p) {
            free(p_tmp);
            end = NULL;
            return PM3_ESOFT;
        }
    }

exit:
    free(p_tmp);
    end = NULL;
    return res;
}

static void asn1_print_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    bool candump = true;
    asn1_tag_dump(tlv, level, &candump);
    if (is_leaf && candump) {
        print_buffer(tlv->value, tlv->len, level + 1);
    }
}

int asn1_print(uint8_t *asn1buf, size_t asn1buflen, const char *indent) {

    struct tlvdb *t = tlvdb_parse_multi(asn1buf, asn1buflen);
    if (t) {
        tlvdb_visit(t, asn1_print_cb, NULL, 0);
        tlvdb_free(t);
    } else {
        PrintAndLogEx(ERR, "Can't parse data as TLV tree");
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}


typedef struct {
    const char *hex;
    const char *expected;
    const char *desc;
} asn1_test;

int asn1_selftest(void) {

    PrintAndLogEx(INFO, "to be implemented. Feel free to contribute!");

    /*

    ICEMAN:
    Problem to be solved,  how to extract data back from our asn1 decoder to compare with the expected text found in the following test cases.
    Thanks @Mistial for the suggestion and links.

    These test cases are from the project lapo-luchini's asn1js   (ISC license which is like MIT license)
    https://github.com/lapo-luchini/asn1js/blob/trunk/test.js


    const asn1_test tests[] = {
        // RSA Laboratories technical notes from https://luca.ntop.org/Teaching/Appunti/asn1.html
        {"0304066E5DC0", "(18 bit)\n011011100101110111", "ntop, bit string: DER encoding"},
        {"0304066E5DE0", "(18 bit)\n011011100101110111", "ntop, bit string: padded with  `100000`"},
        {"038104066E5DC0", "(18 bit)\n011011100101110111", "ntop, bit string: long form of length octets"},
        {"23090303006E5D030206C0", "(18 bit)\n011011100101110111", "ntop, bit string (constructed encoding): `0110111001011101` + `11`"},
        {"160D7465737431407273612E636F6D", "test1@rsa.com", "ntop, ia5string: DER encoding"},
        {"16810D7465737431407273612E636F6D", "test1@rsa.com", "ntop, ia5string: long form of length octets"},
        {"36131605746573743116014016077273612E636F6D", "test1@rsa.com", "ntop, ia5string: constructed encoding: `test1` + `@` + `rsa.com`"},
        {"020100", "0", "ntop, integer: 0"},
        {"02017F", "127", "ntop, integer: 127"},
        {"02020080", "128", "ntop, integer: 128"},
        {"02020100", "256", "ntop, integer: 256"},
        {"020180", "-128", "ntop, integer: -128"},
        {"0202FF7F", "-129", "ntop, integer: -129"},
        {"0500", "", "ntop, null: DER"},
        {"058100", "", "ntop, null: long form of length octets"},
        {"06062A864886F70D", "1.2.840.113549", "ntop, object identifier"},
        {"04080123456789ABCDEF", "(8 byte)\n0123456789ABCDEF", "ntop, octet string: DER encoding"},
        {"0481080123456789ABCDEF", "(8 byte)\n0123456789ABCDEF", "ntop, octet string: long form of length octets"},
        {"240C040401234567040489ABCDEF", "(8 byte)\n0123456789ABCDEF", "ntop, octet string (constructed encoding): 01…67 + 89…ef"},
        {"130B5465737420557365722031", "Test User 1", "ntop, printable string: DER encoding"},
        {"13810B5465737420557365722031", "Test User 1", "ntop, printable string: long form of length octets"},
        {"330F130554657374201306557365722031", "Test User 1", "ntop, printable string: constructed encoding: `Test ` + `User 1`"},
        {"140F636CC26573207075626C6971756573", "clés publiques", "ntop, t61string: DER encoding"},
        {"14810F636CC26573207075626C6971756573", "clés publiques", "ntop, t61string: long form of length octets"},
        {"34151405636CC2657314012014097075626C6971756573", "clés publiques", "ntop, t61string: constructed encoding: `clés` + ` ` + `publiques`"},
        {"170D3931303530363233343534305A", "1991-05-06 23:45:40 UTC", "ntop, utc time: UTC"},
        {"17113931303530363136343534302D30373030", "1991-05-06 16:45:40 UTC-07:00", "ntop, utc time: PDT"},
        // inspired by http://luca.ntop.org/Teaching/Appunti/asn1.html
        {"0304086E5DC0", "Exception:\nInvalid BitString with unusedBits=8", "bit string: invalid unusedBits"},
        // http://msdn.microsoft.com/en-us/library/windows/desktop/aa379076(v=vs.85).aspx
        {"30820319308202820201003023310F300D0603550403130654657374434E3110300E060355040A1307546573744F726730819F300D06092A864886F70D010101050003818D00308189028181008FE2412A08E851A88CB3E853E7D54950B3278A2BCBEAB54273EA0257CC6533EE882061A11756C12418E3A808D3BED931F3370B94B8CC43080B7024F79CB18D5DD66D82D0540984F89F970175059C89D4D5C91EC913D72A6B309119D6D442E0C49D7C9271E1B22F5C8DEEF0F1171ED25F315BB19CBC2055BF3A37424575DC90650203010001A08201B4301A060A2B0601040182370D0203310C160A362E302E353336312E323042060A2B0601040182370D0201313430321E260043006500720074006900660069006300610074006500540065006D0070006C0061007400651E080055007300650072305706092B0601040182371514314A30480201090C237669636833642E6A646F6D6373632E6E74746573742E6D6963726F736F66742E636F6D0C154A444F4D4353435C61646D696E6973747261746F720C07636572747265713074060A2B0601040182370D0202316630640201011E5C004D006900630072006F0073006F0066007400200045006E00680061006E006300650064002000430072007900700074006F0067007200610070006800690063002000500072006F00760069006400650072002000760031002E003003010030818206092A864886F70D01090E31753073301706092B0601040182371402040A1E08005500730065007230290603551D2504223020060A2B0601040182370A030406082B0601050507030406082B06010505070302300E0603551D0F0101FF0404030205A0301D0603551D0E041604143C0F73DAF8EF41D83AEABE922A5D2C966A7B9454300D06092A864886F70D01010505000381810047EB995ADF9E700DFBA73132C15F5C24C2E0BFC624AF15660EB86A2EAB2BC4971FE3CBDC63A525ECC7B428616636A1311BBFDDD0FCBF1794901DE55EC7115EC9559FEBA33E14C799A6CBBAA1460F39D444C4C84B760E205D6DA9349ED4D58742EB2426511490B40F065E5288327A9520A0FDF7E57D60DD72689BF57B058F6D1E",
            "(3 elem)", "PKCS#10 request"},
        // Int10
        {"02102FA176B36EE9F049F444B40099661945", "(126 bit)\n63312083136615639753586560173617846597", "Big integer (126 bit)"},
        {"028181008953097086EE6147C5F4D5FFAF1B498A3D11EC5518E964DC52126B2614F743883F64CA51377ABB530DFD20464A48BD67CD27E7B29AEC685C5D10825E605C056E4AB8EEA460FA27E55AA62C498B02D7247A249838A12ECDF37C6011CF4F0EDEA9CEE687C1CB4A51C6AE62B2EFDB000723A01C99D6C23F834880BA8B42D5414E6F",
            "(1024 bit)\n96432446964907009840023644401994013457468837455140331578268642517697945390319089463541388080569398374873228752921897678940332050406994011437231634303608704223145390228074087922901239478374991949372306413157758278029522534299413919735715864599284769202556071242381348472464716517735026291259010477833523908207",
            "Big integer (1024 bit)"},
        {"02820201009BA9ABBF614A97AF2F97669A745FD0D996FDCFE2E466EF1F1F4733C244A3DF9ADE1FB554DD157C6935116FBBC80C8E6A181ED88FD916BC1048365CF063B3905A5C2437D7A3D6CB0971B9F1017284B07DDB4D80CDFCD36FC9F8DAB60E82D24585A81B68A83DE8F4446CBDA1C2CB03BE8C3E130084DF4A48C0E3220AE8E937A7184CB1090D23567F044DD9178418A5C8DA409473EBCE0E573C03813A9D0AA1574369AC576D799078E5B5B43BD8BC4C8D28A1A7A3A7BA024E25D12AAEEDAE0322B86B200F302854957FE0EECE0A669DD1402D6E22AF9D1AC10519D26FC0F29FF87BB30242FB50A91D2D930F23ABC6C10F92FFD0A215F55309711CFF451384E6265EF8E0881C0AFC16B6A87306B8F0638402A0C65AECE774DF70AEA38325EAD6C7978793A7C68A8A33976037103E973E6E2915D6A10FD1882C129F6FAAA4C642EB41A2E39543D301856D8EBB3BF32336C7FE3BE0A1250748ABC98974FF088F80BFC09665F3EEEC4B68BD9D88C331B340F1E8CFF638BB9CE4D17FD4E5589B7CFAD4F30E9B7591E4BA522E197ED1F5CD5A19FCBA06F6FB52A84B9904DDF8F9B48B50A34E6289F08724FA8342C187FAD52D292A5A717A646AD72760630DDBCE49F58D1F90893217F87343B8D25A938661D6E1750AEA796676884F71EB0425D60A5A7A93E5B94B17400FB1B6B9F5DE4FDCE0B3AC3B117060844A436E9920C029710AC065",
            "(4096 bit)\n635048724432704421127930570668665246853305382538324205739741643121831497295424070220821366244137115920753022123888627038218427491681054376713237422498116573180444839575827154645186734602336866679804832661256616738257119870932328599495025506292424741581222812593482590762754785441060866630543522468678295806775919446210955958208696766307578451905771148370694894591388931494246786732600822191966681852303750991082312180670980233382216493445574638820565887523903118457551295241540793541306271618874366356869335229283992012581380459991160410157116077111142487644315609688092841697874946124416376553323373756926990721842430477982958383467149331238064901788481621489266725616974850293388387825359434286033332681714766010619113405542747712973535303497912234899589502990216128180823653963322406352206636893824027962569732222882297210841939793442415179615290739900774082858983244011679281115202763730964934473392333219986431517733237277686866318351054204026883453068392486990840498271719737813876367239342153571643327128417739316281558041652406500713712661305061745568036561978158652008943224271511931676512028205883718704503533046383542018858616087454820845906934069146870330990447993387221061968484774662499598623702280426558025111180066917",
            "Big integer (4096 bit)"},
        {"0202007F", "127", "Padded 127"},
        {"0202FF7F", "-129", "Negative 129"},
        {"0202FC18", "-1000", "Negative 1000 (2)"},
        {"0204FFFFFC18", "-1000", "Negative 1000 (4)"},
        {"0208FFFFFFFFFFFFFC18", "-1000", "Negative 1000 (8)"},
        {"0210FFFFFFFFFFFFFFFFFFFFFFFFFFFFFC18", "-1000", "Negative 1000 (16)"},
        {"0203800001", "-8388607", "Negative 8388607"},
        {"02020000", "0", "Zero (2)"},
        {"0204FFFFFFFF", "-1", "Negative 1 (4)"},
        // OID
        {"060C69C7C79AB78084C289F9870D", "2.25.84478768945400492475277", "Big OID arc"},
        {"06146982968D8D889BCCA8C7B3BDD4C080AAAED78A1B", "2.25.184830721219540099336690027854602552603", "Bigger OID arc"},
        {"060488378952", "2.999.1234", "OID arc > 2.47"},
        {"060782A384F3CAC00A", "2.9999999999930", "OID with Int10 corner case (1)"},
        {"060881E3AFEAA69A800A", "2.999999999999930", "OID with Int10 corner case (2)"},
        {"06092A864886F70D010105", "1.2.840.113549.1.1.5\nsha1WithRSAEncryption\nPKCS #1", "known OID from Peter Gutmann list"},
        // OID corner case from https://misc.daniel-marschall.de/asn.1/oid-sizecheck/oid_size_test.txt
        {"060A81FFFFFFFFFFFFFFFF7F", "2.18446744073709551535", "OID root 64 bit - 1"},
        {"060A82808080808080808000", "2.18446744073709551536", "OID root 64 bit"},
        {"060A82808080808080808001", "2.18446744073709551537", "OID root 64 bit + 1"},
        {"0620FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7F",   "2.26959946667150639794667015087019630673637144422540572481103610249135", "OID derLen20c"},
        {"0621818080808080808080808080808080808080808080808080808080808080808000", "2.26959946667150639794667015087019630673637144422540572481103610249136", "OID derLen21c"},
        // relative OID
        {"0D0A0102030405060708090A","1.2.3.4.5.6.7.8.9.10", "Relative OID from GitHub PR 56"},
        {"0D04C27B0302","8571.3.2", "Relative OID from ISO/IEC 8825-1:2002 8.20.5"},
        // UTF-8
        {"0C0E4C61706FE280997320F09F9A972E", "Lapo’s 🚗.", "UTF-8 4-byte sequence"},
        // T-REC-X.690-201508
        {"0307040A3B5F291CD0", "(44 bit)\n00001010001110110101111100101001000111001101", "Example 8.6.4.2: bit string (primitive encoding)"},
        {"23800303000A3B0305045F291CD00000", "(44 bit)\n00001010001110110101111100101001000111001101", "Example 8.6.4.2: bit string (constructed encoding)"},
        // avoid past bugs
        {"23800303000A3B230A0302005F030404291CD00000", "(44 bit)\n00001010001110110101111100101001000111001101", "Bit string (recursive constructed)"},
        {"0348003045022100DE601E573DAFB59BC551D58E3E7B9EDA0612DD0112805A2217B734759B884417022067C3FDE60780D41C1D7A3B90291F3D39C4DC2F206DCCBA2F982C06B67C09B232", "(568 bit)\n0011000001000101000000100010000100000000110111100110000000011110010101110011110110101111101101011001101111000101010100011101010110001110001111100111101110011110110110100000011000010010110111010000000100010010100000000101101000100010000101111011011100110100011101011001101110001000010001000001011100000010001000000110011111000011111111011110011000000111100000001101010000011100000111010111101000111011100100000010100100011111001111010011100111000100110111000010111100100000011011011100110010111010001011111001100000101100000001101011011001111100000010011011001000110010", "not constructed, but contains structures"},
        {"040731323334353637", "(7 byte)\n1234567", "Octet string with ASCII content"},
        {"0407312E3233E282AC", "(7 byte)\n1.23€", "Octet string with UTF-8 content"},
        // GitHub issue #47
        {"0420041EE4E3B7ED350CC24D034E436D9A1CB15BB1E328D37062FB82E84618AB0A3C", "(32 byte)\n041EE4E3B7ED350CC24D034E436D9A1CB15BB1E328D37062FB82E84618AB0A3C", "Do not mix encapsulated and structured octet strings"},
        // GitHub issue #54
        {"181531393835313130363231303632372E332D31323334", "1985-11-06 21:06:27.3 UTC-12:34", "UTC offsets with minutes"},
        // GitHub issue #54
        {"181331393835313130363231303632372E332B3134", "1985-11-06 21:06:27.3 UTC+14:00", "UTC offset +13 and +14"},
        };

    int tot = ARRAYLEN(tests);

    PrintAndLogEx(INFO,"ASN1 decoder selftest.  {%d tests}", tot);
    int count = 0;
    for (int i=0; i< ARRAYLEN(tests); i++) {
        size_t n = strlen(tests[i].hex) * 2;

        uint8_t *d = calloc(n, sizeof(uint8_t));
        if (d == NULL) {
            return PM3_EMALLOC;
        }
        int len = 0;
        param_gethex_to_eol(tests[i].hex, 0, d, n, &len);
        if (len == 0) {
            free(d);
            continue;
        }

        PrintAndLogEx(INFO, "%s [%d: %s]", tests[i].desc, len, sprint_hex_inrow(d, len));


        struct tlvdb *t = tlvdb_parse_multi((const unsigned char*)n, len);
        if (t) {
            bool candump = false;
            if (asn1_tag_dump(&t->tag, 0, &candump)) {
                count++;
            }
            tlvdb_free(t);
        }
        free(d);
    }


    PrintAndLogEx(SUCCESS, "Pass... %s", (count == tot) ? _GREEN_("ok") : _RED_("fail"));
    PrintAndLogEx(NORMAL, "");

    */

    return PM3_SUCCESS;
}
