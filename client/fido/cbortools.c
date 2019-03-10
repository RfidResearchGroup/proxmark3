//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Tools for work with CBOR format http://cbor.io/spec.html
// via Intel tinycbor (https://github.com/intel/tinycbor) library
//-----------------------------------------------------------------------------
//

#include "cbortools.h"
#include <stdlib.h>
#include "emv/emvjson.h"
#include "util.h"
#include "fidocore.h"

static void indent(int nestingLevel) {
    while (nestingLevel--)
        printf("  ");
}

static CborError dumpelm(CborValue *it, bool *got_next, int nestingLevel) {
    CborError err;
    *got_next = false;

    CborType type = cbor_value_get_type(it);
    indent(nestingLevel);
    switch (type) {
        case CborMapType:
        case CborArrayType: {
            printf(type == CborArrayType ? "Array[" : "Map[");
            break;
        }

        case CborIntegerType: {
            int64_t val;
            cbor_value_get_int64(it, &val);     // can't fail
            printf("%lld", (long long)val);
            break;
        }

        case CborByteStringType: {
            uint8_t *buf;
            size_t n;
            err = cbor_value_dup_byte_string(it, &buf, &n, it);
            *got_next = true;
            if (err)
                return err;     // parse error
            printf("%s", sprint_hex(buf, n));
            free(buf);
            break;
        }

        case CborTextStringType: {
            char *buf;
            size_t n;
            err = cbor_value_dup_text_string(it, &buf, &n, it);
            *got_next = true;
            if (err)
                return err;     // parse error
            printf("%s", buf);
            free(buf);
            break;
        }

        case CborTagType: {
            CborTag tag;
            cbor_value_get_tag(it, &tag);
            printf("Tag(%lld)", (long long)tag);
            break;
        }

        case CborSimpleType: {
            uint8_t type;
            cbor_value_get_simple_type(it, &type);
            printf("simple(%u)", type);
            break;
        }

        case CborNullType:
            printf("null");
            break;

        case CborUndefinedType:
            printf("undefined");
            break;

        case CborBooleanType: {
            bool val;
            cbor_value_get_boolean(it, &val);       // can't fail
            printf("%s", val ? "true" : "false");
            break;
        }

        case CborDoubleType: {
            double val;
            if (false) {
                float f;
                case CborFloatType:
                    cbor_value_get_float(it, &f);
                    val = f;
                } else {
                    cbor_value_get_double(it, &val);
                }
                printf("%g", val);
                break;
            }
        case CborHalfFloatType: {
            uint16_t val;
            cbor_value_get_half_float(it, &val);
            printf("__f16(%04x)", val);
            break;
        }

        case CborInvalidType:
            printf("CborInvalidType!!!");
            break;
    }

    return CborNoError;
}

static CborError dumprecursive(uint8_t cmdCode, bool isResponse, CborValue *it, bool isMapType, int nestingLevel) {
    int elmCount = 0;
    while (!cbor_value_at_end(it)) {
        CborError err;
        CborType type = cbor_value_get_type(it);
//printf("^%x^", type);
        bool got_next;

        switch (type) {
            case CborMapType:
            case CborArrayType: {
                // recursive type
                CborValue recursed;
                assert(cbor_value_is_container(it));
                if (!(isMapType && (elmCount % 2)))
                    indent(nestingLevel);
                printf(type == CborArrayType ? "Array[\n" : "Map[\n");
                err = cbor_value_enter_container(it, &recursed);
                if (err)
                    return err;       // parse error
                err = dumprecursive(cmdCode, isResponse, &recursed, (type == CborMapType), nestingLevel + 1);
                if (err)
                    return err;       // parse error
                err = cbor_value_leave_container(it, &recursed);
                if (err)
                    return err;       // parse error
                indent(nestingLevel);
                printf("]");
                got_next = true;
                break;
            }

            default: {
                err = dumpelm(it, &got_next, (isMapType && (elmCount % 2)) ? 0 : nestingLevel);
                if (err)
                    return err;
                if (cmdCode > 0 && nestingLevel == 1 && isMapType && !(elmCount % 2)) {
                    int64_t val;
                    cbor_value_get_int64(it, &val);
                    char *desc = fido2GetCmdMemberDescription(cmdCode, isResponse, val);
                    if (desc)
                        printf(" (%s)", desc);
                }
                break;
            }
        }

        if (!got_next) {
            err = cbor_value_advance_fixed(it);
            if (err)
                return err;
        }
        if (isMapType && !(elmCount % 2)) {
            printf(": ");
        } else {
            printf("\n");
        }
        elmCount++;
    }
    return CborNoError;
}

int TinyCborInit(uint8_t *data, size_t length, CborValue *cb) {
    CborParser parser;
    CborError err = cbor_parser_init(data, length, 0, &parser, cb);
    if (err)
        return err;

    return 0;
}

int TinyCborPrintFIDOPackage(uint8_t cmdCode, bool isResponse, uint8_t *data, size_t length) {
    CborValue cb;
    int res;
    res = TinyCborInit(data, length, &cb);
    if (res)
        return res;

    CborError err = dumprecursive(cmdCode, isResponse, &cb, false, 0);

    if (err) {
        fprintf(stderr,
#if __WORDSIZE == 64
                "CBOR parsing failure at offset %" PRId64 " : %s\n",
#else
                "CBOR parsing failure at offset %" PRId32 " : %s\n",
#endif
                cb.ptr - data, cbor_error_string(err));
        return 1;
    }

    return 0;
}

int JsonObjElmCount(json_t *elm) {
    int res = 0;
    const char *key;
    json_t *value;

    if (!json_is_object(elm))
        return 0;

    json_object_foreach(elm, key, value) {
        if (strlen(key) > 0 && key[0] != '.')
            res++;
    }

    return res;
}

int JsonToCbor(json_t *elm, CborEncoder *encoder) {
    if (!elm || !encoder)
        return 1;

    int res;

    // CBOR map == JSON object
    if (json_is_object(elm)) {
        CborEncoder map;
        const char *key;
        json_t *value;

        res = cbor_encoder_create_map(encoder, &map, JsonObjElmCount(elm));
        cbor_check(res);

        json_object_foreach(elm, key, value) {
            if (strlen(key) > 0 && key[0] != '.') {
                res = cbor_encode_text_stringz(&map, key);
                cbor_check(res);

                // RECURSION!
                JsonToCbor(value, &map);
            }
        }

        res = cbor_encoder_close_container(encoder, &map);
        cbor_check(res);
    }

    // CBOR array == JSON array
    if (json_is_array(elm)) {
        size_t index;
        json_t *value;
        CborEncoder array;

        res = cbor_encoder_create_array(encoder, &array, json_array_size(elm));
        cbor_check(res);

        json_array_foreach(elm, index, value) {
            // RECURSION!
            JsonToCbor(value, &array);
        }

        res = cbor_encoder_close_container(encoder, &array);
        cbor_check(res);
    }

    if (json_is_boolean(elm)) {
        res = cbor_encode_boolean(encoder, json_is_true(elm));
        cbor_check(res);
    }

    if (json_is_integer(elm)) {
        res = cbor_encode_int(encoder, json_integer_value(elm));
        cbor_check(res);
    }

    if (json_is_real(elm)) {
        res = cbor_encode_float(encoder, json_real_value(elm));
        cbor_check(res);
    }

    if (json_is_string(elm)) {
        const char *val = json_string_value(elm);
        if (CheckStringIsHEXValue(val)) {
            size_t datalen = 0;
            uint8_t data[4096] = {0};
            res = JsonLoadBufAsHex(elm, "$", data, sizeof(data), &datalen);
            if (res)
                return 100;

            res = cbor_encode_byte_string(encoder, data, datalen);
            cbor_check(res);
        } else {
            res = cbor_encode_text_stringz(encoder, val);
            cbor_check(res);
        }
    }



    return 0;
}

int CborMapGetKeyById(CborParser *parser, CborValue *map, uint8_t *data, size_t dataLen, int key) {
    CborValue cb;

    CborError err = cbor_parser_init(data, dataLen, 0, parser, &cb);
    cbor_check(err);

    if (cbor_value_get_type(&cb) != CborMapType)
        return 1;

    err = cbor_value_enter_container(&cb, map);
    cbor_check(err);

    int64_t indx;
    while (!cbor_value_at_end(map)) {
        // check number
        if (cbor_value_get_type(map) != CborIntegerType)
            return 1;

        cbor_value_get_int64(map, &indx);

        err = cbor_value_advance(map);
        cbor_check(err);

        if (indx == key)
            return 0;

        // pass value
        err = cbor_value_advance(map);
        cbor_check(err);
    }

    err = cbor_value_leave_container(&cb, map);
    cbor_check(err);

    return 2;
}

CborError CborGetArrayBinStringValue(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen) {
    return CborGetArrayBinStringValueEx(elm, data, maxdatalen, datalen, NULL, 0);
}

CborError CborGetArrayBinStringValueEx(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen, uint8_t *delimeter, size_t delimeterlen) {
    CborValue array;
    if (datalen)
        *datalen = 0;

    size_t slen = maxdatalen;
    size_t totallen = 0;

    CborError res = cbor_value_enter_container(elm, &array);
    cbor_check(res);

    while (!cbor_value_at_end(&array)) {
        res = cbor_value_copy_byte_string(&array, &data[totallen], &slen, &array);
        cbor_check(res);

        totallen += slen;
        if (delimeter) {
            memcpy(&data[totallen], delimeter, delimeterlen);
            totallen += delimeterlen;
        }
        slen = maxdatalen - totallen;
    }

    res = cbor_value_leave_container(elm, &array);
    cbor_check(res);

    if (datalen)
        *datalen = totallen;

    return CborNoError;
};

CborError CborGetBinStringValue(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen) {
    if (datalen)
        *datalen = 0;

    size_t slen = maxdatalen;

    CborError res = cbor_value_copy_byte_string(elm, data, &slen, elm);
    cbor_check(res);

    if (datalen)
        *datalen = slen;

    return CborNoError;
};

CborError CborGetArrayStringValue(CborValue *elm, char *data, size_t maxdatalen, size_t *datalen, char *delimeter) {
    CborValue array;
    if (datalen)
        *datalen = 0;

    size_t slen = maxdatalen;
    size_t totallen = 0;

    CborError res = cbor_value_enter_container(elm, &array);
    cbor_check(res);

    while (!cbor_value_at_end(&array)) {
        res = cbor_value_copy_text_string(&array, &data[totallen], &slen, &array);
        cbor_check(res);

        totallen += slen;
        if (delimeter) {
            strcat(data, delimeter);
            totallen += strlen(delimeter);
        }
        slen = maxdatalen - totallen;
        data[totallen] = 0x00;
    }

    res = cbor_value_leave_container(elm, &array);
    cbor_check(res);

    if (datalen)
        *datalen = totallen;

    return CborNoError;
};

CborError CborGetStringValue(CborValue *elm, char *data, size_t maxdatalen, size_t *datalen) {
    if (datalen)
        *datalen = 0;

    size_t slen = maxdatalen;

    CborError res = cbor_value_copy_text_string(elm, data, &slen, elm);
    cbor_check(res);

    if (datalen)
        *datalen = slen;

    return CborNoError;
};

CborError CborGetStringValueBuf(CborValue *elm) {
    static char stringBuf[2048];
    memset(stringBuf, 0x00, sizeof(stringBuf));

    return CborGetStringValue(elm, stringBuf, sizeof(stringBuf), NULL);
};

int CBOREncodeElm(json_t *root, char *rootElmId, CborEncoder *encoder) {
    json_t *elm = NULL;
    if (rootElmId && strlen(rootElmId) && rootElmId[0] == '$')
        elm = json_path_get(root, rootElmId);
    else
        elm = json_object_get(root, rootElmId);

    if (!elm)
        return 1;

    int res = JsonToCbor(elm, encoder);

    return res;
}

CborError CBOREncodeClientDataHash(json_t *root, CborEncoder *encoder) {
    uint8_t buf[100] = {0};
    size_t jlen;

    JsonLoadBufAsHex(root, "$.ClientDataHash", buf, sizeof(buf), &jlen);

    // fill with 0x00 if not found
    if (!jlen)
        jlen = 32;

    int res = cbor_encode_byte_string(encoder, buf, jlen);
    cbor_check(res);

    return 0;
}
