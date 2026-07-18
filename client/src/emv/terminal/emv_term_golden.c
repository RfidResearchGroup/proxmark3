//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_golden.h"
#include "emv_terminal.h"
#include "emv_term_mock.h"
#include "emv_term_scheme.h"
#include "emv_term_profile.h"
#include "emv_term_load.h"
#include "emv_term_host.h"
#include "emv_term_arqc.h"
#include "phase_taa.h"
#include "ui.h"
#include "fileutils.h"
#include "util.h"
#include <jansson.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>

static const char *FIXTURE_SUBPATHS[] = {
    "client/src/emv/test/fixtures",
    "src/emv/test/fixtures",
    NULL,
};

static int fixtures_root(char *out, size_t outlen) {
    for (int i = 0; FIXTURE_SUBPATHS[i]; i++) {
        if (fileExists(FIXTURE_SUBPATHS[i])) {
            str_copy(out, outlen, FIXTURE_SUBPATHS[i]);
            return PM3_SUCCESS;
        }
    }
    return PM3_ESOFT;
}

static void fixture_path(const char *root, const char *name, const char *file, char *out, size_t outlen) {
    if (!out || outlen == 0) {
        return;
    }
    size_t pos = 0;
    pos += str_copy(out + pos, outlen - pos, root);
    if (pos + 1 < outlen) {
        out[pos++] = '/';
        out[pos] = '\0';
    }
    pos += str_copy(out + pos, outlen - pos, name);
    if (pos + 1 < outlen) {
        out[pos++] = '/';
        out[pos] = '\0';
    }
    str_copy(out + pos, outlen - pos, file);
}

static bool read_expected_str(json_t *root, const char *key, char *out, size_t outlen) {
    json_t *j = json_object_get(root, key);
    if (!json_is_string(j)) {
        return false;
    }
    str_copy(out, outlen, json_string_value(j));
    return true;
}

static bool outcome_matches(const char *expected, emv_term_outcome_t actual) {
    if (!expected || !expected[0]) {
        return true;
    }
    return strcmp(expected, emv_term_outcome_str(actual)) == 0;
}

static bool requested_ac_matches(json_t *expected, const emv_term_ctx_t *ctx) {
    json_t *j = json_object_get(expected, "RequestedAC");
    if (!json_is_string(j)) {
        return true;
    }
    const char *want = json_string_value(j);
    uint8_t ac = ctx->requested_ac;
    if (strcmp(want, "aac") == 0) {
        return ac == EMVAC_AAC_BYTE;
    }
    if (strcmp(want, "arqc") == 0) {
        return ac == EMVAC_ARQC_BYTE;
    }
    if (strcmp(want, "tc") == 0) {
        return ac == EMVAC_TC_BYTE;
    }
    return false;
}

static bool phases_match(json_t *expected, const emv_term_ctx_t *ctx, bool verbose, const char *fixture) {
    json_t *exp_phases = json_object_get(expected, "Phases");
    if (!json_is_array(exp_phases)) {
        return true;
    }

    size_t n = json_array_size(exp_phases);
    for (size_t i = 0; i < n; i++) {
        json_t *ep = json_array_get(exp_phases, i);
        if (!json_is_object(ep)) {
            continue;
        }
        json_t *jname = json_object_get(ep, "name");
        json_t *jres = json_object_get(ep, "result");
        if (!json_is_string(jname) || !json_is_integer(jres)) {
            continue;
        }
        const char *pname = json_string_value(jname);
        int want_res = (int)json_integer_value(jres);
        bool found = false;
        for (size_t j = 0; j < ctx->event_count; j++) {
            if (strcmp(emv_term_phase_name(ctx->events[j].id), pname) == 0) {
                found = true;
                if (ctx->events[j].result != want_res) {
                    if (verbose) {
                        PrintAndLogEx(ERR, "[%s] phase %s result want=%d got=%d",
                                      fixture, pname, want_res, ctx->events[j].result);
                    }
                    return false;
                }
                break;
            }
        }
        if (!found) {
            if (verbose) {
                PrintAndLogEx(ERR, "[%s] missing phase event: %s", fixture, pname);
            }
            return false;
        }
    }
    return true;
}

static bool cryptogram_type_matches(json_t *expected, const emv_term_ctx_t *ctx) {
    json_t *crypto = json_object_get(expected, "Cryptogram");
    if (!json_is_object(crypto)) {
        return true;
    }
    json_t *jtype = json_object_get(crypto, "Type");
    if (!json_is_string(jtype)) {
        return true;
    }
    const char *want = json_string_value(jtype);
    uint8_t cid = ctx->ac1_cid ? ctx->ac1_cid : ctx->requested_ac;
    uint8_t ctype = cid & 0xC0;
    if (strcmp(want, "AAC") == 0) {
        return ctype == EMVAC_AAC_BYTE;
    }
    if (strcmp(want, "ARQC") == 0) {
        return ctype == EMVAC_ARQC_BYTE;
    }
    if (strcmp(want, "TC") == 0) {
        return ctype == EMVAC_TC_BYTE;
    }
    return true;
}

static int compare_expected(json_t *expected, const emv_term_ctx_t *ctx, bool verbose, const char *fixture) {
    char outcome[32] = {0};
    read_expected_str(expected, "Outcome", outcome, sizeof(outcome));
    if (!outcome_matches(outcome, ctx->outcome)) {
        if (verbose) {
            PrintAndLogEx(ERR, "[%s] outcome want=%s got=%s",
                          fixture, outcome[0] ? outcome : "(any)",
                          emv_term_outcome_str(ctx->outcome));
        }
        return PM3_ESOFT;
    }
    if (!requested_ac_matches(expected, ctx)) {
        if (verbose) {
            PrintAndLogEx(ERR, "[%s] RequestedAC mismatch (got %02x)", fixture, ctx->requested_ac);
        }
        return PM3_ESOFT;
    }
    if (!phases_match(expected, ctx, verbose, fixture)) {
        return PM3_ESOFT;
    }
    if (!cryptogram_type_matches(expected, ctx)) {
        if (verbose) {
            PrintAndLogEx(ERR, "[%s] Cryptogram.Type mismatch", fixture);
        }
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int run_phases_fixture(const char *dir, const char *name, json_t *run, json_t *expected, bool verbose) {
    json_t *phases = json_object_get(run, "phases");
    if (!json_is_array(phases)) {
        PrintAndLogEx(ERR, "[%s] run.json missing phases array", name);
        return PM3_ESOFT;
    }

    char card_path[FILE_PATH_SIZE];
    fixture_path(dir, name, "card_tlv.json", card_path, sizeof(card_path));
    if (!fileExists(card_path)) {
        PrintAndLogEx(ERR, "[%s] card_tlv.json required for phases mode", name);
        return PM3_ESOFT;
    }

    char exc_path[FILE_PATH_SIZE] = {0};
    char pin_buf[16] = {0};
    emv_term_cli_opts_t opts = {0};

    json_t *jexc = json_object_get(run, "exception_file");
    if (json_is_string(jexc)) {
        fixture_path(dir, name, json_string_value(jexc), exc_path, sizeof(exc_path));
        opts.exception_file = exc_path;
    }
    json_t *jpin = json_object_get(run, "pin");
    if (json_is_string(jpin)) {
        str_copy(pin_buf, sizeof(pin_buf), json_string_value(jpin));
        opts.pin = pin_buf;
    }
    if (json_is_true(json_object_get(run, "cvm_skip_online"))) {
        opts.cvm_skip_online = true;
    }

    emv_term_ctx_t ctx;
    int res = emv_term_ctx_init(&ctx, &opts);
    if (res) {
        return res;
    }

    res = emv_term_cli_setup(&ctx);
    if (res) {
        emv_term_ctx_free(&ctx);
        return res;
    }

    res = emv_term_load_card_tlv(&ctx, card_path);
    if (res) {
        emv_term_ctx_free(&ctx);
        return res;
    }

    size_t np = json_array_size(phases);
    for (size_t i = 0; i < np; i++) {
        json_t *jp = json_array_get(phases, i);
        if (!json_is_string(jp)) {
            continue;
        }
        const char *pname = json_string_value(jp);
        emv_term_phase_t phase = EMV_PHASE_COUNT;
        for (emv_term_phase_t p = EMV_PHASE_INIT; p < EMV_PHASE_COUNT; p++) {
            if (strcmp(pname, emv_term_phase_name(p)) == 0) {
                phase = p;
                break;
            }
        }
        if (phase >= EMV_PHASE_COUNT) {
            PrintAndLogEx(ERR, "[%s] unknown phase '%s'", name, pname);
            emv_term_ctx_free(&ctx);
            return PM3_EINVARG;
        }
        res = emv_terminal_step(&ctx, phase);
        if (res) {
            emv_term_ctx_free(&ctx);
            return res;
        }
    }

    res = compare_expected(expected, &ctx, verbose, name);
    emv_term_ctx_free(&ctx);
    return res;
}

static int run_scheme_fixture(const char *dir, const char *name, json_t *run, json_t *expected, bool verbose) {
    (void)dir;
    const char *profile = "auto";
    json_t *jprof = json_object_get(run, "profile");
    if (json_is_string(jprof)) {
        profile = json_string_value(jprof);
    }

    uint8_t aid[APDU_AID_LEN] = {0};
    size_t aid_len = 0;
    json_t *jaid = json_object_get(run, "aid");
    if (!json_is_string(jaid)) {
        PrintAndLogEx(ERR, "[%s] scheme mode requires aid hex", name);
        return PM3_EINVARG;
    }
    int buflen = 0;
    if (param_gethex_to_eol(json_string_value(jaid), 0, aid, sizeof(aid), &buflen)) {
        return PM3_EINVARG;
    }
    aid_len = (size_t)buflen;

    emv_term_scheme_info_t info;
    int res = emv_term_scheme_resolve(profile, aid, aid_len, &info);
    if (res) {
        return res;
    }

    char want_scheme[32] = {0};
    if (!read_expected_str(expected, "Scheme", want_scheme, sizeof(want_scheme))) {
        PrintAndLogEx(ERR, "[%s] session_expected.json missing Scheme", name);
        return PM3_ESOFT;
    }
    if (strcmp(want_scheme, info.name) != 0) {
        if (verbose) {
            PrintAndLogEx(ERR, "[%s] scheme want=%s got=%s", name, want_scheme, info.name);
        }
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int run_host_crypto_fixture(const char *dir, const char *name, json_t *expected, bool verbose) {
    char vec_path[FILE_PATH_SIZE];
    fixture_path(dir, name, "vector.json", vec_path, sizeof(vec_path));

    json_error_t error;
    json_t *vec = json_load_file(vec_path, 0, &error);
    if (!vec) {
        PrintAndLogEx(ERR, "[%s] vector.json load error: %s", name, error.text);
        return PM3_ESOFT;
    }

    uint8_t ac_mk[16] = {0};
    uint8_t cdol1[256] = {0};
    uint8_t arqc[16] = {0};
    uint8_t arc[2] = {0x30, 0x30};
    size_t cdol1_len = 0;
    size_t arqc_len = 0;
    uint16_t atc = 0;

    json_t *j = json_object_get(vec, "ACMasterKey");
    int hexlen = 0;
    if (!json_is_string(j) || param_gethex_to_eol(json_string_value(j), 0, ac_mk, sizeof(ac_mk), &hexlen)) {
        json_decref(vec);
        return PM3_ESOFT;
    }
    j = json_object_get(vec, "ATC");
    if (json_is_string(j)) {
        uint8_t atc_b[2] = {0};
        hexlen = 0;
        param_gethex_to_eol(json_string_value(j), 0, atc_b, 2, &hexlen);
        atc = (atc_b[0] << 8) | atc_b[1];
    } else if (json_is_integer(j)) {
        atc = (uint16_t)json_integer_value(j);
    }
    j = json_object_get(vec, "CDOL1");
    if (!json_is_string(j) || param_gethex_to_eol(json_string_value(j), 0, cdol1, sizeof(cdol1), (int *)&cdol1_len)) {
        json_decref(vec);
        return PM3_ESOFT;
    }

    uint8_t sk[16] = {0};
    emv_term_sk_derive_ac(ac_mk, atc, sk);

    j = json_object_get(vec, "ARQC");
    if (json_is_string(j)) {
        hexlen = 0;
        if (param_gethex_to_eol(json_string_value(j), 0, arqc, sizeof(arqc), &hexlen)) {
            json_decref(vec);
            return PM3_ESOFT;
        }
        arqc_len = (size_t)hexlen;
    } else {
        emv_term_retail_mac_3des(sk, cdol1, cdol1_len, arqc);
        arqc_len = 8;
    }
    j = json_object_get(vec, "ARC");
    if (json_is_string(j)) {
        hexlen = 0;
        param_gethex_to_eol(json_string_value(j), 0, arc, 2, &hexlen);
    }

    bool verify_ok = emv_term_arqc_verify(sk, cdol1, cdol1_len, arqc, arqc_len);
    json_t *jexp = json_object_get(expected, "ARQCVerify");
    if (json_is_string(jexp)) {
        bool want = strcmp(json_string_value(jexp), "ok") == 0;
        if (verify_ok != want) {
            if (verbose) {
                PrintAndLogEx(ERR, "[%s] ARQC verify want=%s got=%s",
                              name, want ? "ok" : "fail", verify_ok ? "ok" : "fail");
            }
            json_decref(vec);
            return PM3_ESOFT;
        }
    }

    uint8_t arpc[16] = {0};
    size_t arpc_len = 0;
    if (!emv_term_arpc_compute(EMV_ARPC_CVN18, sk, arqc, arqc_len, arc, 2, arpc, &arpc_len)) {
        json_decref(vec);
        return PM3_ESOFT;
    }

    j = json_object_get(vec, "ExpectedARPC");
    if (json_is_string(j)) {
        uint8_t exp_arpc[16] = {0};
        size_t exp_len = 0;
        param_gethex_to_eol(json_string_value(j), 0, exp_arpc, sizeof(exp_arpc), (int *)&exp_len);
        if (exp_len != arpc_len || memcmp(exp_arpc, arpc, arpc_len) != 0) {
            if (verbose) {
                PrintAndLogEx(ERR, "[%s] ARPC want=%s got=%s",
                              name, json_string_value(j), sprint_hex(arpc, arpc_len));
            }
            json_decref(vec);
            return PM3_ESOFT;
        }
    }

    json_decref(vec);
    return PM3_SUCCESS;
}

static int run_profile_validate_fixture(const char *dir, const char *name, json_t *run, bool verbose) {
    (void)dir;
    json_t *jprof = json_object_get(run, "profile");
    if (!json_is_string(jprof)) {
        PrintAndLogEx(ERR, "[%s] profile_validate mode requires profile path", name);
        return PM3_EINVARG;
    }
    int res = emv_term_profile_validate(json_string_value(jprof));
    if (res && verbose) {
        PrintAndLogEx(ERR, "[%s] profile validate failed", name);
    }
    return res;
}

static int run_mock_fixture(const char *dir, const char *name, json_t *run, json_t *expected, bool verbose) {
    char mock_path[FILE_PATH_SIZE];
    fixture_path(dir, name, "mock_apdu.json", mock_path, sizeof(mock_path));
    if (!fileExists(mock_path)) {
        PrintAndLogEx(ERR, "[%s] mock_apdu.json missing", name);
        return PM3_ESOFT;
    }

    emv_term_cli_opts_t opts = {0};
    opts.mock_apdu = mock_path;
    opts.param_load_json = true;
    opts.use_terminal_profile = true;
    opts.auto_online = json_is_true(json_object_get(run, "auto_online"));
    opts.host_sim = json_is_true(json_object_get(run, "host_sim"));

    json_t *jprof = json_object_get(run, "profile");
    if (json_is_string(jprof)) {
        opts.scheme_profile = json_string_value(jprof);
    }
    json_t *jkeys = json_object_get(run, "host_keys");
    if (json_is_string(jkeys)) {
        opts.host_keys = json_string_value(jkeys);
    }

    emv_term_ctx_t ctx;
    int res = emv_term_ctx_init(&ctx, &opts);
    if (res) {
        return res;
    }
    res = emv_term_cli_setup(&ctx);
    if (res) {
        emv_term_ctx_free(&ctx);
        emv_term_mock_clear();
        return res;
    }

    char prof_path[FILE_PATH_SIZE];
    fixture_path(dir, name, "terminal_profile.json", prof_path, sizeof(prof_path));
    if (fileExists(prof_path)) {
        ctx.opts.profile_path = prof_path;
    }

    res = emv_terminal_run(&ctx);
    if (res == PM3_SUCCESS || res == 1) {
        res = compare_expected(expected, &ctx, verbose, name);
    }
    emv_term_ctx_free(&ctx);
    emv_term_mock_clear();
    return res;
}

static int run_single_fixture(const char *root, const char *name, bool verbose) {
    char exp_path[FILE_PATH_SIZE];
    char run_path[FILE_PATH_SIZE];
    fixture_path(root, name, "session_expected.json", exp_path, sizeof(exp_path));

    if (!fileExists(exp_path)) {
        if (verbose) {
            PrintAndLogEx(INFO, "Skipping %s (no session_expected.json)", name);
        }
        return PM3_SUCCESS;
    }

    json_error_t error;
    json_t *expected = json_load_file(exp_path, 0, &error);
    if (!expected) {
        PrintAndLogEx(ERR, "[%s] expected json error: %s", name, error.text);
        return PM3_ESOFT;
    }

    fixture_path(root, name, "run.json", run_path, sizeof(run_path));
    json_t *run = json_load_file(run_path, 0, &error);
    const char *mode = "mock";
    if (run) {
        json_t *jmode = json_object_get(run, "mode");
        if (json_is_string(jmode)) {
            mode = json_string_value(jmode);
        }
    } else if (fileExists(run_path)) {
        json_decref(expected);
        return PM3_ESOFT;
    }

    int res = PM3_ESOFT;
    if (strcmp(mode, "phases") == 0) {
        res = run_phases_fixture(root, name, run, expected, verbose);
    } else if (strcmp(mode, "scheme") == 0) {
        res = run_scheme_fixture(root, name, run, expected, verbose);
    } else if (strcmp(mode, "host_crypto") == 0) {
        res = run_host_crypto_fixture(root, name, expected, verbose);
    } else if (strcmp(mode, "profile_validate") == 0) {
        res = run_profile_validate_fixture(root, name, run, verbose);
    } else if (strcmp(mode, "mock") == 0) {
        res = run_mock_fixture(root, name, run ? run : json_object(), expected, verbose);
    } else {
        PrintAndLogEx(ERR, "[%s] unknown run mode '%s'", name, mode);
        res = PM3_EINVARG;
    }

    if (run) {
        json_decref(run);
    }
    json_decref(expected);

    if (res == PM3_SUCCESS && verbose) {
        PrintAndLogEx(SUCCESS, "[%s] OK", name);
    }
    return res;
}

int emv_term_golden_run(const char *fixture_name, bool verbose) {
    if (!fixture_name || !fixture_name[0]) {
        return PM3_EINVARG;
    }

    char root[FILE_PATH_SIZE];
    if (fixtures_root(root, sizeof(root)) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Fixtures directory not found");
        return PM3_ESOFT;
    }

    return run_single_fixture(root, fixture_name, verbose);
}

int emv_term_golden_run_all(bool verbose) {
    char root[FILE_PATH_SIZE];
    if (fixtures_root(root, sizeof(root)) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Fixtures directory not found");
        return PM3_ESOFT;
    }

    DIR *d = opendir(root);
    if (!d) {
        PrintAndLogEx(ERR, "Cannot open fixtures dir: %s", root);
        return PM3_ESOFT;
    }

    size_t total = 0;
    size_t passed = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        char subpath[FILE_PATH_SIZE];
        fixture_path(root, ent->d_name, "session_expected.json", subpath, sizeof(subpath));
        if (!fileExists(subpath)) {
            continue;
        }
        total++;
        if (run_single_fixture(root, ent->d_name, verbose) == PM3_SUCCESS) {
            passed++;
        } else if (verbose) {
            PrintAndLogEx(FAILED, "[%s] FAIL", ent->d_name);
        }
    }
    closedir(d);

    if (total == 0) {
        PrintAndLogEx(WARNING, "Golden: no fixtures found");
        return PM3_ESOFT;
    }

    if (passed == total) {
        PrintAndLogEx(SUCCESS, "Golden: %zu/%zu OK", passed, total);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Golden: %zu/%zu OK", passed, total);
    return PM3_ESOFT;
}
