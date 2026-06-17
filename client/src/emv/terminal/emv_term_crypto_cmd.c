//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — crypto playground CLI
//-----------------------------------------------------------------------------

#include "emv_term_crypto_cmd.h"
#include "emv_term_crypto.h"
#include "emv_term_crypto_digest.h"
#include "emv_term_probe.h"
#include "emv_term_profile.h"
#include "emv_term_tlv.h"
#include "../emvcore.h"
#include "emv_transaction.h"
#include "emv_term_session.h"
#include "../emvcore.h"
#include "cliparser.h"
#include "cmdparser.h"
#include "ui.h"
#include "commonutil.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    bool activate;
    bool show_apdu;
    bool decode_tlv;
    bool wired;
    bool jload;
    const char *session;
    const char *output;
    const char *forced_aid;
    char session_buf[FILE_PATH_SIZE];
    char output_buf[FILE_PATH_SIZE];
    char forced_aid_buf[128];
    uint64_t amount_cents;
    bool amount_set;
    uint8_t un[4];
    bool un_set;
    emv_term_crypto_ac_t ac_type;
    bool cda;
    bool mc_challenge;
    int count;
    bool do_challenge;
    bool do_intauth;
    bool do_checksum;
    bool do_vary;
    bool no_genac;
    bool quick_afl;
    bool aid_fallback;
    bool no_aid_fallback;
    bool human_digest;
} emv_term_crypto_cli_t;

static void crypto_cli_defaults(emv_term_crypto_cli_t *c) {
    memset(c, 0, sizeof(*c));
    c->ac_type = EMV_CRYPTO_AC_ARQC;
    c->mc_challenge = true;
    c->count = 1;
    c->aid_fallback = true;
    c->human_digest = true;
}

static emv_term_crypto_ac_t parse_decision(const char *s) {
    if (!s || !s[0]) {
        return EMV_CRYPTO_AC_ARQC;
    }
    if (strncmp(s, "aac", 3) == 0) {
        return EMV_CRYPTO_AC_AAC;
    }
    if (strncmp(s, "tc", 2) == 0) {
        return EMV_CRYPTO_AC_TC;
    }
    return EMV_CRYPTO_AC_ARQC;
}

static void cli_to_genac_opts(const emv_term_crypto_cli_t *cli, emv_term_crypto_genac_opts_t *opts) {
    emv_term_crypto_genac_opts_defaults(opts);
    opts->ac_type = cli->ac_type;
    opts->cda = cli->cda;
    opts->mc_challenge = cli->mc_challenge;
    if (cli->amount_set) {
        opts->amount_set = true;
        emv_term_uint_to_bcd(cli->amount_cents, opts->amount, sizeof(opts->amount));
    }
    if (cli->un_set) {
        opts->un_set = true;
        memcpy(opts->un, cli->un, 4);
    }
}

static int crypto_init_live_only(emv_term_ctx_t *term_ctx, const emv_term_crypto_cli_t *cli) {
    emv_term_cli_opts_t opts = {0};
    opts.activate_field = cli->activate;
    opts.show_apdu = cli->show_apdu;
    opts.decode_tlv = cli->decode_tlv;
    opts.channel = cli->wired ? CC_CONTACT : CC_CONTACTLESS;
    opts.param_load_json = cli->jload;
    opts.crypto_quick_afl = cli->quick_afl;
    opts.crypto_aid_fallback = cli->aid_fallback && !cli->no_aid_fallback;
    if (cli->forced_aid && cli->forced_aid[0]) {
        int buflen = 0;
        if (!param_gethex_to_eol(cli->forced_aid, 0, opts.crypto_forced_aid,
                                 sizeof(opts.crypto_forced_aid), &buflen) && buflen > 0) {
            opts.crypto_forced_aid_len = (size_t)buflen;
        }
    }

    int res = emv_term_ctx_init(term_ctx, &opts);
    if (res) {
        return res;
    }

    if (cli->jload) {
        emv_term_init_transaction_params(term_ctx->terminal, true, NULL, TT_QVSDCMCHIP, false);
        emv_term_copy_terminal_tags_to_card(term_ctx);
    }

    if (cli->amount_set) {
        emv_term_crypto_set_amount_cents(term_ctx, cli->amount_cents);
    }
    if (cli->un_set) {
        emv_term_crypto_set_un_bytes(term_ctx, cli->un);
    }

    return PM3_SUCCESS;
}

static int crypto_prepare_live(emv_term_ctx_t *term_ctx, const emv_term_crypto_cli_t *cli) {
    int res = crypto_init_live_only(term_ctx, cli);
    if (res) {
        return res;
    }

    if (!cli->session || !cli->session[0]) {
        int prep = EMVPrepareContactlessEx(term_ctx->opts.channel, true, true);
        if (prep) {
            emv_term_ctx_free(term_ctx);
            return prep;
        }
        term_ctx->opts.activate_field = false;
    }

    emv_term_crypto_prepare_opts_t prep_opts = {
        .quick_afl = cli->quick_afl,
        .aid_fallback = cli->aid_fallback && !cli->no_aid_fallback,
        .forced_aid_hex = cli->forced_aid,
    };
    res = emv_term_crypto_prepare_card(term_ctx, cli->jload, cli->session, &prep_opts);
    if (res) {
        emv_term_ctx_free(term_ctx);
        return res;
    }

    return PM3_SUCCESS;
}

static void crypto_finish(emv_term_ctx_t *term_ctx, Iso7816CommandChannel channel) {
    DropFieldEx(channel);
    SetAPDULogging(false);
    emv_term_ctx_free(term_ctx);
}

static void crypto_cli_pin_str(const char *src, char *dst, size_t dstlen, const char **out) {
    if (!dst || !dstlen || !out) {
        return;
    }
    dst[0] = '\0';
    *out = NULL;
    if (src && src[0]) {
        str_copy(dst, dstlen, src);
        *out = dst;
    }
}

static void crypto_cli_pin_session(emv_term_crypto_cli_t *cli, CLIParserContext *ctx, int idx) {
    crypto_cli_pin_str(arg_get_str(ctx, idx)->sval[0], cli->session_buf, sizeof(cli->session_buf), &cli->session);
}

static void crypto_cli_pin_output(emv_term_crypto_cli_t *cli, CLIParserContext *ctx, int idx) {
    crypto_cli_pin_str(arg_get_str(ctx, idx)->sval[0], cli->output_buf, sizeof(cli->output_buf), &cli->output);
}

static void crypto_cli_pin_forced_aid(emv_term_crypto_cli_t *cli, CLIParserContext *ctx, int idx) {
    crypto_cli_pin_str(arg_get_str(ctx, idx)->sval[0], cli->forced_aid_buf, sizeof(cli->forced_aid_buf), &cli->forced_aid);
}

static void parse_amount_un(CLIParserContext *ctx, int amount_idx, int un_idx, emv_term_crypto_cli_t *cli) {
    const char *amount = arg_get_str(ctx, amount_idx)->sval[0];
    if (amount && amount[0]) {
        cli->amount_cents = strtoull(amount, NULL, 10);
        cli->amount_set = true;
    }
    const char *unhex = arg_get_str(ctx, un_idx)->sval[0];
    if (unhex && unhex[0]) {
        int buflen = 0;
        if (!param_gethex_to_eol(unhex, 0, cli->un, sizeof(cli->un), &buflen) && buflen == 4) {
            cli->un_set = true;
        }
    }
}

#define CRYPTO_BASE_ARGS \
        arg_lit0("s",  "select",   "Activate field and init card"), \
        arg_lit0("a",  "apdu",     "Show APDUs"), \
        arg_lit0("t",  "tlv",      "TLV decode"), \
        arg_lit0("w",  "wired",    "Contact"), \
        arg_lit0("j",  "jload",    "Load terminal profile"), \
        arg_str0(NULL, "session", "<file>", "Session JSON")

static int CmdEMVTerminalCryptoSummary(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto summary",
                  "Print CDOL/AIP/crypto TLV summary",
                  "emv terminal crypto summary --session s.json\n"
                  "emv terminal crypto summary -s -j\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        arg_str0("m",  "amount", "<cents>", "Override 9F02"),
        arg_str0(NULL, "un", "<hex>", "Override 9F37 (4 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.show_apdu = arg_get_lit(ctx, 2);
    cli.decode_tlv = arg_get_lit(ctx, 3);
    cli.wired = arg_get_lit(ctx, 4);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    parse_amount_un(ctx, 7, 8, &cli);
    crypto_cli_pin_session(&cli, ctx, 6);
    CLIParserFree(ctx);

    emv_term_ctx_t term_ctx;
    int res = crypto_prepare_live(&term_ctx, &cli);
    if (res) {
        return res;
    }
    SetAPDULogging(cli.show_apdu);
    res = emv_term_crypto_print_summary(&term_ctx);
    crypto_finish(&term_ctx, cli.wired ? CC_CONTACT : CC_CONTACTLESS);
    return res;
}

static int CmdEMVTerminalCryptoChallenge(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto challenge",
                  "GET CHALLENGE (00 84)",
                  "emv terminal crypto challenge -s -j -a\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.show_apdu = arg_get_lit(ctx, 2);
    cli.decode_tlv = arg_get_lit(ctx, 3);
    cli.wired = arg_get_lit(ctx, 4);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    crypto_cli_pin_session(&cli, ctx, 6);
    CLIParserFree(ctx);

    emv_term_ctx_t term_ctx;
    int res = crypto_prepare_live(&term_ctx, &cli);
    if (res) {
        return res;
    }
    SetAPDULogging(cli.show_apdu);
    res = emv_term_crypto_challenge(&term_ctx, cli.decode_tlv, true);
    crypto_finish(&term_ctx, cli.wired ? CC_CONTACT : CC_CONTACTLESS);
    return res;
}

static int crypto_genac_handler(const char *Cmd, bool ac2) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, ac2 ? "emv terminal crypto genac2" : "emv terminal crypto genac",
                  ac2 ? "GENERATE AC from CDOL2" : "GENERATE AC from CDOL1 (80 AE)",
                  "emv terminal crypto genac -s -j --decision arqc -m 100 -a\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        arg_str0("d",  "decision", "<aac|tc|arqc>", "Terminal decision (default arqc)"),
        arg_lit0("c",  "cda",      "Request CDA in P1"),
        arg_lit0(NULL, "no-mc-challenge", "Skip auto GET CHALLENGE for Mastercard"),
        arg_str0("m",  "amount", "<cents>", "Override 9F02"),
        arg_str0(NULL, "un", "<hex>", "Override 9F37 (4 bytes)"),
        arg_str0("o",  "output", "<file>", "Export crypto JSON"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.show_apdu = arg_get_lit(ctx, 2);
    cli.decode_tlv = arg_get_lit(ctx, 3);
    cli.wired = arg_get_lit(ctx, 4);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    const char *dec = arg_get_str(ctx, 7)->sval[0];
    if (dec && dec[0]) {
        cli.ac_type = parse_decision(dec);
    }
    cli.cda = arg_get_lit(ctx, 8);
    cli.mc_challenge = !arg_get_lit(ctx, 9);
    parse_amount_un(ctx, 10, 11, &cli);
    cli.output = arg_get_str(ctx, 12)->sval[0];
    crypto_cli_pin_session(&cli, ctx, 6);
    crypto_cli_pin_output(&cli, ctx, 12);
    CLIParserFree(ctx);

    emv_term_ctx_t term_ctx;
    int res = crypto_prepare_live(&term_ctx, &cli);
    if (res) {
        return res;
    }

    emv_term_crypto_genac_opts_t gopts;
    cli_to_genac_opts(&cli, &gopts);

    SetAPDULogging(cli.show_apdu);
    res = emv_term_crypto_genac(&term_ctx, &gopts, ac2);
    if (res == PM3_SUCCESS && cli.output && cli.output[0]) {
        emv_term_crypto_export_json(&term_ctx, cli.output, NULL, 0);
    }
    crypto_finish(&term_ctx, cli.wired ? CC_CONTACT : CC_CONTACTLESS);
    return res;
}

static int CmdEMVTerminalCryptoGenac(const char *Cmd) {
    return crypto_genac_handler(Cmd, false);
}

static int CmdEMVTerminalCryptoGenac2(const char *Cmd) {
    return crypto_genac_handler(Cmd, true);
}

static int CmdEMVTerminalCryptoVary(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto vary",
                  "Repeat GEN AC with different 9F37 values",
                  "emv terminal crypto vary -s -j --count 5 --decision arqc -a\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        arg_str0("d",  "decision", "<aac|tc|arqc>", "Terminal decision"),
        arg_lit0("c",  "cda",      "Request CDA"),
        arg_lit0(NULL, "no-mc-challenge", "Skip MC GET CHALLENGE"),
        arg_u64_0(NULL, "count", "<n>", "Iterations (default 3)"),
        arg_str0("m",  "amount", "<cents>", "Override 9F02"),
        arg_str0(NULL, "un", "<hex>", "Base 9F37 (optional)"),
        arg_str0("o",  "output", "<file>", "Export JSON with Runs[]"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.show_apdu = arg_get_lit(ctx, 2);
    cli.decode_tlv = arg_get_lit(ctx, 3);
    cli.wired = arg_get_lit(ctx, 4);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    const char *dec = arg_get_str(ctx, 7)->sval[0];
    if (dec && dec[0]) {
        cli.ac_type = parse_decision(dec);
    }
    cli.cda = arg_get_lit(ctx, 8);
    cli.mc_challenge = !arg_get_lit(ctx, 9);
    cli.count = (int)arg_get_u64_def(ctx, 10, 3);
    if (cli.count < 1) {
        cli.count = 1;
    }
    parse_amount_un(ctx, 11, 12, &cli);
    cli.output = arg_get_str(ctx, 13)->sval[0];
    crypto_cli_pin_session(&cli, ctx, 6);
    crypto_cli_pin_output(&cli, ctx, 13);
    CLIParserFree(ctx);

    emv_term_ctx_t term_ctx;
    int res = crypto_prepare_live(&term_ctx, &cli);
    if (res) {
        return res;
    }

    emv_term_crypto_genac_opts_t gopts;
    cli_to_genac_opts(&cli, &gopts);

    emv_term_crypto_run_entry_t entries[32] = {0};
    size_t entry_count = ARRAYLEN(entries);

    SetAPDULogging(cli.show_apdu);
    res = emv_term_crypto_vary_un(&term_ctx, &gopts, cli.count, entries, &entry_count);
    if (cli.output && cli.output[0]) {
        emv_term_crypto_export_json(&term_ctx, cli.output, entries, entry_count);
    }
    crypto_finish(&term_ctx, cli.wired ? CC_CONTACT : CC_CONTACTLESS);
    return res;
}

static int CmdEMVTerminalCryptoIntauth(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto intauth",
                  "INTERNAL AUTHENTICATE / DDA (00 88)",
                  "emv terminal crypto intauth -s -j -t -a\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.show_apdu = arg_get_lit(ctx, 2);
    cli.decode_tlv = arg_get_lit(ctx, 3);
    cli.wired = arg_get_lit(ctx, 4);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    crypto_cli_pin_session(&cli, ctx, 6);
    CLIParserFree(ctx);

    emv_term_ctx_t term_ctx;
    int res = crypto_prepare_live(&term_ctx, &cli);
    if (res) {
        return res;
    }
    SetAPDULogging(cli.show_apdu);
    res = emv_term_crypto_intauth(&term_ctx, cli.decode_tlv);
    crypto_finish(&term_ctx, cli.wired ? CC_CONTACT : CC_CONTACTLESS);
    return res;
}

static int CmdEMVTerminalCryptoChecksum(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto checksum",
                  "COMPUTE CRYPTOGRAPHIC CHECKSUM (MSD / UDOL)",
                  "emv terminal crypto checksum -s -j -a\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.show_apdu = arg_get_lit(ctx, 2);
    cli.decode_tlv = arg_get_lit(ctx, 3);
    cli.wired = arg_get_lit(ctx, 4);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    crypto_cli_pin_session(&cli, ctx, 6);
    CLIParserFree(ctx);

    emv_term_ctx_t term_ctx;
    int res = crypto_prepare_live(&term_ctx, &cli);
    if (res) {
        return res;
    }
    SetAPDULogging(cli.show_apdu);
    res = emv_term_crypto_msc_checksum(&term_ctx, cli.decode_tlv);
    crypto_finish(&term_ctx, cli.wired ? CC_CONTACT : CC_CONTACTLESS);
    return res;
}

static int CmdEMVTerminalCryptoExport(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto export",
                  "Export crypto TLV snapshot JSON",
                  "emv terminal crypto export --session s.json -o out.json\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        arg_str1("o", "output", "<file>", "Output JSON path"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    cli.output = arg_get_str(ctx, 7)->sval[0];
    crypto_cli_pin_session(&cli, ctx, 6);
    crypto_cli_pin_output(&cli, ctx, 7);
    CLIParserFree(ctx);

    if (!cli.output || !cli.output[0]) {
        return PM3_EINVARG;
    }

    emv_term_ctx_t term_ctx;
    int res = crypto_prepare_live(&term_ctx, &cli);
    if (res) {
        return res;
    }
    res = emv_term_crypto_export_json(&term_ctx, cli.output, NULL, 0);
    crypto_finish(&term_ctx, cli.wired ? CC_CONTACT : CC_CONTACTLESS);
    return res;
}

#define CRYPTO_PREP_ARGS \
        arg_lit0("q",  "quick",    "Quick AFL (skip SFI 15/12+, stop when CDOL found)"), \
        arg_str0(NULL, "aid", "<hex>", "Force application AID (e.g. A0000000042203)"), \
        arg_lit0(NULL, "no-aid-fallback", "Do not try alternate PPSE apps when CDOL1 missing")

static int CmdEMVTerminalCryptoRun(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto run",
                  "Full crypto lab bench",
                  "emv terminal crypto run -s --quick -o bench.json\n"
                  "emv terminal crypto run -s --aid A0000000042203\n"
                  "emv terminal crypto run -s --summary --vary --count 5\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        CRYPTO_PREP_ARGS,
        arg_str0("d",  "decision", "<aac|tc|arqc>", "GEN AC decision"),
        arg_lit0("c",  "cda",      "Request CDA"),
        arg_lit0(NULL, "no-mc-challenge", "Skip MC GET CHALLENGE"),
        arg_lit0(NULL, "challenge", "Run GET CHALLENGE before GEN AC"),
        arg_lit0(NULL, "intauth",   "Run INTERNAL AUTHENTICATE after GEN AC"),
        arg_lit0(NULL, "checksum",  "Run MSC checksum if UDOL present"),
        arg_lit0(NULL, "vary",      "Vary UN across multiple GEN AC"),
        arg_lit0(NULL, "no-genac",  "Skip GEN AC (summary/challenge only)"),
        arg_lit0(NULL, "summary",   "Human-readable card digest (default on run)"),
        arg_lit0(NULL, "no-summary", "Skip human-readable digest"),
        arg_u64_0(NULL, "count", "<n>", "Vary iterations (default 3)"),
        arg_str0("m",  "amount", "<cents>", "Override 9F02"),
        arg_str0(NULL, "un", "<hex>", "Override 9F37"),
        arg_str0("o",  "output", "<file>", "Export JSON"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.show_apdu = arg_get_lit(ctx, 2);
    cli.decode_tlv = arg_get_lit(ctx, 3);
    cli.wired = arg_get_lit(ctx, 4);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    cli.quick_afl = arg_get_lit(ctx, 7);
    cli.forced_aid = arg_get_str(ctx, 8)->sval[0];
    cli.no_aid_fallback = arg_get_lit(ctx, 9);
    const char *dec = arg_get_str(ctx, 10)->sval[0];
    if (dec && dec[0]) {
        cli.ac_type = parse_decision(dec);
    }
    cli.cda = arg_get_lit(ctx, 11);
    cli.mc_challenge = !arg_get_lit(ctx, 12);
    cli.do_challenge = arg_get_lit(ctx, 13);
    cli.do_intauth = arg_get_lit(ctx, 14);
    cli.do_checksum = arg_get_lit(ctx, 15);
    cli.do_vary = arg_get_lit(ctx, 16);
    cli.no_genac = arg_get_lit(ctx, 17);
    if (arg_get_lit(ctx, 18)) {
        cli.human_digest = true;
    }
    if (arg_get_lit(ctx, 19)) {
        cli.human_digest = false;
    }
    cli.count = (int)arg_get_u64_def(ctx, 20, 3);
    parse_amount_un(ctx, 21, 22, &cli);
    cli.output = arg_get_str(ctx, 23)->sval[0];
    crypto_cli_pin_session(&cli, ctx, 6);
    crypto_cli_pin_forced_aid(&cli, ctx, 8);
    crypto_cli_pin_output(&cli, ctx, 23);
    CLIParserFree(ctx);

    emv_term_ctx_t term_ctx;
    int res = crypto_prepare_live(&term_ctx, &cli);
    if (res) {
        return res;
    }

    emv_term_crypto_bench_opts_t bench = {0};
    bench.do_challenge = cli.do_challenge;
    bench.do_genac = !cli.no_genac;
    bench.do_intauth = cli.do_intauth;
    bench.do_checksum = cli.do_checksum;
    bench.do_vary = cli.do_vary;
    bench.do_digest = cli.human_digest;
    bench.vary_count = cli.count;
    cli_to_genac_opts(&cli, &bench.genac);

    SetAPDULogging(cli.show_apdu);
    res = emv_term_crypto_bench(&term_ctx, &bench, cli.output);
    crypto_finish(&term_ctx, cli.wired ? CC_CONTACT : CC_CONTACTLESS);
    return res;
}

static int CmdEMVTerminalCryptoCompare(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto compare",
                  "Compare two crypto export JSON files",
                  "emv terminal crypto compare -a mc.json -b visa.json\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("a", "file-a", "<file>", "First export JSON"),
        arg_str1("b", "file-b", "<file>", "Second export JSON"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    char path_a[FILE_PATH_SIZE] = {0};
    char path_b[FILE_PATH_SIZE] = {0};
    const char *pa = arg_get_str(ctx, 1)->sval[0];
    const char *pb = arg_get_str(ctx, 2)->sval[0];
    if (pa && pa[0]) {
        str_copy(path_a, sizeof(path_a), pa);
    }
    if (pb && pb[0]) {
        str_copy(path_b, sizeof(path_b), pb);
    }
    CLIParserFree(ctx);

    return emv_term_crypto_compare_json(path_a[0] ? path_a : NULL, path_b[0] ? path_b : NULL);
}

static int CmdEMVTerminalCryptoDigest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto digest",
                  "Human-readable card/crypto digest",
                  "emv terminal crypto digest -s\n"
                  "emv terminal crypto digest --session card.json\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        CRYPTO_PREP_ARGS,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.show_apdu = arg_get_lit(ctx, 2);
    cli.decode_tlv = arg_get_lit(ctx, 3);
    cli.wired = arg_get_lit(ctx, 4);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    cli.quick_afl = arg_get_lit(ctx, 7);
    cli.forced_aid = arg_get_str(ctx, 8)->sval[0];
    cli.no_aid_fallback = arg_get_lit(ctx, 9);
    crypto_cli_pin_session(&cli, ctx, 6);
    crypto_cli_pin_forced_aid(&cli, ctx, 8);
    CLIParserFree(ctx);

    emv_term_ctx_t term_ctx;
    int res = crypto_prepare_live(&term_ctx, &cli);
    if (res) {
        return res;
    }
    SetAPDULogging(cli.show_apdu);
    res = emv_term_crypto_print_digest(&term_ctx, NULL);
    crypto_finish(&term_ctx, cli.wired ? CC_CONTACT : CC_CONTACTLESS);
    return res;
}

static int CmdEMVTerminalCryptoRng(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal crypto rng",
                  "RNG from live card cryptograms (AC/ATC/UN/IAD)",
                  "emv terminal crypto rng -s\n"
                  "emv terminal crypto rng -s --dice\n"
                  "emv terminal crypto rng -s --stream | head -c 64\n"
                  "emv terminal crypto rng -s --stream --stream-raw | head -c 32 | xxd\n"
                  "emv terminal crypto rng -s --samples 5 --max 1000000\n");

    void *argtable[] = {
        arg_param_begin,
        CRYPTO_BASE_ARGS,
        CRYPTO_PREP_ARGS,
        arg_str0("d",  "decision", "<aac|tc|arqc>", "GEN AC decision"),
        arg_lit0(NULL, "no-mc-challenge", "Skip MC GET CHALLENGE"),
        arg_u64_0(NULL, "samples", "<n>", "Fresh AC samples to mix (default 1; re-tap between samples)"),
        arg_u64_0(NULL, "bytes", "<n>", "Raw output bytes (default 8)"),
        arg_u64_0(NULL, "max", "<n>", "Integer in [0..n-1]"),
        arg_lit0(NULL, "dice", "Roll a d6"),
        arg_lit0(NULL, "coin", "Coin flip"),
        arg_lit0(NULL, "stream", "Loop — continuous lowercase hex on stdout (Enter stops)"),
        arg_lit0(NULL, "stream-raw", "With --stream: raw bytes instead of hex"),
        arg_lit0(NULL, "quiet", "Less per-sample output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_crypto_cli_t cli;
    crypto_cli_defaults(&cli);
    cli.activate = arg_get_lit(ctx, 1);
    cli.show_apdu = arg_get_lit(ctx, 2);
    cli.decode_tlv = arg_get_lit(ctx, 3);
    cli.wired = arg_get_lit(ctx, 4);
    cli.jload = arg_get_lit(ctx, 5);
    cli.session = arg_get_str(ctx, 6)->sval[0];
    cli.quick_afl = arg_get_lit(ctx, 7);
    cli.forced_aid = arg_get_str(ctx, 8)->sval[0];
    cli.no_aid_fallback = arg_get_lit(ctx, 9);
    const char *dec = arg_get_str(ctx, 10)->sval[0];
    if (dec && dec[0]) {
        cli.ac_type = parse_decision(dec);
    }
    cli.mc_challenge = !arg_get_lit(ctx, 11);
    cli.count = (int)arg_get_u64_def(ctx, 12, 1);
    int bytes = (int)arg_get_u64_def(ctx, 13, 8);
    uint64_t range_max = arg_get_u64_def(ctx, 14, 0);
    bool dice = arg_get_lit(ctx, 15);
    bool coin = arg_get_lit(ctx, 16);
    bool stream = arg_get_lit(ctx, 17);
    bool stream_raw = arg_get_lit(ctx, 18);
    bool quiet = arg_get_lit(ctx, 19);
    crypto_cli_pin_session(&cli, ctx, 6);
    crypto_cli_pin_forced_aid(&cli, ctx, 8);
    CLIParserFree(ctx);

    if (stream) {
        cli.quick_afl = true;
    }

    if (stream && (dice || coin || range_max > 0)) {
        PrintAndLogEx(ERR, "--stream outputs entropy only (incompatible with --dice/--coin/--max)");
        return PM3_EINVARG;
    }

    emv_term_ctx_t term_ctx;
    int res;
    Iso7816CommandChannel channel = cli.wired ? CC_CONTACT : CC_CONTACTLESS;

    if (stream) {
        res = crypto_init_live_only(&term_ctx, &cli);
    } else {
        res = crypto_prepare_live(&term_ctx, &cli);
    }
    if (res) {
        return res;
    }

    emv_term_crypto_rng_opts_t ropts = {0};
    ropts.samples = cli.count;
    ropts.out_bytes = bytes;
    ropts.quiet = quiet || stream;
    if (stream) {
        ropts.stream_fmt = stream_raw ? EMV_CRYPTO_STREAM_RAW : EMV_CRYPTO_STREAM_HEX;
    }
    cli_to_genac_opts(&cli, &ropts.genac);

    if (dice) {
        ropts.mode = EMV_CRYPTO_RNG_DICE;
    } else if (coin) {
        ropts.mode = EMV_CRYPTO_RNG_COIN;
    } else if (range_max > 0) {
        ropts.mode = EMV_CRYPTO_RNG_RANGE;
        ropts.range_max = range_max;
    }

    SetAPDULogging(cli.show_apdu && !stream);
    if (stream) {
        res = emv_term_crypto_rng_stream(&term_ctx, &ropts, channel);
    } else {
        res = emv_term_crypto_rng(&term_ctx, &ropts);
    }
    crypto_finish(&term_ctx, channel);
    return res;
}

static int CmdEMVTerminalCryptoHelp(const char *Cmd);

static command_t CryptoCommandTable[] = {
    {"help",     CmdEMVTerminalCryptoHelp,    AlwaysAvailable, "Crypto playground help"},
    {"run",      CmdEMVTerminalCryptoRun,     IfPm3Iso14443,   "Full crypto lab bench"},
    {"digest",   CmdEMVTerminalCryptoDigest,  IfPm3Iso14443,   "Human-readable card digest"},
    {"compare",  CmdEMVTerminalCryptoCompare, AlwaysAvailable, "Compare two export JSON files"},
    {"summary",  CmdEMVTerminalCryptoSummary, AlwaysAvailable, "Print CDOL/AIP/crypto summary"},
    {"challenge", CmdEMVTerminalCryptoChallenge, IfPm3Iso14443, "GET CHALLENGE"},
    {"genac",    CmdEMVTerminalCryptoGenac,   IfPm3Iso14443,   "GENERATE AC (CDOL1)"},
    {"genac2",   CmdEMVTerminalCryptoGenac2,  IfPm3Iso14443,   "GENERATE AC (CDOL2)"},
    {"vary",     CmdEMVTerminalCryptoVary,    IfPm3Iso14443,   "Vary UN / repeat GEN AC"},
    {"rng",      CmdEMVTerminalCryptoRng,     IfPm3Iso14443,   "Card-sourced RNG from AC/ATC"},
    {"intauth",  CmdEMVTerminalCryptoIntauth, IfPm3Iso14443,   "INTERNAL AUTHENTICATE (DDA)"},
    {"checksum", CmdEMVTerminalCryptoChecksum, IfPm3Iso14443,  "MSC cryptographic checksum"},
    {"export",   CmdEMVTerminalCryptoExport,    AlwaysAvailable, "Export crypto JSON"},
    {NULL, NULL, NULL, NULL}
};

static int CmdEMVTerminalCryptoHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CryptoCommandTable);
    return PM3_SUCCESS;
}

int CmdEMVTerminalCrypto(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CryptoCommandTable, Cmd);
}
