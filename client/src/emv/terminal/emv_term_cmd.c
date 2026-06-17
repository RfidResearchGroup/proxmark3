//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// EMV terminal emulator — CLI commands
//-----------------------------------------------------------------------------

#include "emv_term_cmd.h"
#include "emv_terminal.h"
#include "emv_term_profile.h"
#include "emv_term_session.h"
#include "emv_term_load.h"
#include "emv_term_host.h"
#include "emv_term_golden.h"
#include "emv_term_mock.h"
#include "emv_term_session_view.h"
#include "emv_term_pin_prompt.h"
#include "emv_term_secure.h"
#include "emv_term_redact.h"
#include "emv_term_sim_export.h"
#include "emv_term_host_tcp.h"
#include "emv_term_banner.h"
#include "emv_term_replay.h"
#include "emv_term_capabilities.h"
#include "emv_term_pcap.h"
#include "phase_cvm.h"
#include "phase_online.h"
#include "phase_complete.h"
#include "cliparser.h"
#include "cmdparser.h"
#include "proxmark3.h"
#include "ui.h"
#include "iso7816/iso7816core.h"
#include <string.h>
#include <stdlib.h>
#include <jansson.h>

static void apply_wave_b_opts(emv_term_cli_opts_t *opts,
                              const char *exception_file,
                              const char *capk_extra,
                              bool no_redact,
                              bool full_tlv) {
    if (exception_file && exception_file[0]) {
        opts->exception_file = exception_file;
    }
    if (capk_extra && capk_extra[0]) {
        opts->capk_extra = capk_extra;
    }
    opts->no_redact = no_redact;
    opts->full_tlv = full_tlv;
}

static void apply_wave_d_opts(emv_term_cli_opts_t *opts,
                              const char *pcap_out,
                              const char *pcap_meta,
                              bool timing_report) {
    if (pcap_out && pcap_out[0]) {
        opts->pcap_out = pcap_out;
    }
    if (pcap_meta && pcap_meta[0]) {
        opts->pcap_meta = pcap_meta;
    }
    opts->timing_report = timing_report;
}

static int CmdEMVTerminalSession(const char *Cmd);
static int CmdHelp(const char *Cmd);

static bool is_scheme_profile_name(const char *s) {
    if (!s || !s[0]) {
        return false;
    }
    return strcmp(s, "auto") == 0 || strcmp(s, "default") == 0 ||
           strcmp(s, "interac") == 0 || strcmp(s, "visa") == 0 || strcmp(s, "mc") == 0;
}

static void apply_profile_arg(emv_term_cli_opts_t *opts, const char *profile_arg) {
    if (!profile_arg || !profile_arg[0]) {
        return;
    }
    if (is_scheme_profile_name(profile_arg)) {
        opts->scheme_profile = profile_arg;
    } else {
        opts->profile_path = profile_arg;
    }
}

static void print_channel(Iso7816CommandChannel channel) {
    switch (channel) {
        case CC_CONTACTLESS:
            PrintAndLogEx(INFO, "Selected channel... " _GREEN_("CONTACTLESS (T=CL)"));
            break;
        case CC_CONTACT:
            PrintAndLogEx(INFO, "Selected channel... " _GREEN_("CONTACT"));
            break;
    }
}

static int parse_tr_type(CLIParserContext *ctx, int qvsdc_idx, int cda_idx, int vsdc_idx, TransactionType_t *tr_type) {
    *tr_type = TT_MSD;
    if (arg_get_lit(ctx, qvsdc_idx)) {
        *tr_type = TT_QVSDCMCHIP;
    }
    if (arg_get_lit(ctx, cda_idx)) {
        *tr_type = TT_CDA;
    }
    if (arg_get_lit(ctx, vsdc_idx)) {
        *tr_type = TT_VSDC;
    }
    return PM3_SUCCESS;
}

static int parse_common_exec_args(CLIParserContext *ctx, emv_term_cli_opts_t *opts,
                                  int select_idx, int apdu_idx, int tlv_idx, int jload_idx,
                                  int force_idx, int qvsdc_idx, int cda_idx, int vsdc_idx,
                                  int acgpo_idx, int wired_idx) {
    memset(opts, 0, sizeof(*opts));
    opts->activate_field = arg_get_lit(ctx, select_idx);
    opts->show_apdu = arg_get_lit(ctx, apdu_idx);
    opts->decode_tlv = arg_get_lit(ctx, tlv_idx);
    opts->param_load_json = arg_get_lit(ctx, jload_idx);
    opts->force_search = arg_get_lit(ctx, force_idx);
    opts->gen_ac_gpo = arg_get_lit(ctx, acgpo_idx);
    opts->channel = arg_get_lit(ctx, wired_idx) ? CC_CONTACT : CC_CONTACTLESS;
    return parse_tr_type(ctx, qvsdc_idx, cda_idx, vsdc_idx, &opts->tr_type);
}

static emv_term_phase_t parse_phase_name(const char *name) {
    for (emv_term_phase_t p = EMV_PHASE_INIT; p < EMV_PHASE_COUNT; p++) {
        if (strcmp(name, emv_term_phase_name(p)) == 0) {
            return p;
        }
    }
    return EMV_PHASE_COUNT;
}

static int CmdEMVTerminalRun(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal run",
                  "Execute full EMV terminal phase loop (init through completion)",
                  "emv terminal run -satj    -> select, show APDU/TLV, load terminal profile\n"
                  "emv terminal run -j --pin 1234 -o /tmp/session.json --qvsdc\n"
                  "emv terminal run -j --auto-online --host-sim --profile auto\n"
                  "emv terminal run --mock-apdu-file fixtures/foo/mock_apdu.json\n"
                  "emv terminal run -j --trace-phases --stop-after taa\n"
                  "\nContactless: HF field is activated automatically at transaction start.");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",   "Activate field and select card"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",      "TLV decode results"),
        arg_lit0("j",  "jload",    "Load terminal profile (emv_terminal_profile.json)"),
        arg_lit0(NULL, "force",    "Force search AID instead of PPSE"),
        arg_rem("By default:",     "Transaction type - MSD"),
        arg_lit0(NULL, "qvsdc",    "Transaction type - qVSDC or M/Chip"),
        arg_lit0("c",  "qvsdccda", "Transaction type - qVSDC/M/Chip plus CDA"),
        arg_lit0("x",  "vsdc",     "Transaction type - VSDC (contact test path)"),
        arg_lit0("g",  "acgpo",    "VISA: generate AC from GPO"),
        arg_lit0("w",  "wired",    "Contact (ISO7816) interface"),
        arg_str0("o",  "output",   "<file>", "Session JSON output path"),
        arg_str0(NULL, "pin",      "<digits>", "Offline PIN (lab only; prefer EMV_TEST_PIN env)"),
        arg_str0(NULL, "profile",  "<name|file>", "Scheme profile (auto|interac|visa|mc) or terminal profile JSON"),
        arg_str0(NULL, "stop-after", "<phase>", "Stop after named phase (init|oda|restrict|cvm|trm|taa|caa|online|complete)"),
        arg_lit0(NULL, "trace-phases", "Log phase boundaries"),
        arg_lit0(NULL, "cvm-skip-online", "Skip online PIN CVM (set TVR bit only)"),
        arg_str0(NULL, "arc",      "<hex>", "Authorization Response Code (8A) for online stub"),
        arg_str0(NULL, "arpc",     "<hex>", "Issuer Authentication Data / ARPC (tag 91)"),
        arg_str0(NULL, "arpc-rc",  "<hex>", "ARPC response code suffix (e.g. Interac 8840)"),
        arg_lit0(NULL, "auto-online", "Run online phase automatically when ARQC returned"),
        arg_lit0(NULL, "host-sim", "Use host simulator for online ARQC/ARPC"),
        arg_str0(NULL, "host-keys", "<file>", "Host simulator keys JSON"),
        arg_str0(NULL, "mock-apdu-file", "<file>", "Replay CAPDU trace from JSON (no card)"),
        arg_lit0(NULL, "continue-on-bad-arqc", "Continue online after ARQC verify failure"),
        arg_lit0(NULL, "record-apdu", "Record APDU trace (stub — use mock fixtures for CI)"),
        arg_str0(NULL, "exception-file", "<file>", "PAN blocklist (SHA-256 / pan: lines)"),
        arg_str0(NULL, "capk-extra", "<file>", "Extra CAPK file merged at ODA init"),
        arg_lit0(NULL, "no-redact", "Session export without crypto redaction (lab only)"),
        arg_lit0(NULL, "full-tlv", "Embed Card.TLV snapshot in session JSON"),
        arg_str0(NULL, "export-sim", "<file>", "Export emv sim patch JSON after completion"),
        arg_str0(NULL, "host-tcp", "<host:port>", "TCP mock acquirer (e.g. 127.0.0.1:8583)"),
        arg_str0(NULL, "pcap-out", "<file.pcap>", "Export ISO7816 APDU trace (Wireshark linktype 265)"),
        arg_str0(NULL, "pcap-meta", "<session.json>", "Companion session JSON for pcap correlation"),
        arg_lit0(NULL, "timing-report", "Record phase duration_ms in session JSON"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_cli_opts_t opts;
    parse_common_exec_args(ctx, &opts, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11);

    opts.output_session = arg_get_str(ctx, 12)->sval[0];
    opts.pin = arg_get_str(ctx, 13)->sval[0];
    apply_profile_arg(&opts, arg_get_str(ctx, 14)->sval[0]);
    opts.stop_after = arg_get_str(ctx, 15)->sval[0];
    opts.trace_phases = arg_get_lit(ctx, 16);
    opts.cvm_skip_online = arg_get_lit(ctx, 17);
    opts.arc = arg_get_str(ctx, 18)->sval[0];
    opts.arpc = arg_get_str(ctx, 19)->sval[0];
    opts.arpc_rc = arg_get_str(ctx, 20)->sval[0];
    opts.auto_online = arg_get_lit(ctx, 21);
    opts.host_sim = arg_get_lit(ctx, 22);
    opts.host_keys = arg_get_str(ctx, 23)->sval[0];
    opts.mock_apdu = arg_get_str(ctx, 24)->sval[0];
    opts.continue_on_bad_arqc = arg_get_lit(ctx, 25);
    opts.record_apdu = arg_get_lit(ctx, 26);
    apply_wave_b_opts(&opts,
                      arg_get_str(ctx, 27)->sval[0],
                      arg_get_str(ctx, 28)->sval[0],
                      arg_get_lit(ctx, 29),
                      arg_get_lit(ctx, 30));
    opts.export_sim = arg_get_str(ctx, 31)->sval[0];
    opts.host_tcp = arg_get_str(ctx, 32)->sval[0];
    apply_wave_d_opts(&opts,
                      arg_get_str(ctx, 33)->sval[0],
                      arg_get_str(ctx, 34)->sval[0],
                      arg_get_lit(ctx, 35));
    opts.use_terminal_profile = opts.param_load_json;
    CLIParserFree(ctx);

    print_channel(opts.channel);

    if (opts.mock_apdu && opts.mock_apdu[0]) {
        opts.activate_field = false;
        opts.skip_banner = true;
    }

    emv_term_banner_maybe_show(opts.skip_banner);

    if (IfPm3Smartcard() == false && opts.channel == CC_CONTACT && !(opts.mock_apdu && opts.mock_apdu[0])) {
        PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support. Exiting.");
        return PM3_EDEVNOTSUPP;
    }

    emv_term_ctx_t term_ctx;
    int res = emv_term_ctx_init(&term_ctx, &opts);
    if (res) {
        return res;
    }

    res = emv_term_cli_setup(&term_ctx);
    if (res) {
        emv_term_ctx_free(&term_ctx);
        emv_term_mock_clear();
        return res;
    }

    if (opts.host_sim) {
        term_ctx.opts.auto_online = true;
    }
    if (opts.host_tcp && opts.host_tcp[0]) {
        term_ctx.opts.auto_online = true;
    }

    res = emv_terminal_run(&term_ctx);
    emv_term_mock_clear();
    emv_term_ctx_free(&term_ctx);
    return res;
}

static int CmdEMVTerminalStep(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal step",
                  "Run a single terminal phase",
                  "emv terminal step init -satj\n"
                  "emv terminal step cvm --session /tmp/s.json --pin 1234\n"
                  "emv terminal step online --session /tmp/s.json --arpc <hex>\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, NULL, "<phase>", "Phase: init|oda|restrict|cvm|trm|taa|caa|online|complete"),
        arg_lit0("s",  "select",   "Activate field and select card"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",      "TLV decode results"),
        arg_lit0("j",  "jload",    "Load terminal profile"),
        arg_lit0(NULL, "force",    "Force search AID"),
        arg_lit0(NULL, "qvsdc",    "Transaction type - qVSDC or M/Chip"),
        arg_lit0("c",  "qvsdccda", "Transaction type - CDA"),
        arg_lit0("x",  "vsdc",     "Transaction type - VSDC"),
        arg_lit0("g",  "acgpo",    "Generate AC from GPO"),
        arg_lit0("w",  "wired",    "Contact interface"),
        arg_str0(NULL, "session", "<file>", "Session file for state carry-over"),
        arg_str0(NULL, "pin",      "<digits>", "PIN for cvm phase"),
        arg_str0("o",  "output",   "<file>", "Updated session JSON path"),
        arg_str0(NULL, "arc",      "<hex>", "ARC for online phase"),
        arg_str0(NULL, "arpc",     "<hex>", "ARPC for online phase"),
        arg_str0(NULL, "arpc-rc",  "<hex>", "ARPC-RC suffix"),
        arg_str0(NULL, "exception-file", "<file>", "PAN blocklist file"),
        arg_str0(NULL, "capk-extra", "<file>", "Extra CAPK file"),
        arg_lit0(NULL, "no-redact", "Session export without redaction"),
        arg_lit0(NULL, "full-tlv", "Embed Card.TLV in session JSON"),
        arg_str0(NULL, "pcap-out", "<file.pcap>", "Export ISO7816 APDU trace"),
        arg_lit0(NULL, "timing-report", "Record phase duration_ms"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *phase_name = arg_get_str(ctx, 1)->sval[0];
    emv_term_phase_t phase = parse_phase_name(phase_name);
    if (phase >= EMV_PHASE_COUNT) {
        PrintAndLogEx(ERR, "Unknown phase '%s'", phase_name);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    emv_term_cli_opts_t opts;
    parse_common_exec_args(ctx, &opts, 2, 3, 4, 5, 6, 8, 9, 10, 11, 12);
    opts.session_path = arg_get_str(ctx, 13)->sval[0];
    opts.pin = arg_get_str(ctx, 14)->sval[0];
    opts.output_session = arg_get_str(ctx, 15)->sval[0];
    opts.arc = arg_get_str(ctx, 16)->sval[0];
    opts.arpc = arg_get_str(ctx, 17)->sval[0];
    opts.arpc_rc = arg_get_str(ctx, 18)->sval[0];
    apply_wave_b_opts(&opts,
                      arg_get_str(ctx, 19)->sval[0],
                      arg_get_str(ctx, 20)->sval[0],
                      arg_get_lit(ctx, 21),
                      arg_get_lit(ctx, 22));
    apply_wave_d_opts(&opts,
                      arg_get_str(ctx, 23)->sval[0],
                      NULL,
                      arg_get_lit(ctx, 24));
    CLIParserFree(ctx);

    print_channel(opts.channel);
    emv_term_banner_maybe_show(false);

    emv_term_ctx_t term_ctx;
    int res = emv_term_ctx_init(&term_ctx, &opts);
    if (res) {
        return res;
    }

    res = emv_term_cli_setup(&term_ctx);
    if (res) {
        emv_term_ctx_free(&term_ctx);
        return res;
    }

    if (opts.session_path && opts.session_path[0] && phase != EMV_PHASE_INIT) {
        emv_term_session_load_json(&term_ctx, opts.session_path);
    }

    SetAPDULogging(opts.show_apdu);
    res = emv_terminal_step(&term_ctx, phase);

    const char *outpath = opts.output_session;
    if (!outpath || !outpath[0]) {
        outpath = term_ctx.session_file[0] ? term_ctx.session_file : opts.session_path;
    }
    if (outpath && outpath[0]) {
        emv_term_session_save_json(&term_ctx, outpath);
    }

    if (phase != EMV_PHASE_INIT) {
        DropFieldEx(opts.channel);
    }
    SetAPDULogging(false);
    emv_term_ctx_free(&term_ctx);
    return res;
}

static int CmdEMVTerminalOnline(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal online",
                  "Complete online path after ARQC (EXTERNAL AUTH + AC2)",
                  "emv terminal online --session s.json --arc 3030 --arpc <hex>\n"
                  "emv terminal online --session s.json --arpc <hex> --arpc-rc 8840 -w\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "session", "<file>", "Session JSON from prior run with ARQC"),
        arg_str0(NULL, "arc",      "<hex>", "Authorization Response Code (8A)"),
        arg_str0(NULL, "arpc",     "<hex>", "Issuer Authentication Data / ARPC"),
        arg_str0(NULL, "arpc-rc",  "<hex>", "ARPC response code suffix"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("w",  "wired",    "Contact interface"),
        arg_str0("o",  "output",   "<file>", "Updated session JSON path"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *session = arg_get_str(ctx, 1)->sval[0];
    const char *arc = arg_get_str(ctx, 2)->sval[0];
    const char *arpc = arg_get_str(ctx, 3)->sval[0];
    const char *arpc_rc = arg_get_str(ctx, 4)->sval[0];
    bool show_apdu = arg_get_lit(ctx, 5);
    bool wired = arg_get_lit(ctx, 6);
    const char *output = arg_get_str(ctx, 7)->sval[0];
    CLIParserFree(ctx);

    if (!session || !session[0]) {
        PrintAndLogEx(ERR, "Session file required");
        return PM3_EINVARG;
    }

    emv_term_cli_opts_t opts = {0};
    opts.channel = wired ? CC_CONTACT : CC_CONTACTLESS;
    opts.show_apdu = show_apdu;
    opts.session_path = session;
    opts.output_session = output;
    opts.arc = arc;
    opts.arpc = arpc;
    opts.arpc_rc = arpc_rc;

    print_channel(opts.channel);
    emv_term_banner_maybe_show(false);

    if (IfPm3Smartcard() == false && opts.channel == CC_CONTACT) {
        PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support. Exiting.");
        return PM3_EDEVNOTSUPP;
    }

    emv_term_ctx_t term_ctx;
    int res = emv_term_ctx_init(&term_ctx, &opts);
    if (res) {
        return res;
    }

    emv_term_session_load_json(&term_ctx, session);

    if (!term_ctx.ac1_performed || (term_ctx.ac1_cid & 0xC0) != EMVAC_ARQC_BYTE) {
        PrintAndLogEx(ERR, "Session does not contain ARQC from AC1 — run caa phase first");
        emv_term_ctx_free(&term_ctx);
        return PM3_EINVARG;
    }

    int prep = EMVPrepareContactless(opts.channel, false);
    if (prep) {
        emv_term_ctx_free(&term_ctx);
        return prep;
    }

    SetAPDULogging(show_apdu);
    res = phase_online_run(&term_ctx);
    if (res == PM3_SUCCESS) {
        phase_complete_run(&term_ctx);
    }

    const char *outpath = output;
    if (!outpath || !outpath[0]) {
        outpath = session;
    }
    emv_term_outcome_t outcome = term_ctx.outcome;
    emv_term_session_save_json(&term_ctx, outpath);

    DropFieldEx(opts.channel);
    SetAPDULogging(false);
    emv_term_ctx_free(&term_ctx);

    PrintAndLogEx(SUCCESS, "[+] Terminal outcome: %s", emv_term_outcome_str(outcome));
    return res;
}

static int CmdEMVTerminalPin(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal pin",
                  "Standalone VERIFY PIN for debugging (requires active session/card)",
                  "emv terminal pin --offline 1234\n"
                  "emv terminal pin --offline 1234 --enciphered -w\n"
                  "emv terminal pin --prompt\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "offline", "<pin>", "Offline PIN digits (4-12)"),
        arg_lit0(NULL, "prompt", "Interactive PIN prompt (TTY required)"),
        arg_lit0(NULL, "enciphered", "Use enciphered offline PIN (CVM 04)"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("w",  "wired",    "Contact interface"),
        arg_str0(NULL, "session", "<file>", "Load session from file (optional)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *pin = arg_get_str(ctx, 1)->sval[0];
    bool use_prompt = arg_get_lit(ctx, 2);
    bool enciphered = arg_get_lit(ctx, 3);
    bool show_apdu = arg_get_lit(ctx, 4);
    bool wired = arg_get_lit(ctx, 5);
    const char *session = arg_get_str(ctx, 6)->sval[0];
    CLIParserFree(ctx);

    char prompt_pin[16] = {0};
    if (use_prompt) {
        if (emv_term_pin_prompt("Enter offline PIN: ", prompt_pin, sizeof(prompt_pin)) != PM3_SUCCESS) {
            return PM3_EINVARG;
        }
        pin = prompt_pin;
    } else if ((!pin || !pin[0]) && getenv("EMV_TEST_PIN")) {
        pin = getenv("EMV_TEST_PIN");
    }

    if (!pin || !pin[0]) {
        PrintAndLogEx(ERR, "PIN required: --offline <pin>, --prompt, or EMV_TEST_PIN");
        emv_term_secure_zero(prompt_pin, sizeof(prompt_pin));
        return PM3_EINVARG;
    }

    emv_term_cli_opts_t opts = {0};
    opts.channel = wired ? CC_CONTACT : CC_CONTACTLESS;
    opts.show_apdu = show_apdu;

    emv_term_ctx_t term_ctx;
    int res = emv_term_ctx_init(&term_ctx, &opts);
    if (res) {
        return res;
    }

    if (session && session[0]) {
        emv_term_session_load_json(&term_ctx, session);
    }

    int prep = EMVPrepareContactless(opts.channel, false);
    if (prep) {
        emv_term_secure_zero(prompt_pin, sizeof(prompt_pin));
        emv_term_ctx_free(&term_ctx);
        return prep;
    }

    SetAPDULogging(show_apdu);
    res = phase_cvm_verify_pin(&term_ctx, pin, enciphered);
    emv_term_secure_zero(prompt_pin, sizeof(prompt_pin));
    DropFieldEx(opts.channel);
    SetAPDULogging(false);
    emv_term_ctx_free(&term_ctx);
    return res;
}

static int CmdEMVTerminalProfile(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal profile",
                  "Print or validate terminal profile JSON",
                  "emv terminal profile print\n"
                  "emv terminal profile validate docs/emv-terminal-emulator/examples/emv_terminal_profile.json\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, NULL, "<action>", "Action: print|validate"),
        arg_str0(NULL, NULL, "<file>", "Profile JSON path (optional)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *action = arg_get_str(ctx, 1)->sval[0];
    const char *file = arg_get_str(ctx, 2)->sval[0];
    CLIParserFree(ctx);

    if (strcmp(action, "print") == 0) {
        return emv_term_profile_print(file);
    }
    if (strcmp(action, "validate") == 0) {
        return emv_term_profile_validate(file);
    }

    PrintAndLogEx(ERR, "Unknown action '%s' — use print or validate", action);
    return PM3_EINVARG;
}

static int CmdEMVTerminalLoad(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal load",
                  "Import card TLV subset from prior emv scan JSON for offline phase testing",
                  "emv terminal load scan.json -o card_session.json\n"
                  "emv terminal load scan.json  # prints loaded AID/tags only");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, NULL, "<file>", "Scan JSON file from emv scan"),
        arg_str0("o", "output", "<file>", "Write session JSON with loaded card state"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *file = arg_get_str(ctx, 1)->sval[0];
    const char *output = arg_get_str(ctx, 2)->sval[0];
    CLIParserFree(ctx);

    emv_term_cli_opts_t opts = {0};
    emv_term_ctx_t term_ctx;
    int res = emv_term_ctx_init(&term_ctx, &opts);
    if (res) {
        return res;
    }

    res = emv_term_load_from_scan(&term_ctx, file);
    if (res) {
        emv_term_ctx_free(&term_ctx);
        return res;
    }

    emv_term_event_add(&term_ctx, EMV_PHASE_INIT, PM3_SUCCESS, 0, "loaded from scan");

    if (output && output[0]) {
        emv_term_session_save_json(&term_ctx, output);
        str_copy(term_ctx.session_file, sizeof(term_ctx.session_file), output);
    }

    emv_term_ctx_free(&term_ctx);
    return PM3_SUCCESS;
}

static int CmdEMVTerminalHostSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal host-sim",
                  "Complete online path using host simulator keys (ARQC verify + ARPC)",
                  "emv terminal host-sim --session s.json\n"
                  "emv terminal host-sim --session s.json --host-keys keys.json -a\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "session", "<file>", "Session JSON with ARQC from AC1"),
        arg_str0(NULL, "host-keys", "<file>", "Host keys JSON (default: interac test keys)"),
        arg_str0(NULL, "arc", "<hex>", "Authorization Response Code (8A)"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_lit0("w", "wired", "Contact interface"),
        arg_str0("o", "output", "<file>", "Updated session JSON path"),
        arg_lit0(NULL, "continue-on-bad-arqc", "Continue after ARQC verify failure"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *session = arg_get_str(ctx, 1)->sval[0];
    const char *host_keys = arg_get_str(ctx, 2)->sval[0];
    const char *arc = arg_get_str(ctx, 3)->sval[0];
    bool show_apdu = arg_get_lit(ctx, 4);
    bool wired = arg_get_lit(ctx, 5);
    const char *output = arg_get_str(ctx, 6)->sval[0];
    bool cont_bad = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    emv_term_cli_opts_t opts = {0};
    opts.channel = wired ? CC_CONTACT : CC_CONTACTLESS;
    opts.show_apdu = show_apdu;
    opts.session_path = session;
    opts.output_session = output;
    opts.arc = arc;
    opts.host_keys = host_keys;
    opts.host_sim = true;
    opts.continue_on_bad_arqc = cont_bad;

    emv_term_banner_maybe_show(false);

    emv_term_ctx_t term_ctx;
    int res = emv_term_ctx_init(&term_ctx, &opts);
    if (res) {
        return res;
    }

    emv_term_session_load_json(&term_ctx, session);
    if (host_keys && host_keys[0]) {
        str_copy(term_ctx.host_keys_path, sizeof(term_ctx.host_keys_path), host_keys);
    }

    SetAPDULogging(show_apdu);
    res = emv_term_host_sim_run(&term_ctx, host_keys);

    const char *outpath = output;
    if (!outpath || !outpath[0]) {
        outpath = session;
    }
    emv_term_outcome_t outcome = term_ctx.outcome;
    emv_term_session_save_json(&term_ctx, outpath);

    DropFieldEx(opts.channel);
    SetAPDULogging(false);
    emv_term_ctx_free(&term_ctx);

    PrintAndLogEx(SUCCESS, "[+] Terminal outcome: %s", emv_term_outcome_str(outcome));
    return res;
}

static int CmdEMVTerminalTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal test",
                  "Run golden regression fixtures (no USB required)",
                  "emv terminal test --golden\n"
                  "emv terminal test --fixture taa_denial_expired\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("g", "golden", "Run all golden fixtures"),
        arg_str0("f", "fixture", "<name>", "Run single fixture by directory name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool golden = arg_get_lit(ctx, 1);
    const char *fixture = arg_get_str(ctx, 2)->sval[0];
    CLIParserFree(ctx);

    if (fixture && fixture[0]) {
        return emv_term_golden_run(fixture, true);
    }
    if (golden || (!fixture || !fixture[0])) {
        return emv_term_golden_run_all(true);
    }

    PrintAndLogEx(ERR, "Use --golden or --fixture <name>");
    return PM3_EINVARG;
}

static int CmdEMVTerminalSessionPrint(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal session print",
                  "Human-readable session summary",
                  "emv terminal session print session.json\n"
                  "emv terminal session print session.json --json\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, NULL, "<file>", "Session JSON path"),
        arg_lit0("j", "json", "Emit raw JSON instead of summary"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *file = arg_get_str(ctx, 1)->sval[0];
    bool as_json = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    return emv_term_session_print(file, as_json);
}

static int CmdEMVTerminalSessionMerge(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal session merge",
                  "Merge scan JSON with terminal session outcomes",
                  "emv terminal session merge scan.json session.json -o merged.json\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, NULL, "<scan>", "Scan JSON from emv scan"),
        arg_str1(NULL, NULL, "<session>", "Terminal session JSON"),
        arg_str0("o", "output", "<file>", "Merged output path"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *scan = arg_get_str(ctx, 1)->sval[0];
    const char *session = arg_get_str(ctx, 2)->sval[0];
    const char *output = arg_get_str(ctx, 3)->sval[0];
    CLIParserFree(ctx);

    if (!output || !output[0]) {
        PrintAndLogEx(ERR, "Output path required (-o)");
        return PM3_EINVARG;
    }
    return emv_term_session_merge(scan, session, output);
}

static int CmdEMVTerminalSessionExport(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal session export",
                  "Re-export session JSON with redaction options",
                  "emv terminal session export session.json -o out.json\n"
                  "emv terminal session export session.json -o out.json --no-redact\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, NULL, "<file>", "Input session JSON"),
        arg_str0("o", "output", "<file>", "Output path (default: overwrite input)"),
        arg_lit0(NULL, "no-redact", "Export full cryptogram hex (lab only)"),
        arg_lit0(NULL, "full-tlv", "Include Card.TLV if present in source"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *input = arg_get_str(ctx, 1)->sval[0];
    const char *output = arg_get_str(ctx, 2)->sval[0];
    bool no_redact = arg_get_lit(ctx, 3);
    bool full_tlv = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    json_error_t error;
    json_t *root = json_load_file(input, 0, &error);
    if (!root) {
        PrintAndLogEx(ERR, "Session load error: %s", error.text);
        return PM3_ESOFT;
    }

    if (!no_redact) {
        emv_term_redact_session_json(root, false);
    } else {
        PrintAndLogEx(WARNING, "Session export without redaction (lab only)");
    }

    const char *outpath = (output && output[0]) ? output : input;
    (void)full_tlv;
    int res = json_dump_file(root, outpath, JSON_INDENT(2));
    json_decref(root);

    if (res) {
        PrintAndLogEx(ERR, "Failed to write: %s", outpath);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "Session exported: %s", outpath);
    return PM3_SUCCESS;
}

static int CmdEMVTerminalHostListen(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal host listen",
                  "TCP mock acquirer on 127.0.0.1 (JSON line protocol)",
                  "emv terminal host listen 8583\n"
                  "emv terminal host listen 8583 --host-keys keys.json\n");

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "port", "<n>", "Listen port (default 8583)"),
        arg_str0(NULL, "host-keys", "<file>", "Host keys JSON"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint64_t port = arg_get_u64_def(ctx, 1, 8583);
    const char *keys = arg_get_str(ctx, 2)->sval[0];
    CLIParserFree(ctx);

    return emv_term_host_tcp_listen((uint16_t)port, keys);
}

static command_t HostCommandTable[] = {
    {"listen",  CmdEMVTerminalHostListen, AlwaysAvailable, "TCP mock acquirer daemon"},
    {"sim",     CmdEMVTerminalHostSim,    IfPm3Iso14443,   "One-shot host-sim on session"},
    {NULL, NULL, NULL, NULL}
};

static int CmdEMVTerminalHost(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(HostCommandTable, Cmd);
}

static int CmdEMVTerminalReplay(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal replay",
                  "Replay mock APDU trace through phase engine (no live card)",
                  "emv terminal replay mock_apdu.json\n"
                  "emv terminal replay mock_apdu.json --from-phase cvm --to-phase caa -o s.json\n"
                  "emv terminal replay mock_apdu.json --host-sim --profile auto\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, NULL, "<mock_apdu.json>", "Mock APDU trace JSON"),
        arg_str0(NULL, "from-phase", "<name>", "Start phase (init|oda|...|complete)"),
        arg_str0(NULL, "to-phase", "<name>", "End phase (default: complete)"),
        arg_str0("o", "output", "<file>", "Session JSON output path"),
        arg_str0(NULL, "profile", "<name>", "Scheme profile (auto|interac|visa|mc)"),
        arg_str0(NULL, "session", "<file>", "Session JSON for mid-flow state"),
        arg_lit0(NULL, "host-sim", "Run online phase with host simulator"),
        arg_str0(NULL, "host-keys", "<file>", "Host simulator keys JSON"),
        arg_str0(NULL, "pcap-out", "<file.pcap>", "Export ISO7816 APDU trace"),
        arg_str0(NULL, "pcap-meta", "<session.json>", "Companion session JSON for pcap"),
        arg_lit0(NULL, "timing-report", "Record phase duration_ms"),
        arg_lit0("j", "jload", "Load terminal profile"),
        arg_lit0(NULL, "trace-phases", "Log phase boundaries"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_cli_opts_t opts = {0};
    opts.mock_apdu = arg_get_str(ctx, 1)->sval[0];
    const char *from_phase = arg_get_str(ctx, 2)->sval[0];
    const char *to_phase = arg_get_str(ctx, 3)->sval[0];
    opts.output_session = arg_get_str(ctx, 4)->sval[0];
    apply_profile_arg(&opts, arg_get_str(ctx, 5)->sval[0]);
    opts.session_path = arg_get_str(ctx, 6)->sval[0];
    opts.host_sim = arg_get_lit(ctx, 7);
    opts.host_keys = arg_get_str(ctx, 8)->sval[0];
    apply_wave_d_opts(&opts,
                      arg_get_str(ctx, 9)->sval[0],
                      arg_get_str(ctx, 10)->sval[0],
                      arg_get_lit(ctx, 11));
    opts.param_load_json = arg_get_lit(ctx, 12);
    opts.use_terminal_profile = opts.param_load_json;
    opts.trace_phases = arg_get_lit(ctx, 13);
    opts.skip_banner = true;
    opts.auto_online = opts.host_sim;
    CLIParserFree(ctx);

    emv_term_ctx_t term_ctx;
    int res = emv_term_ctx_init(&term_ctx, &opts);
    if (res) {
        return res;
    }

    res = emv_term_cli_setup(&term_ctx);
    if (res) {
        emv_term_ctx_free(&term_ctx);
        emv_term_mock_clear();
        return res;
    }

    res = emv_term_replay_run(&term_ctx, from_phase, to_phase);
    emv_term_mock_clear();
    emv_term_ctx_free(&term_ctx);
    return res;
}

static int CmdEMVTerminalCapabilities(const char *Cmd) {
    (void)Cmd;
    return emv_term_capabilities_print();
}

static int CmdEMVTerminalExportSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv terminal export-sim",
                  "Export card patch JSON for emv sim research replay",
                  "emv terminal export-sim session.json -o patch.json\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, NULL, "<session>", "Terminal session JSON"),
        arg_str0("o", "output", "<file>", "Output patch JSON path"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    const char *session = arg_get_str(ctx, 1)->sval[0];
    const char *output = arg_get_str(ctx, 2)->sval[0];
    CLIParserFree(ctx);

    if (!output || !output[0]) {
        PrintAndLogEx(ERR, "Output path required (-o)");
        return PM3_EINVARG;
    }
    return emv_term_sim_export_session(session, output);
}

static command_t SessionCommandTable[] = {
    {"print",  CmdEMVTerminalSessionPrint,  AlwaysAvailable, "Print session summary"},
    {"merge",  CmdEMVTerminalSessionMerge,  AlwaysAvailable, "Merge scan + session JSON"},
    {"export", CmdEMVTerminalSessionExport, AlwaysAvailable, "Re-export session with redaction"},
    {NULL, NULL, NULL, NULL}
};

static int CmdEMVTerminalSession(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(SessionCommandTable, Cmd);
}

static command_t TerminalCommandTable[] = {
    {"help",    CmdHelp,              AlwaysAvailable, "This help"},
    {"run",     CmdEMVTerminalRun,    IfPm3Iso14443,   "Run full terminal phase loop"},
    {"step",    CmdEMVTerminalStep,   IfPm3Iso14443,   "Run single terminal phase"},
    {"online",  CmdEMVTerminalOnline, IfPm3Iso14443,   "Complete online path after ARQC"},
    {"pin",     CmdEMVTerminalPin,    IfPm3Iso14443,   "Standalone VERIFY PIN"},
    {"profile", CmdEMVTerminalProfile, AlwaysAvailable, "Print or validate terminal profile JSON"},
    {"load",    CmdEMVTerminalLoad,   AlwaysAvailable, "Load card data from scan JSON"},
    {"export-sim", CmdEMVTerminalExportSim, AlwaysAvailable, "Export emv sim card patch from session"},
    {"host",    CmdEMVTerminalHost,   AlwaysAvailable, "Host simulator (TCP listen / one-shot)"},
    {"host-sim", CmdEMVTerminalHostSim, IfPm3Iso14443, "Host simulator online completion (alias)"},
    {"test",    CmdEMVTerminalTest,   AlwaysAvailable, "Golden regression fixtures (no USB)"},
    {"replay",  CmdEMVTerminalReplay, AlwaysAvailable, "Replay mock APDU trace through phases"},
    {"capabilities", CmdEMVTerminalCapabilities, AlwaysAvailable, "Device / build capability list"},
    {"session", CmdEMVTerminalSession, AlwaysAvailable, "Session print / merge / export"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(TerminalCommandTable);
    return PM3_SUCCESS;
}

int CmdEMVTerminal(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(TerminalCommandTable, Cmd);
}
