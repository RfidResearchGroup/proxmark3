//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_lua.h"
#include "emv_terminal.h"
#include "emv_term_ctx.h"
#include "emv_term_session.h"
#include "emv_term_sim_export.h"
#include "emv_term_mock.h"
#include "proxmark3.h"
#include "ui.h"
#include "util.h"
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <string.h>

static emv_term_cli_opts_t opts_from_lua_table(lua_State *L, int idx) {
    emv_term_cli_opts_t opts = {0};
    if (!lua_istable(L, idx)) {
        return opts;
    }

    lua_getfield(L, idx, "profile");
    if (lua_isstring(L, -1)) {
        opts.scheme_profile = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, idx, "pin");
    if (lua_isstring(L, -1)) {
        opts.pin = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, idx, "output");
    if (lua_isstring(L, -1)) {
        opts.output_session = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, idx, "host_sim");
    opts.host_sim = lua_toboolean(L, -1);
    lua_pop(L, 1);

    lua_getfield(L, idx, "mock_apdu");
    if (lua_isstring(L, -1)) {
        opts.mock_apdu = lua_tostring(L, -1);
    }
    lua_pop(L, 1);

    lua_getfield(L, idx, "wired");
    if (lua_toboolean(L, -1)) {
        opts.channel = CC_CONTACT;
    }
    lua_pop(L, 1);

    opts.param_load_json = true;
    opts.use_terminal_profile = true;
    return opts;
}

static void push_result(lua_State *L, int rc, emv_term_ctx_t *ctx) {
    lua_newtable(L);
    lua_pushinteger(L, rc);
    lua_setfield(L, -2, "rc");
    lua_pushstring(L, emv_term_outcome_str(ctx->outcome));
    lua_setfield(L, -2, "outcome");
    if (ctx->session_file[0]) {
        lua_pushstring(L, ctx->session_file);
    } else if (ctx->opts.output_session && ctx->opts.output_session[0]) {
        lua_pushstring(L, ctx->opts.output_session);
    } else {
        lua_pushstring(L, "");
    }
    lua_setfield(L, -2, "session_path");
}

static int l_emv_terminal_run(lua_State *L) {
    emv_term_cli_opts_t opts = opts_from_lua_table(L, 1);

    emv_term_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    int res = emv_term_ctx_init(&ctx, &opts);
    if (res) {
        push_result(L, res, &ctx);
        return 1;
    }
    res = emv_term_cli_setup(&ctx);
    if (res) {
        emv_term_ctx_free(&ctx);
        push_result(L, res, &ctx);
        return 1;
    }

    if (opts.output_session && opts.output_session[0]) {
        str_copy(ctx.session_file, sizeof(ctx.session_file), opts.output_session);
    }

    res = emv_terminal_run(&ctx);
    push_result(L, res, &ctx);
    emv_term_mock_clear();
    emv_term_ctx_free(&ctx);
    return 1;
}

static int l_emv_terminal_step(lua_State *L) {
    const char *phase_name = luaL_checkstring(L, 1);
    emv_term_cli_opts_t opts = opts_from_lua_table(L, 2);

    emv_term_phase_t phase = EMV_PHASE_COUNT;
    for (emv_term_phase_t p = EMV_PHASE_INIT; p < EMV_PHASE_COUNT; p++) {
        if (strcmp(phase_name, emv_term_phase_name(p)) == 0) {
            phase = p;
            break;
        }
    }
    if (phase >= EMV_PHASE_COUNT) {
        return luaL_error(L, "unknown phase '%s'", phase_name);
    }

    emv_term_ctx_t ctx;
    int res = emv_term_ctx_init(&ctx, &opts);
    if (res) {
        lua_pushinteger(L, res);
        return 1;
    }
    res = emv_term_cli_setup(&ctx);
    if (res) {
        emv_term_ctx_free(&ctx);
        lua_pushinteger(L, res);
        return 1;
    }

    res = emv_terminal_step(&ctx, phase);
    if (opts.output_session && opts.output_session[0]) {
        emv_term_session_save_json(&ctx, opts.output_session);
    }
    push_result(L, res, &ctx);
    emv_term_ctx_free(&ctx);
    return 1;
}

static int l_emv_terminal_session_load(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    emv_term_cli_opts_t opts = {0};
    emv_term_ctx_t ctx;
    int res = emv_term_ctx_init(&ctx, &opts);
    if (res) {
        lua_pushinteger(L, res);
        return 1;
    }
    res = emv_term_session_load_json(&ctx, path);
    emv_term_ctx_free(&ctx);
    lua_pushinteger(L, res);
    return 1;
}

static int l_emv_terminal_session_save(lua_State *L) {
    const char *path = luaL_checkstring(L, 1);
    emv_term_cli_opts_t opts = {0};
    opts.session_path = path;
    emv_term_ctx_t ctx;
    int res = emv_term_ctx_init(&ctx, &opts);
    if (res) {
        lua_pushinteger(L, res);
        return 1;
    }
    emv_term_session_load_json(&ctx, path);
    res = emv_term_session_save_json(&ctx, path);
    emv_term_ctx_free(&ctx);
    lua_pushinteger(L, res);
    return 1;
}

static int l_emv_terminal_export_sim(lua_State *L) {
    const char *session = luaL_checkstring(L, 1);
    const char *out = luaL_checkstring(L, 2);
    lua_pushinteger(L, emv_term_sim_export_session(session, out));
    return 1;
}

void emv_term_lua_register(lua_State *L) {
    static const luaL_Reg funcs[] = {
        {"emv_terminal_run", l_emv_terminal_run},
        {"emv_terminal_step", l_emv_terminal_step},
        {"emv_terminal_session_load", l_emv_terminal_session_load},
        {"emv_terminal_session_save", l_emv_terminal_session_save},
        {"emv_terminal_export_sim", l_emv_terminal_export_sim},
        {NULL, NULL},
    };
    for (int i = 0; funcs[i].name; i++) {
        lua_pushcfunction(L, funcs[i].func);
        lua_setglobal(L, funcs[i].name);
    }
}
