//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_host_tcp.h"
#include "emv_term_host.h"
#include "emv_term_arqc.h"
#include "../emvjson.h"
#include "ui.h"
#include "util.h"
#include "commonutil.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifndef _WIN32
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#endif

static int parse_hex_field(const char *hex, uint8_t *out, size_t *out_len, size_t max_len) {
    if (!hex || !hex[0] || !out || !out_len) {
        return PM3_EINVARG;
    }
    int buflen = 0;
    if (param_gethex_to_eol(hex, 0, out, max_len, &buflen)) {
        return PM3_ESOFT;
    }
    *out_len = (size_t)buflen;
    return PM3_SUCCESS;
}

static bool parse_host_port(const char *host_port, char *host, size_t host_len, uint16_t *port) {
    if (!host_port || !host_port[0] || !host || !port) {
        return false;
    }
    const char *colon = strrchr(host_port, ':');
    if (!colon || colon == host_port) {
        str_copy(host, host_len, "127.0.0.1");
        *port = (uint16_t)atoi(host_port);
        return *port > 0;
    }
    size_t hlen = (size_t)(colon - host_port);
    if (hlen >= host_len) {
        return false;
    }
    memcpy(host, host_port, hlen);
    host[hlen] = '\0';
    *port = (uint16_t)atoi(colon + 1);
    return *port > 0;
}

static int hex_field_to_buf(json_t *obj, const char *key, uint8_t *out, size_t *out_len, size_t max) {
    json_t *j = json_object_get(obj, key);
    if (!json_is_string(j)) {
        return PM3_ESOFT;
    }
    int buflen = 0;
    if (param_gethex_to_eol(json_string_value(j), 0, out, max, &buflen)) {
        return PM3_ESOFT;
    }
    *out_len = (size_t)buflen;
    return PM3_SUCCESS;
}

static json_t *handle_auth_request(json_t *req, const emv_term_host_keys_t *keys) {
    json_t *jtype = json_object_get(req, "type");
    if (!json_is_string(jtype) || strcmp(json_string_value(jtype), "auth") != 0) {
        return NULL;
    }

    uint8_t arqc[16] = {0};
    size_t arqc_len = 0;
    if (hex_field_to_buf(req, "arqc", arqc, &arqc_len, sizeof(arqc)) != PM3_SUCCESS || arqc_len < 8) {
        PrintAndLogEx(ERR, "TCP host: missing ARQC");
        return NULL;
    }

    uint16_t atc_val = 0;
    json_t *jatc = json_object_get(req, "atc");
    if (json_is_string(jatc)) {
        uint8_t atc_b[2] = {0};
        size_t atc_len = 0;
        hex_field_to_buf(req, "atc", atc_b, &atc_len, sizeof(atc_b));
        if (atc_len >= 2) {
            atc_val = (atc_b[0] << 8) | atc_b[1];
        }
    } else if (json_is_integer(jatc)) {
        atc_val = (uint16_t)json_integer_value(jatc);
    }

    uint8_t sk[16] = {0};
    emv_term_sk_derive_ac(keys->ac_master_key, atc_val, sk);

    json_t *jcdol = json_object_get(req, "cdol1");
    if (json_is_string(jcdol)) {
        uint8_t cdol1[256] = {0};
        size_t cdol1_len = 0;
        if (hex_field_to_buf(req, "cdol1", cdol1, &cdol1_len, sizeof(cdol1)) == PM3_SUCCESS) {
            if (emv_term_arqc_verify(sk, cdol1, cdol1_len, arqc, arqc_len)) {
                PrintAndLogEx(SUCCESS, "TCP host ARQC verify: OK");
            } else {
                PrintAndLogEx(WARNING, "TCP host ARQC verify: FAIL");
            }
        }
    }

    uint8_t arc[2] = {0x30, 0x30};
    json_t *jarc = json_object_get(req, "arc");
    if (json_is_string(jarc)) {
        size_t arc_len = 0;
        hex_field_to_buf(req, "arc", arc, &arc_len, sizeof(arc));
    }

    uint8_t arpc[16] = {0};
    size_t arpc_len = 0;
    if (!emv_term_arpc_compute(keys->arpc_method, sk, arqc, arqc_len, arc, 2, arpc, &arpc_len)) {
        return NULL;
    }

    json_t *resp = json_object();
    json_object_set_new(resp, "type", json_string("auth_resp"));
    JsonSaveBufAsHexCompact(resp, "arc", arc, 2);
    JsonSaveBufAsHexCompact(resp, "arpc", arpc, arpc_len);

    if (keys->default_arpc_rc_set) {
        uint8_t rc[2] = { keys->default_arpc_rc[0], keys->default_arpc_rc[1] };
        JsonSaveBufAsHexCompact(resp, "arpc_rc", rc, 2);
    } else {
        json_object_set_new(resp, "arpc_rc", json_string("8840"));
    }
    json_object_set_new(resp, "script71", json_string(""));

    return resp;
}

#ifndef _WIN32

static int set_socket_timeout(int fd, int sec) {
    struct timeval tv = { .tv_sec = sec, .tv_usec = 0 };
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int read_line(int fd, char *buf, size_t buflen) {
    size_t pos = 0;
    while (pos + 1 < buflen) {
        char c = 0;
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) {
            return PM3_ESOFT;
        }
        if (c == '\n') {
            buf[pos] = '\0';
            return PM3_SUCCESS;
        }
        buf[pos++] = c;
    }
    return PM3_ESOFT;
}

static int write_line(int fd, const char *line) {
    size_t len = strlen(line);
    char *out = malloc(len + 2);
    if (!out) {
        return PM3_EMALLOC;
    }
    memcpy(out, line, len);
    out[len] = '\n';
    ssize_t sent = send(fd, out, len + 1, 0);
    free(out);
    return (sent == (ssize_t)(len + 1)) ? PM3_SUCCESS : PM3_ESOFT;
}

int emv_term_host_tcp_listen(uint16_t port, const char *keys_path) {
    emv_term_host_keys_t keys;
    int res;
    if (keys_path && keys_path[0]) {
        res = emv_term_host_keys_load(&keys, keys_path);
    } else {
        res = emv_term_host_keys_default(&keys, NULL);
    }
    if (res) {
        return res;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        PrintAndLogEx(ERR, "TCP host: socket failed (%s)", strerror(errno));
        return PM3_ESOFT;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PrintAndLogEx(ERR, "TCP host: bind 127.0.0.1:%u failed (%s)", port, strerror(errno));
        close(sock);
        return PM3_ESOFT;
    }

    if (listen(sock, 4) < 0) {
        close(sock);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "TCP mock acquirer listening on 127.0.0.1:%u", port);
    PrintAndLogEx(INFO, "Press Enter to stop");

    while (!kbd_enter_pressed()) {
        struct sockaddr_in client_addr;
        socklen_t clen = sizeof(client_addr);
        int client = accept(sock, (struct sockaddr *)&client_addr, &clen);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            usleep(100000);
            continue;
        }

        set_socket_timeout(client, 5);
        char line[4096] = {0};
        if (read_line(client, line, sizeof(line)) == PM3_SUCCESS) {
            json_error_t error;
            json_t *req = json_loads(line, 0, &error);
            if (req) {
                json_t *resp = handle_auth_request(req, &keys);
                json_decref(req);
                if (resp) {
                    char *dump = json_dumps(resp, JSON_COMPACT);
                    if (dump) {
                        write_line(client, dump);
                        free(dump);
                    }
                    json_decref(resp);
                }
            }
        }
        close(client);
    }

    close(sock);
    PrintAndLogEx(INFO, "TCP host stopped");
    return PM3_SUCCESS;
}

int emv_term_host_tcp_request(emv_term_ctx_t *ctx, const char *host_port,
                              const emv_term_host_keys_t *keys,
                              emv_term_host_tcp_resp_t *resp) {
    if (!ctx || !host_port || !resp) {
        return PM3_EINVARG;
    }
    memset(resp, 0, sizeof(*resp));

    char host[64] = {0};
    uint16_t port = 8583;
    if (!parse_host_port(host_port, host, sizeof(host), &port)) {
        PrintAndLogEx(ERR, "Invalid --host-tcp address (use host:port)");
        return PM3_EINVARG;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return PM3_ESOFT;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        close(fd);
        return PM3_EINVARG;
    }

    set_socket_timeout(fd, 5);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        PrintAndLogEx(ERR, "TCP host connect %s:%u failed (%s)", host, port, strerror(errno));
        close(fd);
        return PM3_ESOFT;
    }

    json_t *req = json_object();
    json_object_set_new(req, "type", json_string("auth"));

    const struct tlv *ac = tlvdb_get(ctx->card, 0x9f26, NULL);
    const struct tlv *atc = tlvdb_get(ctx->card, 0x9f36, NULL);
    if (ac && ac->len) {
        JsonSaveBufAsHexCompact(req, "arqc", (uint8_t *)ac->value, ac->len);
    }
    if (atc && atc->len) {
        JsonSaveBufAsHexCompact(req, "atc", (uint8_t *)atc->value, atc->len);
    }
    if (ctx->aid_len) {
        JsonSaveBufAsHexCompact(req, "aid", ctx->aid, ctx->aid_len);
    }
    if (ctx->cdol1_len) {
        JsonSaveBufAsHexCompact(req, "cdol1", ctx->cdol1_data, ctx->cdol1_len);
    }

    char *dump = json_dumps(req, JSON_COMPACT);
    json_decref(req);
    if (!dump) {
        close(fd);
        return PM3_ESOFT;
    }

    write_line(fd, dump);
    free(dump);

    char line[4096] = {0};
    if (read_line(fd, line, sizeof(line)) != PM3_SUCCESS) {
        close(fd);
        PrintAndLogEx(ERR, "TCP host: no response");
        return PM3_ESOFT;
    }
    close(fd);

    json_error_t error;
    json_t *jresp = json_loads(line, 0, &error);
    if (!jresp) {
        PrintAndLogEx(ERR, "TCP host: bad JSON response");
        return PM3_ESOFT;
    }

    json_t *jtype = json_object_get(jresp, "type");
    if (!json_is_string(jtype) || strcmp(json_string_value(jtype), "auth_resp") != 0) {
        json_decref(jresp);
        return PM3_ESOFT;
    }

    json_t *jarc = json_object_get(jresp, "arc");
    if (json_is_string(jarc)) {
        str_copy(resp->arc, sizeof(resp->arc), json_string_value(jarc));
    }
    json_t *jarpc = json_object_get(jresp, "arpc");
    if (json_is_string(jarpc)) {
        str_copy(resp->arpc, sizeof(resp->arpc), json_string_value(jarpc));
    }
    json_t *jrc = json_object_get(jresp, "arpc_rc");
    if (json_is_string(jrc)) {
        str_copy(resp->arpc_rc, sizeof(resp->arpc_rc), json_string_value(jrc));
    }
    json_t *js71 = json_object_get(jresp, "script71");
    if (json_is_string(js71)) {
        str_copy(resp->script71, sizeof(resp->script71), json_string_value(js71));
    }

    json_decref(jresp);

    if (resp->arc[0]) {
        size_t arc_len = 0;
        uint8_t arc[2] = {0};
        parse_hex_field(resp->arc, arc, &arc_len, 2);
        if (arc_len >= 2) {
            ctx->arc[0] = arc[0];
            ctx->arc[1] = arc[1];
        }
    }

    (void)keys;
    PrintAndLogEx(INFO, "TCP host response: ARC=%s ARPC=%s", resp->arc, resp->arpc);
    return PM3_SUCCESS;
}

#else

int emv_term_host_tcp_listen(uint16_t port, const char *keys_path) {
    (void)port;
    (void)keys_path;
    PrintAndLogEx(ERR, "TCP host not implemented on this platform");
    return PM3_ENOTIMPL;
}

int emv_term_host_tcp_request(emv_term_ctx_t *ctx, const char *host_port,
                              const emv_term_host_keys_t *keys,
                              emv_term_host_tcp_resp_t *resp) {
    (void)ctx;
    (void)host_port;
    (void)keys;
    (void)resp;
    PrintAndLogEx(ERR, "TCP host not implemented on this platform");
    return PM3_ENOTIMPL;
}

#endif
