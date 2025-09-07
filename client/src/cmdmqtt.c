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
// MQTT commands
//-----------------------------------------------------------------------------
#include "cmdmqtt.h"

#include "cmdparser.h"
#include "cliparser.h"
#include "mqtt.h"            // MQTT support
//#include "mbedtls_sockets.h" // MQTT networkings examples

#ifndef _WIN32
#include "posix_sockets.h" // MQTT networkings examples
#else
#include "win32_sockets.h" // MQTT networkings examples
#endif
#include "util_posix.h"  // time
#include "fileutils.h"

#define MQTT_BUFFER_SIZE    ( 1 << 16 )

static int CmdHelp(const char *Cmd);

static void mqtt_publish_callback(void **unused, struct mqtt_response_publish *published) {

    if (published == NULL) {
        return;
    }


    // note that published->topic_name is NOT null-terminated (here we'll change it to a c-string)
    char *topic_name = (char *) calloc(published->topic_name_size + 1, 1);
    if (topic_name == NULL) {
        return;
    }

    memcpy(topic_name, published->topic_name, published->topic_name_size);

    const char *msg = published->application_message;

    const char *ps = strstr(msg, "Created\": \"proxmark3");
    if (ps) {
        int res = saveFileTXT("ice_mqtt", ".json", msg, published->application_message_size, spDefault);
        if (res == PM3_SUCCESS) {
            PrintAndLogEx(INFO, "Got a json file ( %s )", _GREEN_("ok"));
        }
    } else {
        PrintAndLogEx(SUCCESS, _GREEN_("%s") " - ( %zu ) " _YELLOW_("%s"), topic_name, published->application_message_size, msg);
    }
    free(topic_name);
}

static volatile int mqtt_client_should_exit = 0;

static void *mqtt_client_refresher(void *client) {
    while (mqtt_client_should_exit == 0) {
        mqtt_sync((struct mqtt_client *) client);
        msleep(100);
    }
    return NULL;
}

static int mqtt_exit(int status, mqtt_pal_socket_handle sockfd, const pthread_t *client_daemon) {
    close_nb_socket(sockfd);
    if (client_daemon != NULL) {
        mqtt_client_should_exit = 1;
        pthread_join(*client_daemon, NULL); // Wait for the thread to finish
        mqtt_client_should_exit = 0;
    }
    return status;
}

/*
static void mqtt_reconnect_client(struct mqtt_client* client, void **reconnect_state_vptr) {

    struct reconnect_state_t *rs = *((struct reconnect_state_t**) reconnect_state_vptr);

    // Close the clients socket if this isn't the initial reconnect call
    if (client->error != MQTT_ERROR_INITIAL_RECONNECT) {
        close_nb_socket(client->socketfd);
    }

    if (client->error != MQTT_ERROR_INITIAL_RECONNECT) {
        PrintAndLogEx(INFO, "reconnect_client: called while client was in error state `%s`",  mqtt_error_str(client->error));
    }

    int sockfd = open_nb_socket(rs->hostname, rs->port);
    if (sockfd == -1) {
        PrintAndLogEx(FAILED, "Failed to open socket");
        mqtt_exit(PM3_EFAILED, sockfd, NULL);
    }

    // Reinitialize the client.
    mqtt_reinit(client, sockfd, rs->sendbuf, rs->sendbufsz, rs->recvbuf, rs->recvbufsz);

    const char* client_id = NULL;

    uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;

    mqtt_connect(client, client_id, NULL, NULL, 0, NULL, NULL, connect_flags, 400);

    mqtt_subscribe(client, rs->topic, 0);
}
*/

static int mqtt_receive(const char *addr, const char *port, const char *topic, const char *fn) {
    // open the non-blocking TCP socket (connecting to the broker)
    mqtt_pal_socket_handle sockfd = open_nb_socket(addr, port);
    if (sockfd == -1) {
        PrintAndLogEx(FAILED, "Failed to open socket");
        return mqtt_exit(PM3_EFAILED, sockfd, NULL);
    }

    uint8_t sendbuf[MQTT_BUFFER_SIZE]; // 64kb sendbuf should be large enough to hold multiple whole mqtt messages
    uint8_t recvbuf[MQTT_BUFFER_SIZE]; // 64kb recvbuf should be large enough any whole mqtt message expected to be received

    struct mqtt_client client;

    /*
    struct reconnect_state_t rs;
    rs.hostname = addr;
    rs.port = port;
    rs.topic = topic;
    rs.sendbuf = sendbuf;
    rs.sendbufsz = sizeof(sendbuf);
    rs.recvbuf = recvbuf;
    rs.recvbufsz = sizeof(recvbuf);
    mqtt_init_reconnect(&client, mqtt_reconnect_client, &rs, mqtt_publish_callback);
    */

    mqtt_init(&client, sockfd, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), mqtt_publish_callback);

    char cid[20] = "pm3_";
    sprintf(cid + strlen(cid), "%02x%02x%02x%02x"
            , rand() % 0xFF
            , rand() % 0xFF
            , rand() % 0xFF
            , rand() % 0xFF
           );

    // Ensure we have a clean session
    uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
    // Send connection request to the broker
    mqtt_connect(&client, cid, NULL, NULL, 0, NULL, NULL, connect_flags, 400);

    // check that we don't have any errors
    if (client.error != MQTT_OK) {
        PrintAndLogEx(FAILED, "error: %s", mqtt_error_str(client.error));
        return mqtt_exit(PM3_ESOFT, sockfd, NULL);
    }

    // start a thread to refresh the client (handle egress and ingree client traffic)
    pthread_t client_daemon;
    if (pthread_create(&client_daemon, NULL, mqtt_client_refresher, &client)) {
        PrintAndLogEx(FAILED, "Failed to start client daemon");
        return mqtt_exit(PM3_ESOFT, sockfd, NULL);
    }

    // subscribe to a topic with a max QoS level of 0
    mqtt_subscribe(&client, topic, 0);

    PrintAndLogEx(INFO, _CYAN_("%s") " listening at " _CYAN_("%s:%s/%s"), cid, addr, port, topic);
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");

    while (kbd_enter_pressed() == false) {
        msleep(2000);
    };

    PrintAndLogEx(INFO, _CYAN_("%s") " disconnecting from " _CYAN_("%s"), cid, addr);
    return mqtt_exit(PM3_SUCCESS, sockfd, &client_daemon);
}

static int mqtt_send(const char *addr, const char *port, const char *topic, char *msg, const char *fn) {

    uint8_t *data;
    size_t bytes_read = 0;
    if (fn != NULL) {
        int res = loadFile_TXTsafe(fn, "", (void **)&data, &bytes_read, true);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }

    // open the non-blocking TCP socket (connecting to the broker)
    int sockfd = open_nb_socket(addr, port);

    if (sockfd == -1) {
        PrintAndLogEx(FAILED, "Failed to open socket");
        return mqtt_exit(PM3_EFAILED, sockfd, NULL);
    }

    struct mqtt_client client;
    uint8_t sendbuf[MQTT_BUFFER_SIZE];
    uint8_t recvbuf[MQTT_BUFFER_SIZE];
    mqtt_init(&client, sockfd, sendbuf, sizeof(sendbuf), recvbuf, sizeof(recvbuf), mqtt_publish_callback);

    char cid[20] = "pm3_";
    sprintf(cid + strlen(cid), "%02x%02x%02x%02x"
            , rand() % 0xFF
            , rand() % 0xFF
            , rand() % 0xFF
            , rand() % 0xFF
           );

    // Ensure we have a clean session
    uint8_t connect_flags = MQTT_CONNECT_CLEAN_SESSION;
    // Send connection request to the broker
    mqtt_connect(&client, cid, NULL, NULL, 0, NULL, NULL, connect_flags, 400);

    // check that we don't have any errors
    if (client.error != MQTT_OK) {
        PrintAndLogEx(FAILED, "error: %s", mqtt_error_str(client.error));
        mqtt_exit(PM3_EFAILED, sockfd, NULL);
    }

    // start a thread to refresh the client (handle egress and ingree client traffic)
    pthread_t client_daemon;
    if (pthread_create(&client_daemon, NULL, mqtt_client_refresher, &client)) {
        PrintAndLogEx(FAILED,  "Failed to start client daemon");
        mqtt_exit(PM3_EFAILED, sockfd, NULL);

    }

    PrintAndLogEx(INFO, _CYAN_("%s") " is ready", cid);

    if (fn != NULL) {
        PrintAndLogEx(INFO, "Publishing file...");
        mqtt_publish(&client, topic, data, bytes_read, MQTT_PUBLISH_QOS_0);
    } else {
        PrintAndLogEx(INFO, "Publishing message...");
        mqtt_publish(&client, topic, msg, strlen(msg) + 1, MQTT_PUBLISH_QOS_0);
    }

    if (client.error != MQTT_OK) {
        PrintAndLogEx(INFO, "error: %s", mqtt_error_str(client.error));
        mqtt_exit(PM3_ESOFT, sockfd, &client_daemon);
    }

    msleep(4000);

    PrintAndLogEx(INFO, _CYAN_("%s") " disconnecting from " _CYAN_("%s"), cid, addr);
    return mqtt_exit(PM3_SUCCESS, sockfd, &client_daemon);
}

static int CmdMqttSend(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mqtt send",
                  "This command send MQTT messages.  You can send JSON file\n"
                  "Default server:  proxdump.com:1883  topic: proxdump\n",
                  "mqtt send --msg \"Hello from Pm3\"     --> sending msg to default server/port/topic\n"
                  "mqtt send -f myfile.json               --> sending file to default server/port/topic\n"
                  "mqtt send --addr test.mosquitto.org -p 1883 --topic pm3 --msg \"custom mqtt server \"\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "addr", "<str>", "MQTT server address"),
        arg_str0("p", "port", "<str>", "MQTT server port"),
        arg_str0(NULL, "topic", "<str>", "MQTT topic"),
        arg_str0(NULL, "msg", "<str>", "Message to send over MQTT"),
        arg_str0("f", "file", "<fn>", "file to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int alen = 0;
    char addr[256] = {0x00};
    int res = CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)addr, sizeof(addr), &alen);

    int plen = 0;
    char port[10 + 1] = {0x00};
    res |= CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)port, sizeof(port), &plen);

    int tlen = 0;
    char topic[128] = {0x00};
    res |= CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)topic, sizeof(topic), &tlen);

    int mlen = 0;
    char msg[128] = {0x00};
    res |= CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)msg, sizeof(msg), &mlen);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    // Error message if... an error occured.
    if (res) {
        PrintAndLogEx(FAILED, "Error parsing input strings");
        return PM3_EINVARG;
    }

    if (alen == 0) {
        if (strlen(g_session.mqtt_server)) {
            strcpy(addr, g_session.mqtt_server);
        } else {
            strcpy(addr, "proxdump.com");
        }
    }

    if (plen == 0) {
        if (strlen(g_session.mqtt_port)) {
            strcpy(port, g_session.mqtt_port);
        } else {
            strcpy(port, "1883");
        }
    }

    if (tlen == 0) {
        if (strlen(g_session.mqtt_topic)) {
            strcpy(topic, g_session.mqtt_topic);
        } else {
            strcpy(topic, "proxdump");
        }
    }

    if (fnlen) {
        return mqtt_send(addr, port, topic, NULL, filename);
    }

    if (mlen) {
        return mqtt_send(addr, port, topic, msg, NULL);
    }
    return PM3_SUCCESS;
}

static int CmdMqttReceive(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mqtt receive",
                  "This command receives MQTT messages.  JSON text will be saved to file if detected\n"
                  "Default server:  proxdump.com:1883  topic: proxdump\n",
                  "mqtt receive       --> listening to default server/port/topic\n"
                  "mqtt receive --addr test.mosquitto.org -p 1883 --topic pm3\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "addr", "<str>", "MQTT server address"),
        arg_str0("p", "port", "<str>", "MQTT server port"),
        arg_str0(NULL, "topic", "<str>", "MQTT topic"),
        arg_str0("f", "file", "<fn>", "file name to use for received files"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int alen = 0;
    char addr[256] = {0x00};
    int res = CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)addr, sizeof(addr), &alen);

    int plen = 0;
    char port[10 + 1] = {0x00};
    res |= CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)port, sizeof(port), &plen);

    int tlen = 0;
    char topic[128] = {0x00};
    res |= CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)topic, sizeof(topic), &tlen);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    // Error message if... an error occured.
    if (res) {
        PrintAndLogEx(FAILED, "Error parsing input strings");
        return PM3_EINVARG;
    }

    if (alen == 0) {
        if (strlen(g_session.mqtt_server)) {
            strcpy(addr, g_session.mqtt_server);
        } else {
            strcpy(addr, "proxdump.com");
        }
    }

    if (plen == 0) {
        if (strlen(g_session.mqtt_port)) {
            strcpy(port, g_session.mqtt_port);
        } else {
            strcpy(port, "1883");
        }
    }

    if (tlen == 0) {
        if (strlen(g_session.mqtt_topic)) {
            strcpy(topic, g_session.mqtt_topic);
        } else {
            strcpy(topic, "proxdump");
        }
    }

    return mqtt_receive(addr, port, topic, filename);
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,          AlwaysAvailable, "This help"},
    {"send",     CmdMqttSend,      AlwaysAvailable, "Send messages or json file over MQTT"},
    {"receive",  CmdMqttReceive,   AlwaysAvailable, "Receive message or json file over MQTT"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return 0;
}

int CmdMqtt(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
