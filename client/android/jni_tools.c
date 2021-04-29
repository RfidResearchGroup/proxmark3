//
// Created by DXL on 2017/9/1.
//

//including header
#include <malloc.h>
#include <jni_tools.h>
#include "stdbool.h"

// native thread attach label
static bool g_IsAttach;

// get current env for jvm
JNIEnv *getJniEnv() {
    JNIEnv *currentThreadEnv;
    g_IsAttach = false;
    if ((*g_JavaVM)->GetEnv(g_JavaVM, (void **) &currentThreadEnv, JNI_VERSION_1_4) != JNI_OK) {
        LOGE("Get Env Fail!");
        if ((*g_JavaVM)->AttachCurrentThread(g_JavaVM, &currentThreadEnv, NULL) != JNI_OK) {
            LOGE("Attach the current thread Fail!");
            g_IsAttach = false;
            return NULL;
        } else {
            g_IsAttach = true;
            LOGE("Attach the current thread Success!");
            return currentThreadEnv;
        }
    } else {
        g_IsAttach = false;
        //LOGE("Get Env Success!");
        return currentThreadEnv;
    }
}

// detach native thread from jvm
void detachThread() {
    if (g_IsAttach) {
        (*g_JavaVM)->DetachCurrentThread(g_JavaVM);
    }
}

//  cmd arg parse
CMD *parse_command_line(const char *commandStr) {
    CMD *cmd = (CMD *) malloc(sizeof(CMD));
    if (!cmd) {
        return NULL;
    }
    // copy the source to the heap
    char *pTmp = strdup(commandStr);
    // new memory size is default 20 for char **
    int size = 20;
    cmd->cmd = (char **) malloc(size * sizeof(char **));
    if (!cmd->cmd) {
        free(cmd);
        return NULL;
    }
    // parse
    char *pStr = strtok(pTmp, " ");
    cmd->cmd[0] = pStr;
    int count = 1;
    for (; pStr != NULL; ++count) {
        // Capacity expansion
        if (count == (size - 1)) {
            size += 20;
            cmd->cmd = (char **) realloc(cmd->cmd, size * sizeof(char **));
        }
        pStr = strtok(NULL, " ");
        if (pStr) {
            cmd->cmd[count] = pStr;
        }
    }
    cmd->len = (count - 1);
    return cmd;
}

// cmd arg struct free
void free_command_line(CMD *cmd) {
    free(cmd->cmd[0]);
    free(cmd->cmd);
    free(cmd);
}
