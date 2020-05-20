//-----------------------------------------------------------------------------
// Copyright (C) 2009 Michael Gernoth <michael at gernoth.net>
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Main binary
//-----------------------------------------------------------------------------

#include "proxmark3.h"

#include <stdlib.h>
#include <stdio.h>         // for Mingw readline
#include <limits.h>
#include <unistd.h>
#include <ctype.h>
#include "usart_defs.h"
#include "util_posix.h"
#include "proxgui.h"
#include "cmdmain.h"
#include "ui.h"
#include "cmdhw.h"
#include "whereami.h"
#include "comms.h"
#include "fileutils.h"
#include "jni_tools.h"

#define LOCAL_SOCKET_SERVER_NAME "DXL.COM.ASL"

void ShowGraphWindow() {

}

void HideGraphWindow(void) {

}

void RepaintGraphWindow() {

}

int push_cmdscriptfile(char *path, bool stayafter) {
    return PM3_SUCCESS;
}

static char *g_android_my_executable_path = NULL;
static char *g_android_my_executable_directory = NULL;

const char *get_my_executable_path(void) {
    return g_android_my_executable_path;
}

const char *get_my_executable_directory(void) {
    if (g_android_my_executable_directory != NULL) free(g_android_my_executable_directory);
    char buf[1024];
    // get current work directory
    getcwd(buf, sizeof(buf));
    // add / to end.
    sprintf(buf, "%s%s", buf, PATHSEP);
    // create on global
    g_android_my_executable_directory = strdup(buf);
    return g_android_my_executable_directory;
}

static void set_my_executable_path(void) {

}

static const char *my_user_directory = NULL;

const char *get_my_user_directory(void) {
    return my_user_directory;
}

static void set_my_user_directory(void) {
}

static bool open() {
    if (conn.run) {
        return true;
    }
    // Open with LocalSocket(Not a tcp connection!)
    bool ret = OpenProxmark("socket:"LOCAL_SOCKET_SERVER_NAME, false, 1000, false, 115200);
    return ret;
}

/*
 * Transfers to the command buffer and waits for a new command to be executed
 * */
jint sendCMD(JNIEnv *env, jobject instance, jstring cmd_) {
    //may be pm3 not running.
    if (!conn.run) {
        if (open() && TestProxmark() == PM3_SUCCESS) {
            LOGD("Open Successfully!");
            PrintAndLogEx(NORMAL, "Open Successfully!");
        } else {
            LOGD("Open failed!");
            PrintAndLogEx(NORMAL, "Open failed!");
            CloseProxmark();
        }
    }
    // display on new line
    PrintAndLogEx(NORMAL, "\n");
    char *cmd = (char *) ((*env)->GetStringUTFChars(env, cmd_, 0));
    int ret = CommandReceived(cmd);
    if (ret == 99) {
        // exit / quit
        // TODO: implement this
        PrintAndLogEx(NORMAL, "Asked to exit, can't really do that yet...");
    }
    (*env)->ReleaseStringUTFChars(env, cmd_, cmd);
    return ret;
}

/*
 * Is client running!
 * */
jboolean isExecuting(JNIEnv *env, jobject instance) {
    return (jboolean) ((jboolean) conn.run);
}

/*
 * test hw and hw and client.
 * */
jboolean testPm3(JNIEnv *env, jobject instance) {
    bool ret1 = open();
    if (!ret1) {
        CloseProxmark();
        return false;
    }
    bool ret2 = TestProxmark() == PM3_SUCCESS;
    return (jboolean) (ret1 && ret2);
}

/*
 * stop pm3 client
 * */
void stopPm3(JNIEnv *env, jobject instance) {
    CloseProxmark();
}

/*
 * native function map to jvm
 * */
JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *jniEnv = NULL;
    if ((*vm)->GetEnv(vm, (void **) &jniEnv, JNI_VERSION_1_4) != JNI_OK) {
        return -1;
    }
    (*jniEnv)->GetJavaVM(jniEnv, &g_JavaVM);
    jclass clazz = (*jniEnv)->FindClass(jniEnv, "cn/rrg/natives/Proxmark3RRGRdv4Tools");
    if (clazz == NULL) {
        return -1;
    }
    jclass clz_test = (*jniEnv)->FindClass(jniEnv, "cn/rrg/devices/Proxmark3RRGRdv4");
    JNINativeMethod methods[] = {
            {"startExecute", "(Ljava/lang/String;)I", (void *) sendCMD},
            {"stopExecute",  "()V",                   (void *) stopPm3},
            {"isExecuting",  "()Z",                   (void *) isExecuting}
    };
    JNINativeMethod methods1[] = {
            {"testPm3",  "()Z", (void *) testPm3},
            {"closePm3", "()V", stopPm3}
    };
    if ((*jniEnv)->RegisterNatives(jniEnv, clazz, methods, sizeof(methods) / sizeof(methods[0])) !=
        JNI_OK) {
        return -1;
    }
    if ((*jniEnv)->RegisterNatives(jniEnv, clz_test, methods1,
                                   sizeof(methods1) / sizeof(methods1[0])) !=
        JNI_OK) {
        return -1;
    }
    (*jniEnv)->DeleteLocalRef(jniEnv, clazz);
    (*jniEnv)->DeleteLocalRef(jniEnv, clz_test);
    return JNI_VERSION_1_4;
}
