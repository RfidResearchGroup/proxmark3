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

//iceman, todo:  proxify socker server name.  Maybe set in preferences?
#define PM3_LOCAL_SOCKET_SERVER "DXL.COM.ASL"

void ShowGraphWindow(void) {
}

void HideGraphWindow(void) {
}

void RepaintGraphWindow(void) {
}

int push_cmdscriptfile(char *path, bool stayafter) {
    return PM3_SUCCESS;
}

static char *g_android_executable_directory = NULL;
static const char *g_android_user_directory = NULL;

const char *get_executable_directory(void) {

    if (g_android_executable_directory == NULL) {
        char buf[FILE_PATH_SIZE] = {0};
        getcwd(buf, sizeof(buf));
        strncat(buf, PATHSEP, 1);
        g_android_executable_directory = strdup(buf);
    }
    return g_android_executable_directory;
}

const char *get_user_directory(void) {
    return g_android_user_directory;
}

static bool OpenPm3(void) {
    if (conn.run) {
        return true;
    }
    // Open with LocalSocket. Not a tcp connection!
    bool ret = OpenProxmark(session.current_device, "socket:"PM3_LOCAL_SOCKET_SERVER, false, 1000, false, 115200);
    return ret;
}

/*
 * Transfers to the command buffer and waits for a new command to be executed
 * */
jint Console(JNIEnv *env, jobject instance, jstring cmd_) {

    if (!conn.run) {
        if (OpenPm3() && TestProxmark() == PM3_SUCCESS) {
            LOGD("Connected to device");
            PrintAndLogEx(SUCCESS, "Connected to device");
        } else {
            LOGD("Failed to connect to device");
            PrintAndLogEx(ERR, "Failed to connect to device");
            CloseProxmark();
        }
    }

    PrintAndLogEx(NORMAL, "");

    char *cmd = (char *)((*env)->GetStringUTFChars(env, cmd_, 0));
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
jboolean IsClientRunning(JNIEnv *env, jobject instance) {
    return (jboolean)((jboolean) conn.run);
}

/*
 * test hw and hw and client.
 * */
jboolean TestPm3(JNIEnv *env, jobject instance) {
    if (open() == false) {
        CloseProxmark();
        return false;
    }
    bool ret = (TestProxmark() == PM3_SUCCESS);
    return (jboolean)(ret);
}

/*
 * stop pm3 client
 * */
void ClosePm3(JNIEnv *env, jobject instance) {
    CloseProxmark();
}

/*
 * native function map to jvm
 * */

//iceman:  todo,  pm3:ify java class root.  Return codes, should match PM3_E* codes.
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
        {"startExecute", "(Ljava/lang/String;)I", (void *) Console},
        {"stopExecute",  "()V", (void *) ClosePm3},
        {"isExecuting",  "()Z", (void *) IsClientRunning}
    };

    JNINativeMethod methods1[] = {
        {"testPm3",  "()Z", (void *) TestPm3},
        {"closePm3", "()V", ClosePm3}
    };

    if ((*jniEnv)->RegisterNatives(jniEnv, clazz, methods, sizeof(methods) / sizeof(methods[0])) != JNI_OK) {
        return -1;
    }

    if ((*jniEnv)->RegisterNatives(jniEnv, clz_test, methods1, sizeof(methods1) / sizeof(methods1[0])) != JNI_OK) {
        return -1;
    }

    (*jniEnv)->DeleteLocalRef(jniEnv, clazz);
    (*jniEnv)->DeleteLocalRef(jniEnv, clz_test);
    return JNI_VERSION_1_4;
}
