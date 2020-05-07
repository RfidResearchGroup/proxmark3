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

static char *my_executable_path = NULL;
static char *my_executable_directory = NULL;

const char *get_my_executable_path(void) {
    return my_executable_path;
}

const char *get_my_executable_directory(void) {
    return my_executable_directory;
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
 * 发送一条命令等待执行!
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
    //无论如何，新的命令的输入了，就要换个行!
    PrintAndLogEx(NORMAL, "\n");
    char *cmd = (char *)((*env)->GetStringUTFChars(env, cmd_, 0));
    // Many parts of the PM3 client will assume that they can read any write from pwd. So we set
    // pwd to whatever the PM3 "executable directory" is, to get consistent behaviour.
    /*int ret = chdir(get_my_executable_directory());
    if (ret == -1) {
        LOGW("Couldn't chdir(get_my_executable_directory()), errno=%s", strerror(errno));
    }
    char pwd[1024];
    memset((void *) &pwd, 0, sizeof(pwd));
    getcwd((char *) &pwd, sizeof(pwd));
    LOGI("pwd = %s", pwd);*/
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
 * 是否在执行命令
 * */
jboolean isExecuting(JNIEnv *env, jobject instance) {
    return (jboolean)((jboolean) conn.run);
}

/*
 * 进行设备链接验证!
 * */
jboolean testPm3(JNIEnv *env, jobject instance) {
    bool ret1 = open();
    if (!ret1) {
        CloseProxmark();
        return false;
    }
    bool ret2 = TestProxmark() == PM3_SUCCESS;
    return (jboolean)(ret1 && ret2);
}

void stopPm3(JNIEnv *env, jobject instance) {
    CloseProxmark();
}

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
        {"stopExecute",  "()V", (void *) stopPm3},
        {"isExecuting",  "()Z", (void *) isExecuting}
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
