//
// Created by dell on 2017/9/1.
//

#ifndef DXL_TOOLS_H
#define DXL_TOOLS_H

#include <jni.h>
#include <android/log.h>
#include <string.h>

//JNI LOG
#define TAG "PM3"
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE,TAG,__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG,__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)

// a global jvm instance
JavaVM *g_JavaVM;

// get current env for jvm
JNIEnv *getJniEnv();

// detach native thread from jvm， must native thread can detach!
void detachThread();

typedef struct {
    char **cmd;
    int len;
} CMD;

// cmd arg parse
CMD *parse_command_line(const char *commandStr);

// cmd arg struct free
void free_command_line(CMD *);

#endif //DXL_TOOLS_H
