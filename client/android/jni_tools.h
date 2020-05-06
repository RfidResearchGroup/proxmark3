//
// Created by dell on 2017/9/1.
//

#ifndef DXL_TOOLS_H
#define DXL_TOOLS_H

#include <jni.h>
#include <android/log.h>
#include <string.h>

//JNI LOG
#define TAG "DXL BlUESPP_PN532"
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE,TAG,__VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,TAG,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,TAG,__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,TAG,__VA_ARGS__)

//全局的环境变量定义
JavaVM *g_JavaVM;

//线程环境指针获取函数
JNIEnv *getJniEnv();

//子线程释放函数,必须是native层创建的线程才可以调用
void deatchThread();

typedef struct {
    char **cmd;
    int len;
} CMD;

//命令行解析函数
CMD *parse_command_line(const char *commandStr);

//解析结果释放函数!
void free_command_line(CMD *);

#endif //DXL_TOOLS_H