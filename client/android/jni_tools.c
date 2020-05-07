//
// Created by DXL on 2017/9/1.
//

//including header
#include <malloc.h>
#include <jni_tools.h>
#include "stdbool.h"

//当前线程是否添加的标志位
static bool g_IsAttach;

//TODO 环境变量获取函数
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

//解绑线程env
void deatchThread() {
    if (g_IsAttach) {
        LOGD("线程解绑成功!");
        (*g_JavaVM)->DetachCurrentThread(g_JavaVM);
    }
}

//TODO 命令行解析
CMD *parse_command_line(const char *commandStr) {
    //一个指针，指向传进来的命令字符串（const修饰的，我们需要复刻一份!）
    CMD *cmd = (CMD *) malloc(sizeof(CMD));
    if (!cmd) {
        LOGD("申请空间失败!");
        return NULL;
    }
    //拷贝字符串到堆空间!
    char *pTmp = strdup(commandStr);
    LOGD("拷贝参数字符串到临时堆!");
    //返回的结果!先初始化为20个空间
    int size = 20;
    cmd->cmd = (char **) malloc(size * sizeof(char **));
    if (cmd->cmd) {
        LOGD("申请参数空间成功!");
    } else {
        LOGD("申请空间失败!");
    }
    //进行截取
    char *pStr = strtok(pTmp, " ");
    LOGD("第0次截取完成: %s", pStr);
    //给结果数组进行下标为0的第一次初始化
    cmd->cmd[0] = pStr;
    //局部变量用于储存解析到的命令个数，下标移动为一
    int count = 1;
    //需要截取命令参数，以空格为限定符
    for (; pStr != NULL; ++count) {
        //如果容量不够，则扩容!
        if (count == (size - 1)) {
            size += 20;
            cmd->cmd = (char **) realloc(cmd->cmd, size * sizeof(char **));
            LOGD("超过初始容量，自动扩容!");
        }
        pStr = strtok(NULL, " ");
        if (pStr) {
            cmd->cmd[count] = pStr;
            LOGD("第%d次截取完成: %s", count, pStr);
        }
    }
    cmd->len = (count - 1);
    LOGD("解析函数执行完成!");
    return cmd;
}

//内存释放
void free_command_line(CMD *cmd) {
    //二级指针需要逐层释放!
    LOGD("释放命令行字符串二级引用!");
    free(cmd->cmd[0]);
    LOGD("释放命令行一级引用!");
    free(cmd->cmd);
    LOGD("释放结构体内存");
    free(cmd);
}
