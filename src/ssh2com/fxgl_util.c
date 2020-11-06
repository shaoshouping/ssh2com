/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */
/*
 * fxgl_util.c
 * Original Author: chengzhengnan@ruijie.com.cn, 2020-09-01
 *
 * History
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/time.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>

#include "fxgl_util.h"
#include "fxgl_debug.h"
#include "fxgl_session.h"
#include "log.h"

struct timespec g_fxgl_keepalive_ts; /* fxgl模块保活时间戳 */

/* 锁初始化和加解锁相关 */
void fxgl_com_info_lock(int com_index)
{
    if (pthread_mutex_lock(&g_fxgl_com_info[com_index].g_fxgl_cominfo_lock)) {
        debug("FXGL: Failure in trying to lock %d com info mutex\n", com_index);
        return;
    }
}

void fxgl_com_info_unlock(int com_index)
{
    if (pthread_mutex_unlock(&g_fxgl_com_info[com_index].g_fxgl_cominfo_lock)) {
        debug("FXGL: Failure in trying to unlock %d com info mutex\n", com_index);
        return;
    }
}

void fxgl_initlock(pthread_mutex_t *plock)
{
    pthread_mutexattr_t attr;

    if (plock == NULL) {
        goto err;
    }
    if (pthread_mutexattr_init(&attr) != 0) {
        goto err;
    }
    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP) != 0) {
        goto err;
    }
    if (pthread_mutex_init(plock, &attr) != 0) {
        goto err;
    }

    return;
err:
    pthread_mutexattr_destroy(&attr);
    exit(1);
}

void fxgl_cominfo_lock_init()
{
    int i;

    /* 48个串口线程与fxgl_server主线程通信且互不干扰，需要初始化48个锁 */
    for (i = 0; i < FXGL_COM_THREADS_NUM; i++) {
        fxgl_initlock(&g_fxgl_com_info[i].g_fxgl_cominfo_lock);
    }
}

/**
* 读文件函数
* @fd: 文件句柄
* @buf:读取文件数据存储地址
* @len:读取文件数据长度
* @return:写入成功返回写入长度，否则返回-1
* @note:
*    防止read被信号中断导致读取不完整
*/
int fxgl_read(int fd, char *buf, int len)
{
    int left;
    int ret;
    char *tmp_buf;
    
    left = len;
    tmp_buf = buf;
    len = 0;
    while (left > 0) {
        ret = (int)read(fd, tmp_buf, left);
        if (ret < 0) {
            switch (errno) {
            case EINTR:
                /* FALLTHROUGH */ 
            case EAGAIN:
                /* FALLTHROUGH */ 
            case EINPROGRESS:
                /* FALLTHROUGH */ 
#if (EWOULDBLOCK != EAGAIN)
            case EWOULDBLOCK:
#endif /* (EWOULDBLOCK != EAGAIN) */
                continue;
            default:
                break;
            }
            return ret;
        } else if (ret == 0) {
            /* 读到文件末尾了，返回已经读到的字符个数 */
            return len;
        }
        tmp_buf += ret;
        left -= ret;
        len += ret;
    }

    return len;
}

/**
* 写文件函数
* @fd: 文件句柄
* @buf:写入文件数据地址
* @len:写入文件数据长度
* @return:写入成功返回写入长度，否则返回-1
* @note:
*    防止write被信号中断导致写入不完整
*/
int fxgl_write(int fd, void *buf, int len)
{
    int left, ret;
    char *tmp_buf;
    
    left = len;
    tmp_buf = (char*)buf;
    while (left > 0) {
        ret = (int)write(fd, tmp_buf, left);
        if (ret < 0) {
            switch (errno) {
            case EINTR:
                /* FALLTHROUGH */ 
            case EAGAIN:
                /* FALLTHROUGH */ 
            case EINPROGRESS:
                /* FALLTHROUGH */ 
#if (EWOULDBLOCK != EAGAIN)
            case EWOULDBLOCK:
#endif /* (EWOULDBLOCK != EAGAIN) */
                continue;
            default:
                break;
            }
            return ret;
        }
        tmp_buf += ret;
        left -= ret;
    }
    return len;
}

/**
 * fxgl_set_bk -- 设置fd阻塞状态
 * @fd: 带设置描述符
 * @bk: 判断设置是否阻塞
 * @return: 无
 * @note:
 */
void fxgl_set_bk(int fd, bool bk)
{
    int opt;

    if(bk) {
        opt = 0;
    } else {
        opt = 1;
    }
    
    (void)ioctl(fd, FIONBIO, &opt, sizeof(opt));
}

/**
 * fxgl_get_date -- 获取当前日期时间
 * @cur_date: 获取的时间，字符串形式表示
 * @return: 无返回值
 * @note:
 */
void fxgl_get_date(char *cur_date)
{
    struct tm          *p;
    time_t             timep;

    if (cur_date == NULL) {
        return;
    }

    (void)time(&timep);
    p = localtime(&timep);
    sprintf(cur_date, "%04d-%02d-%02d %02d:%02d:%02d", (p->tm_year + 1900), (p->tm_mon + 1), p->tm_mday , p->tm_hour, p->tm_min, p->tm_sec);
}

/**
 * fxgl_session_malloc --申请动态内存
 * @sz: 要申请的内存大小
 * @return: 申请成功,返回指向该内存的指针；失败，返回NULL
 * @note:
 */
void *fxgl_session_malloc(size_t sz)
{
    void   *ptr;

    if (sz == 0 || (ptr = malloc(sz)) == NULL) {
        return NULL;
    }
    memset(ptr, 0, sz);

    return ptr;
}

/**
 * fxgl_session_free --释放动态内存
 * @ptr: 要释放的内存指针
 *
 * 返回值:
 */
void fxgl_session_free(void *ptr)
{
    if (ptr != NULL) {
        free(ptr);
        ptr = NULL;
    }

    return;
}

void fxgl_make_tmp_path(char *path_suffix, char *path, int path_len)
{
    char *path_prefix;

    memset(path, 0, path_len);
    path_prefix = getenv("TMPDIR");
    if (path_prefix == NULL) {
        /* 若环境变量"TMPDIR"获取失败，则直接赋为"/tmp" */
        path_prefix = "/tmp";
    }

    strncpy(path, path_prefix, path_len - 1);
    strncat(path, path_suffix, path_len - strlen(path) - 1);
}

/**
* fxgl_handle_sigalrm - 信号处理函数
* @s: 信号
* @return:
* @note:
*/
static void fxgl_handle_sigalrm(int sig)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    /* 主进程超过10分钟未响应，则重启进程 */
    if (ts.tv_sec - g_fxgl_keepalive_ts.tv_sec > FXGL_KEEPALIVE_TIMEOUT) {
        logit("FXGL: Fxgl process may be busy in %ld sec!\r\n",
            ts.tv_sec - g_fxgl_keepalive_ts.tv_sec);
        chdir("/");
        raise(SIGABRT);
    }

    (void)alarm(FXGL_KEEPALIVE_TIMER);
}

/**
* fxgl_keepalive_init - 初始化保活诊断
* @return:
* @note:
*/
void fxgl_keepalive_init(void)
{
    /* 初始化保活时间戳 */
    (void)clock_gettime(CLOCK_MONOTONIC, &g_fxgl_keepalive_ts);

    /* 启动保活定时器 */
    (void)alarm(FXGL_KEEPALIVE_TIMER);
}

/**
* fxgl_init_signo - 初始化信号量
* @return:
* @note:
*/
void fxgl_init_signo(void)
{
    /* 屏蔽管道破裂信号 */
    (void)signal(SIGPIPE, SIG_IGN);

    /* 主进程添加信号定时器 */
    if (signal(SIGALRM, fxgl_handle_sigalrm) == SIG_ERR) {
        debug("FXGL: Cli-Server: can't catch SIGALRM, err:%s\n", strerror(errno));
    }
}