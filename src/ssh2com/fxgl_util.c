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

struct timespec g_fxgl_keepalive_ts; /* fxglģ�鱣��ʱ��� */

/* ����ʼ���ͼӽ������ */
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

    /* 48�������߳���fxgl_server���߳�ͨ���һ������ţ���Ҫ��ʼ��48���� */
    for (i = 0; i < FXGL_COM_THREADS_NUM; i++) {
        fxgl_initlock(&g_fxgl_com_info[i].g_fxgl_cominfo_lock);
    }
}

/**
* ���ļ�����
* @fd: �ļ����
* @buf:��ȡ�ļ����ݴ洢��ַ
* @len:��ȡ�ļ����ݳ���
* @return:д��ɹ�����д�볤�ȣ����򷵻�-1
* @note:
*    ��ֹread���ź��жϵ��¶�ȡ������
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
            /* �����ļ�ĩβ�ˣ������Ѿ��������ַ����� */
            return len;
        }
        tmp_buf += ret;
        left -= ret;
        len += ret;
    }

    return len;
}

/**
* д�ļ�����
* @fd: �ļ����
* @buf:д���ļ����ݵ�ַ
* @len:д���ļ����ݳ���
* @return:д��ɹ�����д�볤�ȣ����򷵻�-1
* @note:
*    ��ֹwrite���ź��жϵ���д�벻����
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
 * fxgl_set_bk -- ����fd����״̬
 * @fd: ������������
 * @bk: �ж������Ƿ�����
 * @return: ��
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
 * fxgl_get_date -- ��ȡ��ǰ����ʱ��
 * @cur_date: ��ȡ��ʱ�䣬�ַ�����ʽ��ʾ
 * @return: �޷���ֵ
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
 * fxgl_session_malloc --���붯̬�ڴ�
 * @sz: Ҫ������ڴ��С
 * @return: ����ɹ�,����ָ����ڴ��ָ�룻ʧ�ܣ�����NULL
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
 * fxgl_session_free --�ͷŶ�̬�ڴ�
 * @ptr: Ҫ�ͷŵ��ڴ�ָ��
 *
 * ����ֵ:
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
        /* ����������"TMPDIR"��ȡʧ�ܣ���ֱ�Ӹ�Ϊ"/tmp" */
        path_prefix = "/tmp";
    }

    strncpy(path, path_prefix, path_len - 1);
    strncat(path, path_suffix, path_len - strlen(path) - 1);
}

/**
* fxgl_handle_sigalrm - �źŴ�����
* @s: �ź�
* @return:
* @note:
*/
static void fxgl_handle_sigalrm(int sig)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    /* �����̳���10����δ��Ӧ������������ */
    if (ts.tv_sec - g_fxgl_keepalive_ts.tv_sec > FXGL_KEEPALIVE_TIMEOUT) {
        logit("FXGL: Fxgl process may be busy in %ld sec!\r\n",
            ts.tv_sec - g_fxgl_keepalive_ts.tv_sec);
        chdir("/");
        raise(SIGABRT);
    }

    (void)alarm(FXGL_KEEPALIVE_TIMER);
}

/**
* fxgl_keepalive_init - ��ʼ���������
* @return:
* @note:
*/
void fxgl_keepalive_init(void)
{
    /* ��ʼ������ʱ��� */
    (void)clock_gettime(CLOCK_MONOTONIC, &g_fxgl_keepalive_ts);

    /* �������ʱ�� */
    (void)alarm(FXGL_KEEPALIVE_TIMER);
}

/**
* fxgl_init_signo - ��ʼ���ź���
* @return:
* @note:
*/
void fxgl_init_signo(void)
{
    /* ���ιܵ������ź� */
    (void)signal(SIGPIPE, SIG_IGN);

    /* ����������źŶ�ʱ�� */
    if (signal(SIGALRM, fxgl_handle_sigalrm) == SIG_ERR) {
        debug("FXGL: Cli-Server: can't catch SIGALRM, err:%s\n", strerror(errno));
    }
}