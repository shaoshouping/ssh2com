/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */
/*
 * fxgl_util.h
 * Original Author: chengzhengnan@ruijie.com.cn, 2020-09-01
 *
 * History
 */
#ifndef _FXGL_UTIL_H
#define _FXGL_UTIL_H

#include <sys/types.h>
#include <pthread.h>

#define MAX_STR_LEN 256
#define FXGL_KEEPALIVE_TIMER 60
#define FXGL_KEEPALIVE_TIMEOUT 600

/* ������ؽӿ� */
void fxgl_keepalive_init(void);
void fxgl_init_signo(void);

/* �����ļ�·���ӿ� */
void fxgl_make_tmp_path(char *path_suffix, char *path, int path_len);

/* �ռ������ؽӿ� */
void *fxgl_session_malloc(size_t sz);
void fxgl_session_free(void *ptr);

/* ��ȡϵͳʱ�� */
void fxgl_get_date(char *cur_date);

/* ����fd����/������ */
void fxgl_set_bk(int fd, bool bk);

/* ����� */
void fxgl_com_info_lock(int com_index);
void fxgl_com_info_unlock(int com_index);
void fxgl_cominfo_lock_init(void);

/* ��д�ļ���� */
int fxgl_read(int fd, char *buf, int len);
int fxgl_write(int fd, void *buf, int len);

#endif