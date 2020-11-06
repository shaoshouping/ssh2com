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

/* 保活相关接口 */
void fxgl_keepalive_init(void);
void fxgl_init_signo(void);

/* 创建文件路径接口 */
void fxgl_make_tmp_path(char *path_suffix, char *path, int path_len);

/* 空间分配相关接口 */
void *fxgl_session_malloc(size_t sz);
void fxgl_session_free(void *ptr);

/* 获取系统时间 */
void fxgl_get_date(char *cur_date);

/* 设置fd阻塞/非阻塞 */
void fxgl_set_bk(int fd, bool bk);

/* 锁相关 */
void fxgl_com_info_lock(int com_index);
void fxgl_com_info_unlock(int com_index);
void fxgl_cominfo_lock_init(void);

/* 读写文件相关 */
int fxgl_read(int fd, char *buf, int len);
int fxgl_write(int fd, void *buf, int len);

#endif