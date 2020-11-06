/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */
/*
 * util.h
 * Original Author: linxingqiang@ruijie.com.cn, 2020-09-01
 *
 * History
 */
#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>
#include <pthread.h>

#define BUF_MAX_LEN 256
#define MSG_MAX_LEN 8000
#define HAVE_DECL_O_NONBLOCK 1

#if defined(HAVE_DECL_O_NONBLOCK) && HAVE_DECL_O_NONBLOCK == 0
# define O_NONBLOCK      00004	/* Non Blocking Open */
#endif


/* 创建文件路径接口 */
void make_tmp_path(char *path_suffix, char *path, int path_len);

/* 空间分配相关接口 */
void *console_malloc(size_t sz);
void console_free(void *ptr);

/* 获取系统时间 */
void get_date(char *cur_date);

/* 设置fd阻塞/非阻塞 */
void set_bk(int fd, int bk);
int set_nonblock(int fd) ;
int is_int(char* str);

#endif
