/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 *
/*
 * util.c
 * Original Author: linxingqiang@ruijie.com.cn, 2020-09-01
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
#include <fcntl.h>
#include <ctype.h>


#include "../ssh2com/log.h"
#include "console_util.h"

/* set/unset filedescriptor to non-blocking */
int set_nonblock(int fd) {
	int val;

	val = fcntl(fd, F_GETFL);
	if (val < 0) {
		error("fcntl(%d, F_GETFL): %s", fd, strerror(errno));
		return (-1);
	}
	if (val & O_NONBLOCK) {
		debug3("fd %d is O_NONBLOCK", fd);
		return (0);
	}
	debug2("fd %d setting O_NONBLOCK", fd);
	val |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, val) == -1) {
		debug("fcntl(%d, F_SETFL, O_NONBLOCK): %s", fd,
		    strerror(errno));
		return (-1);
	}
	return (0);
}

/**
 * console_malloc --申请动态内存
 * @sz: 要申请的内存大小
 * @return: 申请成功,返回指向该内存的指针；失败，返回NULL
 * @note:
 */
void *console_malloc(size_t sz)
{
    void   *ptr;
    if (sz == 0 || (ptr = malloc(sz)) == NULL) {
        return NULL;
    }
    memset(ptr, 0, sz);
    return ptr;
}

/**
 * console_free --释放动态内存
 * @ptr: 要释放的内存指针
 *
 * 返回值:
 */
void console_free(void *ptr)
{
    if (ptr != NULL) {
        free(ptr);
        ptr = NULL;
    }
}

int is_int(char* str)
{
    int len;
    len = strlen(str);
    int i=0;
    for(; i<len; i++) {
        if(!(isdigit(str[i])))
            return 0;
    }
    return 1;
}

