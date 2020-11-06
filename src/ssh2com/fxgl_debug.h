/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */
/*
 * fxgl_debug.h
 * Original Author: chengzhengnan@ruijie.com.cn, 2020-09-01
 *
 * History
 */
#ifndef _FXGL_DEBUG_H
#define _FXGL_DEBUG_H

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>

extern bool g_fxgl_debug;

void fxgl_command_init(void);

#define FXGL_DEBUG_MSG(fmt, arg...) printf("[%s: %d][DEBUG] " fmt, __func__, __LINE__, ##arg)

#define FXGL_ERROR_MSG(fmt, arg...) printf("[%s: %d][ERROR] " fmt, __func__, __LINE__, ##arg)

#endif