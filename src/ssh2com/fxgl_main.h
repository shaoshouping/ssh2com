/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */
/*
 * fxgl_main.h
 * Original Author: chengzhengnan@ruijie.com.cn, 2020-09-01
 *
 * History
 */
#ifndef _FXGL_MAIN_H
#define _FXGL_MAIN_H

#define FXGL_COM_THREADS_NUM 48  /* 串口线程数量 */
#define FXGL_COM_TIMEOUT_PERIOD 120 /* 串口超时时间，默认2分钟 */
#define FXGL_NO_SESSION_SPEC -1
#define SSHD2COM_SUFFIX "_CLIENTSOCKET"

pthread_t g_fxgl_com_thread[FXGL_COM_THREADS_NUM - 1];

#endif