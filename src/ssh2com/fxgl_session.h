/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */
/*
 * fxgl_session.h
 * Original Author: chengzhengnan@ruijie.com.cn, 2020-09-01
 *
 * History
 */
#ifndef _FXGL_SESSION_H
#define _FXGL_SESSION_H

#include "list.h"

#include "fxgl_main.h"
#include "fxgl_util.h"

#define FXGL_MAX_IPLEN 64
#define FXGL_MAX_UNAMELEN 256
#define FXGL_MAX_TIMELEN 64
#define FXGL_MAX_BUFLEN 2048
#define FXGL_FILENAME_MAXLEN 64
#define FXGL_MAX_INDEXNUM 20
#define FXGL_MAX_PATHLEN 256
#define FXGL_COM_PORT_START 2001

typedef enum {
    SESSION_TYPE_SSH,       /* SSH会话 */
    SESSION_TYPE_TELNET,    /* TELNET会话 */
    SESSION_TYPE_MAX,
} session_type_t;

typedef enum {
    USER_PRIVILEGE_NONE,      /* 未知权限 */
    USER_PRIVILEGE_READ,      /* read权限 */
    USER_PRIVILEGE_ADMIN,     /* admin权限 */
    USER_PRIVILEGE_MAX,
} user_privilege_t;

typedef struct _session_info_s
{
    struct list_head list;
    int session_index;                 /* 会话索引 1-20 */
    int sock;                          /* 与SSH组件的连接FD */
    int com_num;                       /* 会话关联的串口号 */
    session_type_t session_type;       /* 会话类型 */
    user_privilege_t user_priv;        /* 用户权限 */
    long last_op_time;                 /* 上次输入时间，用于计算空闲时间，记录CPU时间 */
    char username[FXGL_MAX_UNAMELEN];  /* 登陆用户名 */
    char login_ip[FXGL_MAX_IPLEN];     /* 登陆IP，格式化 */
    char login_time[FXGL_MAX_TIMELEN]; /* 登陆时间，采用系统时间，格式化 */
    char *send_buf;                    /* 发送给SSH客户的缓存空间 */
} session_info_t;

typedef struct _com_info_s
{
    int com_index;                       /* 串口索引1-48 */
    int port;                            /* 协议登陆端口 */
    pthread_t thread_id;                 /* 线程ID */
    pid_t pid;                           /* picocom子进程id */
    pthread_mutex_t g_fxgl_cominfo_lock; /* 串口线程资源锁 */
    bool sess_used[FXGL_MAX_INDEXNUM];   /* 会话索引占用 true占用/ false未占用 */
    char com_name[FXGL_MAX_UNAMELEN];    /* 串口名称 */
    char write_buf[FXGL_MAX_BUFLEN];     /* 串口写入缓存 */
    struct list_head session_head;       /* 会话链表 */
} com_info_t;

typedef struct fxgl_sess_fd_s
{
    int *sess_fd;
    char sess_info_path[FXGL_FILENAME_MAXLEN];
} fxgl_sess_fd_t;

typedef struct {
    int fxgl_inpipefd[2];                  /* 进入反向模块主进程的单向pipe */
    int fxgl_outpipefd[2];                 /* 进入picocom子进程的单向pipe */
} fxgl_pipe_event_t;

com_info_t g_fxgl_com_info[FXGL_COM_THREADS_NUM];

/* 串口线程与picocom子进程通信pipe */
fxgl_pipe_event_t g_fxgl_pipe_event[FXGL_COM_THREADS_NUM];

/* 反向管理服务端初始化 */
int fxgl_server_init(void);

#endif