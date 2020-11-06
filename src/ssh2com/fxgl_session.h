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
    SESSION_TYPE_SSH,       /* SSH�Ự */
    SESSION_TYPE_TELNET,    /* TELNET�Ự */
    SESSION_TYPE_MAX,
} session_type_t;

typedef enum {
    USER_PRIVILEGE_NONE,      /* δ֪Ȩ�� */
    USER_PRIVILEGE_READ,      /* readȨ�� */
    USER_PRIVILEGE_ADMIN,     /* adminȨ�� */
    USER_PRIVILEGE_MAX,
} user_privilege_t;

typedef struct _session_info_s
{
    struct list_head list;
    int session_index;                 /* �Ự���� 1-20 */
    int sock;                          /* ��SSH���������FD */
    int com_num;                       /* �Ự�����Ĵ��ں� */
    session_type_t session_type;       /* �Ự���� */
    user_privilege_t user_priv;        /* �û�Ȩ�� */
    long last_op_time;                 /* �ϴ�����ʱ�䣬���ڼ������ʱ�䣬��¼CPUʱ�� */
    char username[FXGL_MAX_UNAMELEN];  /* ��½�û��� */
    char login_ip[FXGL_MAX_IPLEN];     /* ��½IP����ʽ�� */
    char login_time[FXGL_MAX_TIMELEN]; /* ��½ʱ�䣬����ϵͳʱ�䣬��ʽ�� */
    char *send_buf;                    /* ���͸�SSH�ͻ��Ļ���ռ� */
} session_info_t;

typedef struct _com_info_s
{
    int com_index;                       /* ��������1-48 */
    int port;                            /* Э���½�˿� */
    pthread_t thread_id;                 /* �߳�ID */
    pid_t pid;                           /* picocom�ӽ���id */
    pthread_mutex_t g_fxgl_cominfo_lock; /* �����߳���Դ�� */
    bool sess_used[FXGL_MAX_INDEXNUM];   /* �Ự����ռ�� trueռ��/ falseδռ�� */
    char com_name[FXGL_MAX_UNAMELEN];    /* �������� */
    char write_buf[FXGL_MAX_BUFLEN];     /* ����д�뻺�� */
    struct list_head session_head;       /* �Ự���� */
} com_info_t;

typedef struct fxgl_sess_fd_s
{
    int *sess_fd;
    char sess_info_path[FXGL_FILENAME_MAXLEN];
} fxgl_sess_fd_t;

typedef struct {
    int fxgl_inpipefd[2];                  /* ���뷴��ģ�������̵ĵ���pipe */
    int fxgl_outpipefd[2];                 /* ����picocom�ӽ��̵ĵ���pipe */
} fxgl_pipe_event_t;

com_info_t g_fxgl_com_info[FXGL_COM_THREADS_NUM];

/* �����߳���picocom�ӽ���ͨ��pipe */
fxgl_pipe_event_t g_fxgl_pipe_event[FXGL_COM_THREADS_NUM];

/* ����������˳�ʼ�� */
int fxgl_server_init(void);

#endif