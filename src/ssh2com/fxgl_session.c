/*
 * Copyright(C) 2020 Ruijie Network. All rights reserved.
 */
/*
 * fxgl_main.c
 * Original Author: chengzhengnan@ruijie.com.cn, 2020-09-01
 *
 * History
 */
#include <stdlib.h>  
#include <stdio.h>  
#include <stddef.h>  
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>  
#include <sys/syscall.h>
#include <sys/un.h>  
#include <sys/stat.h>
#include <errno.h>  
#include <string.h>  
#include <unistd.h>  
#include <ctype.h>  
#include <pthread.h> 
#include <time.h>
#include <fcntl.h>  

#include "list.h"
#include "fxgl_debug.h"
#include "fxgl_main.h"
#include "fxgl_util.h"
#include "fxgl_session.h"
#include "log.h"

#define UNIX_PATH_MAX 108
#define MAX_QUE_LEN 20
#define FXGL_COMNUM_MAP_OFFSET 2000
#define FXGL_SERVER_SOCK "/tmp/fxgl/ssh2com-server.sock"

static int fxgl_return_session_num(session_info_t *ssh_session_info, int com_map_num)
{
    int sess_num;
    struct list_head *list_tmp, *list_tmp_n;
    session_info_t *info;
    
    sess_num = 0;
    (void)fxgl_com_info_lock(com_map_num);
    if (list_empty(&g_fxgl_com_info[com_map_num].session_head)) {
        g_fxgl_com_info[com_map_num].sess_used[sess_num] = true;
        (void)fxgl_com_info_unlock(com_map_num);
        return sess_num;
    }

    list_for_each_safe(list_tmp, list_tmp_n, &g_fxgl_com_info[com_map_num].session_head) {
        info = list_entry(list_tmp, session_info_t, list);
        if (info->sock > 0 && info->session_index >= 0) {
            g_fxgl_com_info[com_map_num].sess_used[info->session_index] = true;
        }
        sess_num++;
    }
    (void)fxgl_com_info_unlock(com_map_num);

    return sess_num + 1;
}

static void fxgl_map_sess(session_info_t *ssh_session_info)
{
    int sess_num;
    int com_map_num;
    struct list_head *list_tmp, *list_tmp_n;
    session_info_t *info;

    com_map_num = ssh_session_info->com_num - FXGL_COMNUM_MAP_OFFSET - 1;
    sess_num = fxgl_return_session_num(ssh_session_info, com_map_num);
    ssh_session_info->session_index = sess_num;
    logit("FXGL: ALLOCATE session index SUCCESS! session_index = %d\n", ssh_session_info->session_index);
    (void)fxgl_com_info_lock(com_map_num);
    list_add_tail(&ssh_session_info->list, &g_fxgl_com_info[com_map_num].session_head);
    list_for_each_safe(list_tmp, list_tmp_n, &g_fxgl_com_info[com_map_num].session_head) {
        info = list_entry(list_tmp, session_info_t, list);
        if (info->sock > 0 && info->session_index >= 0) {
            logit("FXGL: new session has been added to the com_info, session_index = %d, sock_id = %d, com_port = %d, com_index = %d\n", \
                info->session_index, info->sock, info->com_num, com_map_num);
        }
    }
    (void)fxgl_com_info_unlock(com_map_num);
    logit("FXGL: Add session to com_info success!, com_index = %d\n", com_map_num);

    return;
}

static int fxgl_fill_session_info(char *key_str, char *val_str, session_info_t *ssh_session_info)
{
    if (strcmp(key_str, "CLIENT_IP") == 0) {
        memcpy(ssh_session_info->login_ip, val_str, sizeof(char) * FXGL_MAX_IPLEN);
    } else if (strcmp(key_str, "USERNAME") == 0) {
        memcpy(ssh_session_info->username, val_str, sizeof(char) * FXGL_MAX_UNAMELEN);
    } else if (strcmp(key_str, "PRIVILEGE") == 0) {
        ssh_session_info->user_priv = atoi(val_str);
    } else if (strcmp(key_str, "Login_type") == 0) {
        ssh_session_info->session_type = atoi(val_str);
    } else if (strcmp(key_str, "DEVICE_PORT") == 0) {
        if (atoi(val_str) < FXGL_COM_PORT_START) {
            debug("FXGL: Invalid device port %d, should larger than 2000!\n", atoi(val_str));
            return -1;
        }
        ssh_session_info->com_num = atoi(val_str);
    } else {
        debug("FXGL: false key word!\n");
        return -1;
    }

    logit("FXGL: login_ip = %s, device port = %d\n", ssh_session_info->login_ip, ssh_session_info->com_num);
    return 0;
}

static session_info_t *fxgl_new_session_info_init(int *fd)
{
    session_info_t *ssh_session_info;

    ssh_session_info = (session_info_t *)fxgl_session_malloc(sizeof(session_info_t));
    if (ssh_session_info == NULL) {
        debug("FXGL: new ssh session malloc fail!\n");
        return NULL;
    }
    ssh_session_info->last_op_time = 0;
    ssh_session_info->session_type = SESSION_TYPE_SSH;
    fxgl_get_date(ssh_session_info->login_time);
    ssh_session_info->sock = *fd;
    ssh_session_info->send_buf = (char *)fxgl_session_malloc(FXGL_MAX_BUFLEN);
    logit("FXGL: new session init succuss! sess_fd = %d\n", ssh_session_info->sock);

    return ssh_session_info;
}

static int fxgl_save_sess_info(fxgl_sess_fd_t *sess_info_fd)
{
    FILE *pfd;
    char tmp_buf[FXGL_MAX_BUFLEN];
    char *key_str;
    char *val_str;
    int  key_type;
    session_info_t *new_ssh_session;

    pfd = fopen(sess_info_fd->sess_info_path, "r");
    if (pfd == NULL) {
        debug("FXGL: Open %s failed!\n", sess_info_fd->sess_info_path);
        return -1;
    }

    new_ssh_session = fxgl_new_session_info_init(sess_info_fd->sess_fd);
    if (new_ssh_session == NULL) {
        debug("FXGL: new ssh session init fail!\n");
        fclose(pfd);
        return -1;
    }

    while (1) {
        memset(tmp_buf, 0, sizeof(tmp_buf));
        fgets(tmp_buf, sizeof(tmp_buf) - 1, pfd);
        logit("FXGL: config file get line:%s.\n", tmp_buf);
        if (feof(pfd)) {
            logit("FXGL: read session info finished.\n");
            fclose(pfd);
            break;
        }

        key_str = strtok(tmp_buf, "=");
        logit("FXGL: KEY_STR = %s\n", key_str);
        if (key_str == NULL) {
            debug("FXGL: Invalid file contents.\n");
            goto err_exit;
        } 

        val_str = strtok(NULL, "=");
        if (val_str == NULL) {
            debug("FXGL: Invalid file contents.\n");
            goto err_exit;
        }
        logit("FXGL: VAL_STR = %s\n", val_str);
        if (fxgl_fill_session_info(key_str, val_str, new_ssh_session) != 0) {
            debug("FXGL: fill session fail!\n");
            goto err_exit;
        }
    }
    logit("FXGL: Start mapping session!\n");
    /* 将会话加入串口结构体中 */
    (void)fxgl_map_sess(new_ssh_session);

    return 0;

err_exit:
    fclose(pfd);
    close(new_ssh_session->sock);
    fxgl_session_free(new_ssh_session->send_buf);
    fxgl_session_free(new_ssh_session);
    return -1;
}

static void *fxgl_server_thread_handler(void *arg)
{
    fxgl_sess_fd_t *sess_info_fd;

    sess_info_fd = (fxgl_sess_fd_t *)arg;

    pthread_detach(pthread_self());

    logit("FXGL: Start analysing ssh session info, open file %s\n", sess_info_fd->sess_info_path);
    if (fxgl_save_sess_info(sess_info_fd) != 0) {
        debug("FXGL: Failed to save new session info.\n");
        fxgl_session_free(sess_info_fd);
        return NULL;
    }
    
    if (unlink(sess_info_fd->sess_info_path) < 0) {
        debug("FXGL: Remove %s fail! err[%d]: %s\n", sess_info_fd->sess_info_path, errno, strerror(errno));
    }

    if (unlink(strcat(sess_info_fd->sess_info_path, SSHD2COM_SUFFIX)) < 0) {
        debug("FXGL: Remove %s fail! err[%d]: %s\n", strcat(sess_info_fd->sess_info_path, SSHD2COM_SUFFIX), errno, strerror(errno));
    }

    fxgl_session_free(sess_info_fd);

    logit("FXGL: Analyse socket success! exit thread!\n");
    pthread_exit(NULL);
}

static int fxgl_server_handler()
{
    int ret;
    struct sockaddr_un srvun, cliun;
    fxgl_sess_fd_t *tmp_ssh_sess_fd;
    int listen_fd, *conn_fd;
    size_t srvun_len;
    pthread_t server_tid;
    socklen_t cliun_len;
    char tmp_ssh_sess_path[FXGL_FILENAME_MAXLEN];
    char *buf_tmp = NULL;
    int socket_amount = 0;

    server_tid = syscall(SYS_gettid);
    listen_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        debug("FXGL: socket error\n");
        goto exit;
    }
    logit("FXGL: socket success, listen_fd = %d\n", listen_fd);

    memset(&srvun, 0, sizeof(srvun));
    srvun.sun_family = AF_UNIX;
    strncpy(srvun.sun_path, FXGL_SERVER_SOCK, sizeof(srvun.sun_path) - 1);
    unlink(FXGL_SERVER_SOCK);
    srvun_len = sizeof(srvun);

    if (bind(listen_fd, (struct sockaddr *)&srvun, (socklen_t) srvun_len) != 0) {
        debug("FXGL: cli: bind socket fail(%d)_%s, path:%s\r\n", errno, strerror(errno), FXGL_SERVER_SOCK);
        goto exit;
    }
    logit("FXGL: UNIX domain socket bound\n");

    if (listen(listen_fd, MAX_QUE_LEN) != 0) {
        debug("FXGL: listen error!\n");
        goto exit;
    }

    while (1) {
        memset(&cliun, 0, sizeof(cliun));
        cliun_len = sizeof(cliun);
        conn_fd = (int *)malloc(sizeof(int));
        if (!conn_fd) {
            debug("FXGL: malloc failed!\n");
            break;
        }

        logit("FXGL: Waiting client...\n");
        *conn_fd = accept(listen_fd, (struct sockaddr *)&cliun, (socklen_t *)&cliun_len);
        socket_amount++;
        (void)fcntl(*conn_fd, F_SETFD, O_NONBLOCK | FD_CLOEXEC);
        if (*conn_fd < 0 || cliun.sun_path == NULL) {
            debug("FXGL: accept failed!\n");
            continue;
        }
        logit("FXGL: A new ssh session connected, client sock number: [%d], tid: [%ld], total socket amount: [%d]\n", \
            *conn_fd, server_tid, socket_amount);

        tmp_ssh_sess_fd = (fxgl_sess_fd_t *)fxgl_session_malloc(sizeof(fxgl_sess_fd_t));
        memset(tmp_ssh_sess_fd->sess_info_path, 0, sizeof(tmp_ssh_sess_fd->sess_info_path));
        buf_tmp = strstr(cliun.sun_path, SSHD2COM_SUFFIX);
        strncpy(tmp_ssh_sess_fd->sess_info_path, (char *)cliun.sun_path, buf_tmp - cliun.sun_path);
        logit("FXGL: Find the session info file: %s\n", tmp_ssh_sess_fd->sess_info_path);
        tmp_ssh_sess_fd->sess_fd = conn_fd;

        if (pthread_create(&server_tid, NULL, fxgl_server_thread_handler, (void *)tmp_ssh_sess_fd) != 0) {
            debug("FXGL: Failed to create thread! err[%d]: %s\n", errno, strerror(errno));
        }
    }

exit:
    close(listen_fd);
    unlink(FXGL_SERVER_SOCK);
    return 0;
}

/* fxgl服务端初始化 */
int fxgl_server_init()
{
    (void)fxgl_server_handler();

    return 0;
}