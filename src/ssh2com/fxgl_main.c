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
#include <string.h>
#include <sys/socket.h>  
#include <sys/un.h>  
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <errno.h>  
#include <string.h>  
#include <fcntl.h>  
#include <unistd.h>  
#include <ctype.h>  
#include <pthread.h> 
#include <syslog.h>
#include <signal.h>
#include <stdbool.h>

#include "list.h"
#include "fxgl_debug.h"
#include "fxgl_main.h"
#include "fxgl_util.h"
#include "fxgl_session.h"
#include "log.h"

#define FXGL_MAX(a,b) (((a)>(b))?(a):(b))

static int g_com_index[FXGL_COM_THREADS_NUM] = {0};

static void fxgl_clear_com_session(int com_index, int sess_fd);

static void fxgl_forward_ssh_msg(int sess_fd, int sess_index, int com_index)
{
    int ret, len;
    char tmpbuf[FXGL_MAX_BUFLEN];

    memset(tmpbuf, 0, sizeof(tmpbuf));
    len = read(sess_fd, tmpbuf, sizeof(tmpbuf));
    if (len < 0) {
        debug("FXGL: Cannot read info from session %d. err[%d]:%s\n", sess_fd, errno, strerror(errno));
        return;
    } else if (len == 0) {
        debug("FXGL: socket closed! start clear COM%d sessions.\n", com_index);
        /* 清理socket关闭的会话 */
        (void)fxgl_clear_com_session(com_index, sess_fd);

        return;
    }

    memset(g_fxgl_com_info[com_index].write_buf, 0, FXGL_MAX_BUFLEN);
    memcpy(g_fxgl_com_info[com_index].write_buf, tmpbuf, FXGL_MAX_BUFLEN);
    if (fxgl_write(g_fxgl_pipe_event[com_index].fxgl_outpipefd[1], g_fxgl_com_info[com_index].write_buf, \
            strlen(g_fxgl_com_info[com_index].write_buf)) < 0) {
        debug("FXGL: write %s to com%d fail!\n", g_fxgl_com_info[com_index].write_buf, \
            com_index);
    }
    
    return;
}

static void fxgl_session_delete(session_info_t *info)
{
    list_del_init(&info->list);
    fxgl_session_free(info->send_buf);
    close(info->sock);
    fxgl_session_free(info);
}

static void fxgl_kill_child_process(int com_index)
{
    int status;

    (void)fxgl_com_info_lock(com_index);
    kill(g_fxgl_com_info[com_index].pid, SIGKILL);
    waitpid(g_fxgl_com_info[com_index].pid, &status, 0);
    close(g_fxgl_pipe_event[com_index].fxgl_outpipefd[1]);
    close(g_fxgl_pipe_event[com_index].fxgl_inpipefd[0]);
    (void)fxgl_com_info_unlock(com_index);
}

static void fxgl_clear_com_session(int com_index, int sess_fd)
{
    struct list_head *list_tmp, *list_tmp_n;
    session_info_t *info;

    (void)fxgl_com_info_lock(com_index);
    list_for_each_safe(list_tmp, list_tmp_n, &g_fxgl_com_info[com_index].session_head) {
        info = list_entry(list_tmp, session_info_t, list);
        if (info->sock > 0 && sess_fd == FXGL_NO_SESSION_SPEC) {
            logit("FXGL: Found session! fd = %d\n", info->sock);
            fxgl_session_delete(info);
            g_fxgl_com_info[com_index].sess_used[info->session_index] = false;
        } else if (info->sock == sess_fd && sess_fd != FXGL_NO_SESSION_SPEC) {
            logit("FXGL: sock %d have exited, clear it.\n", sess_fd);
            fxgl_session_delete(info);
            g_fxgl_com_info[com_index].sess_used[info->session_index] = false;
        }
    }
    (void)fxgl_com_info_unlock(com_index);

    return;
}

static int fxgl_forward_com_msg(int com_index)
{
    int ret;
    char tmpbuf[FXGL_MAX_BUFLEN];
    struct list_head *list_tmp, *list_tmp_n;
    session_info_t *info;

    memset(tmpbuf, 0, sizeof(tmpbuf));
    ret = read(g_fxgl_pipe_event[com_index].fxgl_inpipefd[0], tmpbuf, sizeof(tmpbuf));
    if (ret < 0) {
        debug("FXGL: read pipe to COM%d fail! errno[%d]%s\n", com_index, errno, strerror(errno));
        return -1;
    } else if (ret == 0) {
        debug("FXGL: COM%d pipe closed, picocom may have exited.\n", com_index);
        return -1;
    }

    (void)fxgl_com_info_lock(com_index);
    list_for_each_safe(list_tmp, list_tmp_n, &g_fxgl_com_info[com_index].session_head) {
        info = list_entry(list_tmp, session_info_t, list);
        if (info->sock > 0) {
            info->send_buf = (char *)tmpbuf;
            if(fxgl_write(info->sock, info->send_buf, strlen(info->send_buf)) < 0) {
                debug("FXGL: write send_buf %s to ssh session %d fail!\n", info->send_buf, info->session_index);
            }
            info->send_buf = NULL;
        }
    }
    (void)fxgl_com_info_unlock(com_index);

    return 0;
}

static void fxgl_save_child_pid(pid_t pid, int com_index)
{
    (void)fxgl_com_info_lock(com_index);
    g_fxgl_com_info[com_index].pid = pid;
    (void)fxgl_com_info_unlock(com_index);
}

static void fxgl_save_com_name(char *path, char *path_prefix, int com_index, int thread_id)
{
    int i;

    sprintf(path, "%s%u", path_prefix, com_index);

    (void)fxgl_com_info_lock(com_index);
    g_fxgl_com_info[com_index].com_index = com_index;
    g_fxgl_com_info[com_index].thread_id = thread_id;
    memset(g_fxgl_com_info->com_name, 0, sizeof(g_fxgl_com_info->com_name));
    memcpy(g_fxgl_com_info->com_name, path, sizeof(path));
    for (i = 0; i < FXGL_MAX_INDEXNUM; i++) {
        g_fxgl_com_info[com_index].sess_used[i] = false;
    }
    (void)fxgl_com_info_unlock(com_index);
}

static void fxgl_launch_picocom(int com_index, int tid)
{
    pid_t pid;
    char path[FXGL_MAX_PATHLEN];

    memset(path, 0, sizeof(path));
    (void)fxgl_save_com_name(path, "/dev/ttyRG", com_index, tid);

    pid = fork();
    if (pid == 0)
    {
        /* 关联子进程输入输出到读写pipe一端 */
        if (dup2(g_fxgl_pipe_event[com_index].fxgl_outpipefd[0], STDIN_FILENO) != STDIN_FILENO) {
            debug("FXGL: dup2 error in stdin, errno[%d]%s.\n", errno, strerror(errno));
            exit(1);
        }
        
        if (dup2(g_fxgl_pipe_event[com_index].fxgl_inpipefd[1], STDOUT_FILENO) != STDOUT_FILENO) {
            debug("FXGL: dup2 error in stdout, errno[%d]%s.\n", errno, strerror(errno));
            exit(1);
        }
        
        if (dup2(g_fxgl_pipe_event[com_index].fxgl_inpipefd[1], STDERR_FILENO) != STDERR_FILENO) {
            debug("FXGL: dup2 error in stderr, errno[%d]%s.\n", errno, strerror(errno));
            exit(1);
        }

        /* 通知kernel传递SIGTERM若父进程终止 */
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        /* picocom替代子进程 */
        execl("/usr/bin/picocom", "picocom", "-b", "115200", path, (char *)NULL);

        /* execl fail */
        exit(1);
    }

    (void)fxgl_save_child_pid(pid, com_index);

    /* 关闭父进程未使用的pipe端 */
    close(g_fxgl_pipe_event[com_index].fxgl_outpipefd[0]);
    close(g_fxgl_pipe_event[com_index].fxgl_inpipefd[1]);
}

static int fxgl_init_pipe_event(int com_index) 
{
    int ret;

    ret = pipe(g_fxgl_pipe_event[com_index].fxgl_inpipefd);
    if (ret != 0) {
        debug("FXGL: init inpipefd fail!\n");
        return ret;
    }
    (void)fcntl(g_fxgl_pipe_event[com_index].fxgl_inpipefd[1], F_SETFD, FD_CLOEXEC);

    ret = pipe(g_fxgl_pipe_event[com_index].fxgl_outpipefd);
    if (ret != 0) {
        debug("FXGL: init outpipefd fail!\n");
        return ret;
    }
    (void)fcntl(g_fxgl_pipe_event[com_index].fxgl_outpipefd[0], F_SETFD, FD_CLOEXEC);

    return 0;
}

/* 串口线程处理函数 */
static void *fxgl_com_threads_handler(void *arg)
{
    unsigned int tid;
    int com_thread_index;
    int com_fd, max_fd;
    int ret;
    int com_timeout_period;
    fd_set fxgl_fdset;
    struct list_head *list_tmp, *list_tmp_n;
    struct timeval tv;
    session_info_t *info;
    char path[FXGL_MAX_PATHLEN];

    com_thread_index = *(int *)arg;
    pthread_detach(pthread_self());
    tid = syscall(SYS_gettid);
    /* 超时时间判定标志 */
    com_timeout_period = 0;

    //(void)fxgl_keepalive_init();

    if (fxgl_init_pipe_event(com_thread_index) != 0) {
        debug("FXGL: COM%d Create pipe fail! err:%d, %s\n", com_thread_index, errno, strerror(errno));
        return NULL;
    }
    logit("FXGL: Create pipe success! Start launching COM%d picocom process.\n", com_thread_index);

    /* 创建picocom子进程 */
    (void)fxgl_launch_picocom(com_thread_index, tid);

    /* 监听开始 */
    for (;;) { 
        /* 串口描述符加入监听 */
        (void)fxgl_set_bk(g_fxgl_pipe_event[com_thread_index].fxgl_inpipefd[0], true);
        max_fd = g_fxgl_pipe_event[com_thread_index].fxgl_inpipefd[0];
        FD_ZERO(&fxgl_fdset);
        FD_SET(g_fxgl_pipe_event[com_thread_index].fxgl_inpipefd[0], &fxgl_fdset);

        /* 会话fd状态更新 */

        /* 该串口线程下的所有会话加入 */
        (void)fxgl_com_info_lock(com_thread_index);
        if (list_empty(&g_fxgl_com_info[com_thread_index].session_head)) {
            //logit("FXGL:g_fxgl_com_info[%d].session_head is empty. fd_setsize = %d\n", com_thread_index, FD_SETSIZE);
            (void)fxgl_com_info_unlock(com_thread_index);
            sleep(1);
            FD_CLR(g_fxgl_pipe_event[com_thread_index].fxgl_inpipefd[0], &fxgl_fdset);
            continue;
        }

        list_for_each_safe(list_tmp, list_tmp_n, &g_fxgl_com_info[com_thread_index].session_head) {
            info = list_entry(list_tmp, session_info_t, list);
            if (info->sock > 0) {
                FD_SET(info->sock, &fxgl_fdset);
                max_fd = FXGL_MAX(max_fd, info->sock);
                (void)fxgl_set_bk(info->sock, true);
            }
        }
        (void)fxgl_com_info_unlock(com_thread_index);

        /* 设置串口默认超时时间（无输入输出） */
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        ret = select(max_fd + 1, &fxgl_fdset, NULL, NULL, &tv);
        if (ret < 0) {
            debug("FXGL: select fail! err[%d]:%s\n", errno, strerror(errno));
            FD_CLR(info->sock, &fxgl_fdset);
            FD_CLR(g_fxgl_pipe_event[com_thread_index].fxgl_inpipefd[0], &fxgl_fdset);
            continue;
        } else if (ret == 0) {
            com_timeout_period += tv.tv_sec;
            if (com_timeout_period >= FXGL_COM_TIMEOUT_PERIOD) {
                /* 超时处理,清空该串口下所有会话 */
                (void)fxgl_clear_com_session(com_thread_index, FXGL_NO_SESSION_SPEC);
            }
            FD_CLR(info->sock, &fxgl_fdset);
            FD_CLR(g_fxgl_pipe_event[com_thread_index].fxgl_inpipefd[0], &fxgl_fdset);
            continue;
        } 

        com_timeout_period = 0;
        /* 串口有数据可读 */
        if (FD_ISSET(g_fxgl_pipe_event[com_thread_index].fxgl_inpipefd[0], &fxgl_fdset)) {
            ret = fxgl_forward_com_msg(com_thread_index);
            if (ret < 0) {
                /* 读取picocom失败，清理会话信息，kill掉当前子进程，重新fork */
                debug("FXGL: Forward COM%d msg fail, start clear sessions!\n", com_thread_index);
                (void)fxgl_clear_com_session(com_thread_index, FXGL_NO_SESSION_SPEC);
                (void)fxgl_kill_child_process(com_thread_index);
                logit("FXGL: kill child_process success, start reset COM%d picocom.\n", com_thread_index);
                if (fxgl_init_pipe_event(com_thread_index) != 0) {
                    debug("FXGL: COM%d Create pipe fail! err:%d, %s\n", com_thread_index, errno, strerror(errno));
                    return NULL;
                }
                (void)fxgl_launch_picocom(com_thread_index, tid);
                FD_CLR(info->sock, &fxgl_fdset);
                FD_CLR(g_fxgl_pipe_event[com_thread_index].fxgl_inpipefd[0], &fxgl_fdset);
                continue;
            }
        }

        (void)fxgl_com_info_lock(com_thread_index);
        list_for_each_safe(list_tmp, list_tmp_n, &g_fxgl_com_info[com_thread_index].session_head) {
            info = list_entry(list_tmp, session_info_t, list);
            /* 会话存在输入，转去串口描述符 */
            if (info->sock > 0 && FD_ISSET(info->sock, &fxgl_fdset)) {
                (void)fxgl_forward_ssh_msg(info->sock, info->session_index, com_thread_index);
                FD_CLR(info->sock, &fxgl_fdset);
            }
        }
        (void)fxgl_com_info_unlock(com_thread_index);
        FD_CLR(g_fxgl_pipe_event[com_thread_index].fxgl_inpipefd[0], &fxgl_fdset);
    } /* End of for(;;) */

    (void)fxgl_kill_child_process(com_thread_index);

    return NULL;
}

static void fxgl_com_threads_create()
{
    int i;

    for (i = 0; i < FXGL_COM_THREADS_NUM; i++) {
        g_com_index[i] = i;
        if (pthread_create(&g_fxgl_com_thread[i], NULL, fxgl_com_threads_handler, &g_com_index[i]) != 0) {
            debug("FXGL: Failed to create num.%d com thread!\n", i);
            continue;
        }
        logit("FXGL: Create num.%d com thread success.\n", g_com_index[i]);
    }
}

static void fxgl_init_sess_head(void)
{
    int i;

    for (i = 0; i < FXGL_COM_THREADS_NUM; i++) {
        INIT_LIST_HEAD(&g_fxgl_com_info[i].session_head);
    }
}

static int is_fxgl_running(void)
{
    FILE *fp;
    pthread_t pid;
    char buf[MAX_STR_LEN + 1];
    
    fp = popen("ps -A | grep ssh2com", "r");
    if (fp == NULL) {
        debug("FXGL: Check failed\n");
        return 1;
    }

    if (fgets(buf, MAX_STR_LEN, fp) != NULL) {
        pid = atol(buf);
        if (pid && pid != getpid()) {
            pclose(fp);
            return 1;
        }
    }
    pclose(fp);
    return 0;
}

int main(int argc, char **argv)
{
    int ret;

    char path[FXGL_FILENAME_MAXLEN];

    /* 设置守护进程 */
    daemon(0, 0);

    (void)log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 1);
    /* 进程给予最大权限 */
    (void)umask(0);
    (void)fxgl_make_tmp_path("/fxgl", path, sizeof(path));
    ret = mkdir(path, (S_IRWXU|S_IRWXG|S_IRWXO));
    if (ret == -1) {
        if (errno != EEXIST) {
            debug("FXGL: Failed to create mng directory, errno[%d]%s.\n", errno,
                strerror(errno));
            debug("FXGL: Failed to create mng directory, errno[%d]%s.\n", errno,
                strerror(errno));
            return ret;
        }
    }

    /* 单实例检查 */
    if (is_fxgl_running()) {
        debug("FXGL: Fxgl Server is running or check failed!\n");
        return 0;
    } 

    //(void)fxgl_init_signo();
    //(void)fxgl_keepalive_init();

    /* 初始化会话链表表头 */
    (void)fxgl_init_sess_head();

    logit("FXGL: Start creating 48 com threads...\n");

    /* 锁初始化 */
    (void)fxgl_cominfo_lock_init();

    /* 初始化并启动线程数组 */
    (void)fxgl_com_threads_create();

    /* FXGL服务器初始化，负责监听ssh连接 */
    logit("FXGL: Start the server!\n");
    (void)fxgl_server_init();

    return 0;
}