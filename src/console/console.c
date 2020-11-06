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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <dirent.h>
#include <stddef.h>

#include "console_util.h"
#include "../ssh2com/log.h"

#define SSHD2COM_SOCKETADDR "/tmp/fxgl/ssh2com-server.sock"
#define SSHD2COM_DIR "/tmp/sshd"
#define SSHD2COM_PATH_SUFFIX "_CLIENTSOCKET"
#define CONSOLE_NAME_MAX  512
#define CONSOLE_PATH_LEN  100
#define CONSOLE_MESSAGE_LEN 200
#define CONSOLE_GET_PEER_ADDR_REG  "who | grep '\\ %s\\ ' | sed 's/^.*(//g' | sed 's/)//g'"
#define CONSOLE_GET_LOCAL_USERNAME_REG  "who | grep '\\ %s\\ ' | awk '{print $1}'"

#define MAX_FD(a,b) (((a)>(b))?(a):(b))

struct console {
    /* cached local and remote ip addresses and ports */
    char *remote_ipaddr;
    int local_port;
    char *user_name;
};

static struct console* active_state;
struct termios term_old, term_new;
int rfd, wfd;
int console_socket = -1;


static void signal_handler(int sig)
{
    exit(0);
}

char * get_popen_result(char* cmd, char* pty_name, int size) {
    char buf[100];
    int len;
    int fd;
    char *p = console_malloc(size);
    FILE* file;
    
    /* get peer ipaddr */
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf),  cmd, pty_name);
    if ((file = popen(buf, "r")) == NULL) {
        return NULL;
    }
    fd = fileno(file);
    len = read(fd, buf, sizeof (buf));
    if (len < 1) { 
        console_free(p);
        return NULL;
    }
    strncpy(p, buf, len-1);
    return p;
}


char * get_peer_ipaddr(char* pty_name) {
    char *p;

    p = get_popen_result(CONSOLE_GET_PEER_ADDR_REG, pty_name, 20);

    printf("client ip:%s\n", p);
    debug("client ip:%s", p);
    logit("client ip:%s", p);
    return p;
}

char * get_local_username(char* pty_name) {
    char *p ;

    p = get_popen_result(CONSOLE_GET_LOCAL_USERNAME_REG, pty_name, 100);
    printf("login username:%s\n", p);
    debug("login username:%s", p);
    logit("login username:%s", p);
    return p;
}

int  init_active_state(int local_port) {
    char pty_name[100];
    int len;
    int fd;
    FILE * file;
     
    memset(pty_name, 0, sizeof(pty_name));
    file = popen("ps | awk '{print $2}' | sed -n 2p", "r");
    if (file == NULL) return -1;
    
    fd = fileno(file);
    len = read(fd, pty_name, sizeof (pty_name));
    if (len < 0) {
       logit("can't get pty_name.");
       return -1;
    }
    pty_name[len-1] = '\0';
    printf("pty_name:%s\n", pty_name);
    debug("pty_name:%s", pty_name);
    logit("pty_name:%s", pty_name);
     
    active_state = (struct console*)console_malloc(sizeof(struct console));
    active_state->remote_ipaddr = get_peer_ipaddr(pty_name);
    active_state->local_port = local_port;
    active_state->user_name = get_local_username(pty_name);
    return 1;
}

void free_active_state() {
    if (active_state) {
        console_free(active_state->remote_ipaddr);
        console_free(active_state->user_name);
        console_free(active_state);
    }
}

void free_env() {
    tcsetattr(rfd, TCSANOW, &term_old);
    (void)free_active_state();
    close(rfd);
    close(wfd);
    logit("console socket = %d\n", console_socket);
    if (console_socket > 0) {
        close(console_socket);
        logit("console socket %d close!\n", console_socket);
    }
}

void fd_init(int* rfdp, int* wfdp) {
    *rfdp = STDIN_FILENO;
    *wfdp = STDOUT_FILENO;
}

/* 禁止回显 */
void set_raw_mode() {
    tcgetattr(STDIN_FILENO, &term_old);
    term_new = term_old;
    term_new.c_lflag &= (~ICANON & ~ECHO);  //leave ISIG ON- allow intr's
    term_new.c_iflag &= (~IXON & ~ICRNL);
    term_new.c_oflag &= (~ONLCR);
    term_new.c_cc[VMIN] = 1;
    term_new.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &term_new);
}

void enter_raw_mode() {
    struct termios tio;

    if (tcgetattr(fileno(stdin), &tio) == -1) {
        perror("tcgetattr");
        return;
    }
    term_old = tio;
    tio.c_iflag |= IGNPAR;
    tio.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
/*#ifdef IUCLC
    tio.c_iflag &= ~IUCLC;
#endif*/
    tio.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
/*#ifdef IEXTEN
    tio.c_lflag &= ~IEXTEN;
#endif*/
    //tio.c_oflag &= ~OPOST;
    tio.c_cc[VMIN] = 1;
    tio.c_cc[VTIME] = 0;
    if (tcsetattr(fileno(stdin), TCSADRAIN, &tio) == -1) {
             printf("tcsetarr");
    } 
}

void reset_raw_mode() {
    tcsetattr(fileno(stdin), TCSANOW, &term_old);
}

static int console_com_connect(void) {
    struct console *console = active_state; /* XXX */
    int ret;
    int len;
    int opt;
    int client_sockfd;
    struct sockaddr_un server_sockaddr, client_sockaddr;
    char server_path[CONSOLE_NAME_MAX];
    char client_path[CONSOLE_PATH_LEN];
    char *unix_domain_server_path;
    int sfd;
    char message[CONSOLE_MESSAGE_LEN];
    struct timeval tv;
    
    gettimeofday(&tv,NULL);
    if (NULL == opendir(SSHD2COM_DIR)) {
        mkdir(SSHD2COM_DIR, S_IRUSR | S_IWUSR | S_IXUSR);
    }
    snprintf(client_path, sizeof(client_path), "%s/%s_%d_%ld", SSHD2COM_DIR, console->remote_ipaddr, console->local_port, tv.tv_sec);
    sfd = creat(client_path, S_IRUSR | S_IWUSR);
    if (sfd < 0) {
        logit("console:Client cannot create tmp file %s\n", client_path);
    }
    snprintf(message, sizeof(message), \
    "CLIENT_IP=%s\nUSERNAME=%s\nDEVICE_PORT=%d\nPRIVILEGE=%d\nLogin_type=%d\n", \
    console->remote_ipaddr, \
    console->user_name, \
    console->local_port, 1, 1);
    ret = write(sfd, message, strlen(message));
    if(ret < 0)
    {
        logit("console: Client write tmp file %s failed\n", client_path);
        perror("console_com_connect");
        close(sfd);
        return -1;
    }    
    close(sfd);
    fsync(sfd);
    //snprintf(client_path, sizeof(client_path), "%s/%s_%d%ld%s", SSHD2COM_DIR, ssh->remote_ipaddr, ssh->local_port, SSHD2COM_PATH_SUFFIX);
    strcat(client_path, SSHD2COM_PATH_SUFFIX);
    memset(server_path, 0, sizeof(server_path));
    unix_domain_server_path = SSHD2COM_SOCKETADDR;
    
    client_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_sockfd < 0) {
        logit("console: (Client cannot create communication socket\n");
        return -1;
    }
    memset(&client_sockaddr, 0, sizeof(client_sockaddr));
    client_sockaddr.sun_family = AF_UNIX;  
    strcpy(client_sockaddr.sun_path, client_path);
    len = offsetof(struct sockaddr_un, sun_path) + strlen(client_sockaddr.sun_path);
    unlink(client_sockaddr.sun_path);
    
    //将套接字关联client本地通信�??
    if (bind(client_sockfd, (struct sockaddr *)&client_sockaddr, len) < 0) 
    {
        logit("console: Client bind failed, error[%d]: %s\n", errno, strerror(errno));
        return -1;
    } 
    opt = 1;
    if (setsockopt(client_sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&opt, sizeof(opt))!= 0) {
        logit("console: Client setsockopt failed, error[%d]: %s\n", errno, strerror(errno));
        close(client_sockfd);
        return -1;
    }
    
    server_sockaddr.sun_family = AF_UNIX;
    memset(server_sockaddr.sun_path, 0, sizeof(server_sockaddr.sun_path));
    strncpy(server_sockaddr.sun_path, unix_domain_server_path, sizeof(server_sockaddr.sun_path) - 1);
    len = sizeof(server_sockaddr);
    ret = connect(client_sockfd, (struct sockaddr *)&server_sockaddr, len);
    if (ret < 0) {
        logit("console: Client error on connecting, errno: %d, ret: %d\n", errno, ret);
        close(client_sockfd);
        return -1;
    }
    logit("connect success, console socket is %d\n", client_sockfd);
    return client_sockfd;
}

/*
 * Waits until the client can do something (some data becomes available on
 * one of the file descriptors).
 */
static void wait_until_can_do_something(fd_set *readsetp, fd_set *writesetp,
    int *maxfdp, struct timeval *tv) {
    int ret;
    char buf[100];
    
    FD_ZERO(readsetp);
    FD_SET(rfd, readsetp);
    FD_SET(console_socket, readsetp);
    if (writesetp != NULL) {
        FD_ZERO(writesetp);
        FD_SET(wfd, writesetp);
        FD_SET(console_socket, writesetp);
    }

    ret = select(*maxfdp, readsetp, NULL, NULL, NULL);
    if (ret > 0) return;
    if (ret <= 0) {
        if (ret < 0 && errno == EINTR)
            return;
        snprintf(buf, sizeof(buf), "select: %s\r\n", strerror(errno));
        logit("%s", buf);
    }

    return;
}


int main(int argc, char* argv[]) {
    char buf[BUF_MAX_LEN];
    char msg[MSG_MAX_LEN];
    int flags;
    int len, ret_len;
    fd_set readset, writeset;
    struct timeval tv;
    int max_fd = -1;
    int ret;
    int local_port;

    if (argc < 2) {
        printf("%s: please input console's port_num!!\n", argv[0]);
        return 0;
    }

    if (is_int(argv[1])) {
        local_port = atoi(argv[1]);
    } else {
        printf("%s: argument %s is not console's port num\n", argv[0], argv[1]);
        return 0;
    }
    log_init(argv[0], SYSLOG_LEVEL_INFO, SYSLOG_FACILITY_USER, 0);
    ret = init_active_state(local_port);
    if (!ret) {
        perror("init_active_state");
        exit(-1);
    }
    fd_init(&rfd, &wfd);
    enter_raw_mode();
    max_fd = rfd;
    max_fd = MAX_FD(max_fd, wfd);
    if ((console_socket = console_com_connect()) <= 0){
        perror("Cann't connect fxgl server");
        (void)free_env();
        return -1;
    }
    max_fd = MAX_FD(max_fd, console_socket);
    max_fd += 1;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    set_nonblock(console_socket);
    logit("console start!!!");
    while (1) {
        wait_until_can_do_something(&readset, NULL, &max_fd, &tv);
        if (FD_ISSET(rfd, &readset)) {
            len = read(rfd, msg, sizeof(msg));
            if (len > 0) {
                write(console_socket, msg, len);
            } else if (len < 0 && (errno == EAGAIN || errno == EINTR) ) {
                logit("rfd's read is interrupted!");
            } else if (len <= 0) {
                snprintf(buf, sizeof(buf), "read: %.100s\r\n",
                        strerror(errno));
                logit("%s", buf);
            }
        }
        if (FD_ISSET(console_socket, &readset)) {
            len = read(console_socket, msg, sizeof(msg));
            if (len > 0) {
                write(wfd, msg, len);
            } else if (len < 0 && (errno == EAGAIN || errno == EINTR)) {
                logit("console socket's read is interrupted!");
            } else if (len <= 0) {
                break;
            }
        }
    }
    (void)free_env();
    return 0;
}
