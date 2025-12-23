/**
 * @file tiny.c
 * @brief 简单的 HTTP/1.0 Web 服务器
 * 
 * 基于 CSAPP tiny.c 改编，移除了对 csapp.h 的依赖
 * 支持 GET、HEAD、DELETE 方法，支持静态页面和 CGI 动态页面
 * 
 * 原始代码来自: Computer Systems: A Programmer's Perspective (CS:APP)
 * 改编适配 Linux 系统，添加 HEAD/DELETE 支持
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* 常量定义 */
#define MAXLINE  8192   /* 最大行长度 */
#define MAXBUF   8192   /* 最大缓冲区大小 */
#define LISTENQ  1024   /* 监听队列长度 */

/* 外部环境变量 */
extern char **environ;

/* RIO (Robust I/O) 缓冲区结构 */
typedef struct {
    int rio_fd;                 /* 文件描述符 */
    int rio_cnt;                /* 缓冲区中未读字节数 */
    char *rio_bufptr;           /* 下一个未读字节的指针 */
    char rio_buf[MAXLINE];      /* 内部缓冲区 */
} rio_t;

/* 函数声明 */
void doit(int fd);
void read_requesthdrs(rio_t *rp);
int parse_uri(char *uri, char *filename, char *cgiargs);
void serve_static(int fd, char *filename, int filesize, int send_body);
void get_filetype(char *filename, char *filetype);
void serve_dynamic(int fd, char *filename, char *cgiargs);
void serve_delete(int fd, char *filename);
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg);

/* RIO 函数声明 */
void rio_readinitb(rio_t *rp, int fd);
ssize_t rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen);
ssize_t rio_writen(int fd, void *usrbuf, size_t n);

/* 辅助函数声明 */
int open_listenfd(int port);

/**
 * @brief 主函数
 */
int main(int argc, char **argv) {
    int listenfd, connfd, port;
    socklen_t clientlen;
    struct sockaddr_in clientaddr;
    char client_ip[INET_ADDRSTRLEN];

    /* 忽略 SIGPIPE 信号，防止写入关闭的 socket 导致程序退出 */
    signal(SIGPIPE, SIG_IGN);

    /* 检查命令行参数 */
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        exit(1);
    }
    port = atoi(argv[1]);

    /* 创建监听 socket */
    listenfd = open_listenfd(port);
    if (listenfd < 0) {
        fprintf(stderr, "无法创建监听 socket\n");
        exit(1);
    }

    printf("Tiny Web 服务器已启动，监听端口 %d\n", port);
    printf("根目录: 当前目录 (.)\n");
    printf("CGI 目录: ./cgi-bin/\n");
    printf("按 Ctrl+C 停止服务器\n\n");

    while (1) {
        clientlen = sizeof(clientaddr);
        connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clientlen);
        if (connfd < 0) {
            perror("accept");
            continue;
        }

        /* 获取客户端 IP */
        inet_ntop(AF_INET, &clientaddr.sin_addr, client_ip, sizeof(client_ip));
        printf("接受来自 %s:%d 的连接\n", client_ip, ntohs(clientaddr.sin_port));

        /* 处理请求 */
        doit(connfd);

        /* 关闭连接 */
        close(connfd);
    }

    return 0;
}

/**
 * @brief 处理一个 HTTP 请求/响应事务
 */
void doit(int fd) {
    int is_static;
    struct stat sbuf;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char filename[MAXLINE], cgiargs[MAXLINE];
    rio_t rio;

    /* 读取请求行 */
    rio_readinitb(&rio, fd);
    if (rio_readlineb(&rio, buf, MAXLINE) <= 0) {
        return;
    }
    
    printf("请求行: %s", buf);
    sscanf(buf, "%s %s %s", method, uri, version);

    /* 读取请求头部 */
    read_requesthdrs(&rio);

    /* 解析 URI */
    is_static = parse_uri(uri, filename, cgiargs);

    /* 处理 HEAD 请求 */
    if (strcasecmp(method, "HEAD") == 0) {
        if (stat(filename, &sbuf) < 0) {
            clienterror(fd, filename, "404", "Not found",
                       "Tiny couldn't find this file");
            return;
        }
        serve_static(fd, filename, sbuf.st_size, 0);  /* send_body = 0 */
        return;
    }

    /* 处理 DELETE 请求 */
    if (strcasecmp(method, "DELETE") == 0) {
        serve_delete(fd, filename);
        return;
    }

    /* 处理 GET 请求 */
    if (strcasecmp(method, "GET") != 0) {
        clienterror(fd, method, "501", "Not Implemented",
                   "Tiny does not implement this method");
        return;
    }

    /* 检查文件是否存在 */
    if (stat(filename, &sbuf) < 0) {
        clienterror(fd, filename, "404", "Not found",
                   "Tiny couldn't find this file");
        return;
    }

    if (is_static) {
        /* 静态内容 */
        if (!(S_ISREG(sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode)) {
            clienterror(fd, filename, "403", "Forbidden",
                       "Tiny couldn't read the file");
            return;
        }
        serve_static(fd, filename, sbuf.st_size, 1);  /* send_body = 1 */
    } else {
        /* 动态内容 (CGI) */
        if (!(S_ISREG(sbuf.st_mode)) || !(S_IXUSR & sbuf.st_mode)) {
            clienterror(fd, filename, "403", "Forbidden",
                       "Tiny couldn't run the CGI program");
            return;
        }
        serve_dynamic(fd, filename, cgiargs);
    }
}

/**
 * @brief 读取并丢弃请求头部
 */
void read_requesthdrs(rio_t *rp) {
    char buf[MAXLINE];

    rio_readlineb(rp, buf, MAXLINE);
    while (strcmp(buf, "\r\n") != 0) {
        printf("头部: %s", buf);
        rio_readlineb(rp, buf, MAXLINE);
    }
    printf("\n");
}

/**
 * @brief 解析 URI，提取文件名和 CGI 参数
 * @return 1 表示静态内容，0 表示动态内容
 */
int parse_uri(char *uri, char *filename, char *cgiargs) {
    char *ptr;

    if (!strstr(uri, "cgi-bin")) {
        /* 静态内容 */
        strcpy(cgiargs, "");
        strcpy(filename, ".");
        strcat(filename, uri);
        if (uri[strlen(uri)-1] == '/') {
            strcat(filename, "index.html");
        }
        return 1;
    } else {
        /* 动态内容 */
        ptr = strchr(uri, '?');
        if (ptr) {
            strcpy(cgiargs, ptr + 1);
            *ptr = '\0';
        } else {
            strcpy(cgiargs, "");
        }
        strcpy(filename, ".");
        strcat(filename, uri);
        return 0;
    }
}

/**
 * @brief 发送静态内容
 * @param send_body 是否发送响应体 (HEAD 请求时为 0)
 */
void serve_static(int fd, char *filename, int filesize, int send_body) {
    int srcfd;
    char *srcp, filetype[MAXLINE], buf[MAXBUF];

    /* 获取文件类型 */
    get_filetype(filename, filetype);

    /* 构建响应头部 */
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    sprintf(buf, "%sServer: Tiny Web Server\r\n", buf);
    sprintf(buf, "%sConnection: close\r\n", buf);
    sprintf(buf, "%sContent-length: %d\r\n", buf, filesize);
    sprintf(buf, "%sContent-type: %s\r\n\r\n", buf, filetype);

    /* 发送响应头部 */
    rio_writen(fd, buf, strlen(buf));
    printf("响应头部:\n%s", buf);

    /* HEAD 请求不发送响应体 */
    if (!send_body) {
        return;
    }

    /* 发送响应体 */
    srcfd = open(filename, O_RDONLY, 0);
    if (srcfd < 0) {
        perror("open");
        return;
    }

    srcp = mmap(0, filesize, PROT_READ, MAP_PRIVATE, srcfd, 0);
    close(srcfd);
    
    if (srcp == MAP_FAILED) {
        perror("mmap");
        return;
    }

    rio_writen(fd, srcp, filesize);
    munmap(srcp, filesize);
}

/**
 * @brief 获取文件 MIME 类型
 */
void get_filetype(char *filename, char *filetype) {
    if (strstr(filename, ".html"))
        strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif"))
        strcpy(filetype, "image/gif");
    else if (strstr(filename, ".png"))
        strcpy(filetype, "image/png");
    else if (strstr(filename, ".jpg") || strstr(filename, ".jpeg"))
        strcpy(filetype, "image/jpeg");
    else if (strstr(filename, ".css"))
        strcpy(filetype, "text/css");
    else if (strstr(filename, ".js"))
        strcpy(filetype, "application/javascript");
    else
        strcpy(filetype, "text/plain");
}

/**
 * @brief 运行 CGI 程序处理动态内容
 */
void serve_dynamic(int fd, char *filename, char *cgiargs) {
    char buf[MAXLINE];
    char *emptylist[] = { NULL };

    /* 发送响应的第一部分 */
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Server: Tiny Web Server\r\n");
    rio_writen(fd, buf, strlen(buf));

    /* 创建子进程运行 CGI 程序 */
    pid_t pid = fork();
    if (pid == 0) {
        /* 子进程 */
        /* 设置 CGI 环境变量 */
        setenv("QUERY_STRING", cgiargs, 1);
        
        /* 重定向标准输出到客户端 socket */
        dup2(fd, STDOUT_FILENO);
        
        /* 执行 CGI 程序 */
        execve(filename, emptylist, environ);
        
        /* execve 失败 */
        perror("execve");
        exit(1);
    }

    /* 父进程等待子进程结束 */
    waitpid(pid, NULL, 0);
}

/**
 * @brief 处理 DELETE 请求
 */
void serve_delete(int fd, char *filename) {
    char buf[MAXBUF], body[MAXBUF];

    /* 检查文件是否存在 */
    if (access(filename, F_OK) != 0) {
        clienterror(fd, filename, "404", "Not Found",
                   "The requested file does not exist");
        return;
    }

    /* 检查是否有删除权限 */
    if (access(filename, W_OK) != 0) {
        clienterror(fd, filename, "403", "Forbidden",
                   "Permission denied to delete this file");
        return;
    }

    /* 尝试删除文件 */
    if (unlink(filename) != 0) {
        clienterror(fd, filename, "500", "Internal Server Error",
                   "Failed to delete the file");
        return;
    }

    /* 构建成功响应 */
    sprintf(body, "<html><head><title>File Deleted</title></head>\r\n");
    sprintf(body, "%s<body>\r\n", body);
    sprintf(body, "%s<h1>File Deleted Successfully</h1>\r\n", body);
    sprintf(body, "%s<p>The file %s has been deleted.</p>\r\n", body, filename);
    sprintf(body, "%s</body></html>\r\n", body);

    /* 发送响应 */
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    sprintf(buf, "%sServer: Tiny Web Server\r\n", buf);
    sprintf(buf, "%sConnection: close\r\n", buf);
    sprintf(buf, "%sContent-type: text/html\r\n", buf);
    sprintf(buf, "%sContent-length: %d\r\n\r\n", buf, (int)strlen(body));

    rio_writen(fd, buf, strlen(buf));
    rio_writen(fd, body, strlen(body));

    printf("文件已删除: %s\n", filename);
}

/**
 * @brief 发送错误响应
 */
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXLINE], body[MAXBUF];

    /* 构建 HTTP 响应体 */
    sprintf(body, "<html><head><title>Tiny Error</title></head>\r\n");
    sprintf(body, "%s<body bgcolor=\"ffffff\">\r\n", body);
    sprintf(body, "%s<h1>%s: %s</h1>\r\n", body, errnum, shortmsg);
    sprintf(body, "%s<p>%s: %s</p>\r\n", body, longmsg, cause);
    sprintf(body, "%s<hr><em>The Tiny Web server</em>\r\n", body);
    sprintf(body, "%s</body></html>\r\n", body);

    /* 发送 HTTP 响应头部 */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-type: text/html\r\n");
    rio_writen(fd, buf, strlen(buf));
    sprintf(buf, "Content-length: %d\r\n\r\n", (int)strlen(body));
    rio_writen(fd, buf, strlen(buf));

    /* 发送响应体 */
    rio_writen(fd, body, strlen(body));
}

/* ====================== RIO 函数实现 ====================== */

/**
 * @brief 初始化 RIO 缓冲区
 */
void rio_readinitb(rio_t *rp, int fd) {
    rp->rio_fd = fd;
    rp->rio_cnt = 0;
    rp->rio_bufptr = rp->rio_buf;
}

/**
 * @brief 带缓冲的读取一行
 */
static ssize_t rio_read(rio_t *rp, char *usrbuf, size_t n) {
    int cnt;

    while (rp->rio_cnt <= 0) {
        rp->rio_cnt = read(rp->rio_fd, rp->rio_buf, sizeof(rp->rio_buf));
        if (rp->rio_cnt < 0) {
            if (errno != EINTR) return -1;
        } else if (rp->rio_cnt == 0) {
            return 0;
        } else {
            rp->rio_bufptr = rp->rio_buf;
        }
    }

    cnt = n;
    if ((size_t)rp->rio_cnt < n) cnt = rp->rio_cnt;
    memcpy(usrbuf, rp->rio_bufptr, cnt);
    rp->rio_bufptr += cnt;
    rp->rio_cnt -= cnt;
    return cnt;
}

/**
 * @brief 读取一行 (带缓冲)
 */
ssize_t rio_readlineb(rio_t *rp, void *usrbuf, size_t maxlen) {
    int n, rc;
    char c, *bufp = usrbuf;

    for (n = 1; (size_t)n < maxlen; n++) {
        if ((rc = rio_read(rp, &c, 1)) == 1) {
            *bufp++ = c;
            if (c == '\n') {
                n++;
                break;
            }
        } else if (rc == 0) {
            if (n == 1) return 0;
            else break;
        } else {
            return -1;
        }
    }
    *bufp = 0;
    return n - 1;
}

/**
 * @brief 写入 n 个字节
 */
ssize_t rio_writen(int fd, void *usrbuf, size_t n) {
    size_t nleft = n;
    ssize_t nwritten;
    char *bufp = usrbuf;

    while (nleft > 0) {
        if ((nwritten = write(fd, bufp, nleft)) <= 0) {
            if (errno == EINTR) {
                nwritten = 0;
            } else {
                return -1;
            }
        }
        nleft -= nwritten;
        bufp += nwritten;
    }
    return n;
}

/* ====================== 辅助函数实现 ====================== */

/**
 * @brief 创建监听 socket
 */
int open_listenfd(int port) {
    int listenfd, optval = 1;
    struct sockaddr_in serveraddr;

    /* 创建 socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    /* 设置 SO_REUSEADDR 选项，允许地址复用 */
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, 
                   (const void *)&optval, sizeof(int)) < 0) {
        return -1;
    }

    /* 绑定地址 */
    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)port);

    if (bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) {
        return -1;
    }

    /* 开始监听 */
    if (listen(listenfd, LISTENQ) < 0) {
        return -1;
    }

    return listenfd;
}
