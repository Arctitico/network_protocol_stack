/**
 * @file http_client.h
 * @brief HTTP 客户端库头文件
 * 
 * 提供 HTTP 请求构造、发送和响应解析功能
 */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stddef.h>

/* 默认端口 */
#define HTTP_DEFAULT_PORT 80

/* 缓冲区大小 */
#define HTTP_BUFFER_SIZE 4096
#define HTTP_URL_MAX_LEN 2048
#define HTTP_HOST_MAX_LEN 256
#define HTTP_PATH_MAX_LEN 1024

/* HTTP 方法 */
typedef enum {
    HTTP_METHOD_GET,
    HTTP_METHOD_HEAD,
    HTTP_METHOD_POST,
    HTTP_METHOD_DELETE
} http_method_t;

/* HTTP 响应结构 */
typedef struct {
    int status_code;                    /* HTTP 状态码 */
    char status_msg[64];                /* 状态消息 */
    char content_type[128];             /* Content-Type */
    int content_length;                 /* Content-Length */
    char *headers;                      /* 原始头部 */
    char *body;                         /* 响应体 */
    size_t body_len;                    /* 响应体长度 */
} http_response_t;

/* URL 解析结构 */
typedef struct {
    char host[HTTP_HOST_MAX_LEN];       /* 主机名 */
    int port;                           /* 端口号 */
    char path[HTTP_PATH_MAX_LEN];       /* 路径 */
    char query[HTTP_PATH_MAX_LEN];      /* 查询参数 */
} http_url_t;

/**
 * @brief 解析 URL
 * @param url 原始 URL 字符串
 * @param parsed 解析后的结构体
 * @return 0 成功, -1 失败
 */
int http_parse_url(const char *url, http_url_t *parsed);

/**
 * @brief 创建 TCP 连接
 * @param host 主机名或 IP
 * @param port 端口号
 * @return socket fd 成功, -1 失败
 */
int http_connect(const char *host, int port);

/**
 * @brief 发送 HTTP GET 请求
 * @param url 请求 URL
 * @param response 响应结构体指针
 * @return 0 成功, -1 失败
 */
int http_get(const char *url, http_response_t *response);

/**
 * @brief 发送 HTTP HEAD 请求
 * @param url 请求 URL
 * @param response 响应结构体指针
 * @return 0 成功, -1 失败
 */
int http_head(const char *url, http_response_t *response);

/**
 * @brief 发送 HTTP DELETE 请求
 * @param url 请求 URL
 * @param response 响应结构体指针
 * @return 0 成功, -1 失败
 */
int http_delete(const char *url, http_response_t *response);

/**
 * @brief 释放响应结构体内存
 * @param response 响应结构体指针
 */
void http_response_free(http_response_t *response);

/**
 * @brief 获取状态码描述
 * @param status_code HTTP 状态码
 * @return 状态描述字符串
 */
const char *http_status_description(int status_code);

#endif /* HTTP_CLIENT_H */
