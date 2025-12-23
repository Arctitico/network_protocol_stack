/**
 * @file http_client.c
 * @brief HTTP 客户端库实现
 * 
 * 提供 HTTP 请求构造、发送和响应解析功能
 */

#include "../include/http_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

/* HTTP 请求模板 */
#define HTTP_GET_TEMPLATE    "GET %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\nUser-Agent: SimpleBrowser/1.0\r\nAccept: text/html, image/gif, image/jpeg, */*\r\n\r\n"
#define HTTP_HEAD_TEMPLATE   "HEAD %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\nUser-Agent: SimpleBrowser/1.0\r\nAccept: */*\r\n\r\n"
#define HTTP_DELETE_TEMPLATE "DELETE %s HTTP/1.0\r\nHost: %s:%d\r\nConnection: close\r\nUser-Agent: SimpleBrowser/1.0\r\n\r\n"

/**
 * @brief 解析 URL
 */
int http_parse_url(const char *url, http_url_t *parsed) {
    if (!url || !parsed) {
        return -1;
    }

    memset(parsed, 0, sizeof(http_url_t));
    parsed->port = HTTP_DEFAULT_PORT;
    strcpy(parsed->path, "/");

    const char *ptr = url;

    /* 跳过协议头 http:// */
    if (strncasecmp(ptr, "http://", 7) == 0) {
        ptr += 7;
    }

    /* 查找路径分隔符 */
    const char *path_start = strchr(ptr, '/');
    const char *port_start = strchr(ptr, ':');

    /* 提取主机名 */
    size_t host_len;
    if (port_start && (!path_start || port_start < path_start)) {
        /* 有端口号 */
        host_len = port_start - ptr;
        if (host_len >= HTTP_HOST_MAX_LEN) {
            return -1;
        }
        strncpy(parsed->host, ptr, host_len);
        parsed->host[host_len] = '\0';

        /* 提取端口号 */
        if (path_start) {
            char port_buf[16];
            size_t port_len = path_start - port_start - 1;
            strncpy(port_buf, port_start + 1, port_len);
            port_buf[port_len] = '\0';
            parsed->port = atoi(port_buf);
        } else {
            parsed->port = atoi(port_start + 1);
        }
    } else if (path_start) {
        host_len = path_start - ptr;
        if (host_len >= HTTP_HOST_MAX_LEN) {
            return -1;
        }
        strncpy(parsed->host, ptr, host_len);
        parsed->host[host_len] = '\0';
    } else {
        strncpy(parsed->host, ptr, HTTP_HOST_MAX_LEN - 1);
    }

    /* 提取路径 */
    if (path_start) {
        /* 查找查询参数 */
        const char *query_start = strchr(path_start, '?');
        if (query_start) {
            size_t path_len = query_start - path_start;
            strncpy(parsed->path, path_start, path_len);
            parsed->path[path_len] = '\0';
            strncpy(parsed->query, query_start + 1, HTTP_PATH_MAX_LEN - 1);
        } else {
            strncpy(parsed->path, path_start, HTTP_PATH_MAX_LEN - 1);
        }
    }

    return 0;
}

/**
 * @brief 创建 TCP 连接
 */
int http_connect(const char *host, int port) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent *he;

    /* 解析主机名 */
    he = gethostbyname(host);
    if (!he) {
        fprintf(stderr, "[HTTP] Failed to resolve host: %s\n", host);
        return -1;
    }

    /* 创建 socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "[HTTP] Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    /* 设置服务器地址 */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr, he->h_addr_list[0], he->h_length);

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "[HTTP] Failed to connect: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * @brief 发送数据
 */
static int http_send(int sockfd, const char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sockfd, data + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += n;
    }
    return 0;
}

/**
 * @brief 接收所有数据
 */
static char *http_recv_all(int sockfd, size_t *total_len) {
    size_t buf_size = HTTP_BUFFER_SIZE;
    size_t received = 0;
    char *buffer = malloc(buf_size);
    if (!buffer) return NULL;

    while (1) {
        if (received + HTTP_BUFFER_SIZE > buf_size) {
            buf_size *= 2;
            char *new_buf = realloc(buffer, buf_size);
            if (!new_buf) {
                free(buffer);
                return NULL;
            }
            buffer = new_buf;
        }

        ssize_t n = recv(sockfd, buffer + received, HTTP_BUFFER_SIZE - 1, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            free(buffer);
            return NULL;
        }
        if (n == 0) break;
        received += n;
    }

    buffer[received] = '\0';
    *total_len = received;
    return buffer;
}

/**
 * @brief 解析 HTTP 响应
 */
static int http_parse_response(const char *raw, size_t raw_len, http_response_t *response) {
    memset(response, 0, sizeof(http_response_t));

    /* 解析状态行 */
    const char *line_end = strstr(raw, "\r\n");
    if (!line_end) return -1;

    char status_line[256];
    size_t line_len = line_end - raw;
    if (line_len >= sizeof(status_line)) line_len = sizeof(status_line) - 1;
    strncpy(status_line, raw, line_len);
    status_line[line_len] = '\0';

    /* 解析 HTTP/1.x XXX Message */
    char version[16];
    if (sscanf(status_line, "%s %d %63[^\r\n]", version, &response->status_code, response->status_msg) < 2) {
        return -1;
    }

    /* 查找头部结束位置 */
    const char *header_end = strstr(raw, "\r\n\r\n");
    if (!header_end) {
        header_end = raw + raw_len;
    }

    /* 保存原始头部 */
    size_t headers_len = header_end - raw;
    response->headers = malloc(headers_len + 1);
    if (response->headers) {
        strncpy(response->headers, raw, headers_len);
        response->headers[headers_len] = '\0';
    }

    /* 解析 Content-Type */
    const char *ct = strcasestr(raw, "Content-Type:");
    if (ct && ct < header_end) {
        ct += 13;
        while (*ct == ' ') ct++;
        const char *ct_end = strstr(ct, "\r\n");
        if (ct_end && ct_end < header_end) {
            size_t ct_len = ct_end - ct;
            if (ct_len >= sizeof(response->content_type)) {
                ct_len = sizeof(response->content_type) - 1;
            }
            strncpy(response->content_type, ct, ct_len);
        }
    }

    /* 解析 Content-Length */
    const char *cl = strcasestr(raw, "Content-Length:");
    if (cl && cl < header_end) {
        cl += 15;
        response->content_length = atoi(cl);
    }

    /* 提取响应体 */
    if (header_end && header_end + 4 <= raw + raw_len) {
        const char *body_start = header_end + 4;
        response->body_len = raw_len - (body_start - raw);
        response->body = malloc(response->body_len + 1);
        if (response->body) {
            memcpy(response->body, body_start, response->body_len);
            response->body[response->body_len] = '\0';
        }
    }

    return 0;
}

/**
 * @brief 执行 HTTP 请求
 */
static int http_request(const char *url, http_method_t method, http_response_t *response) {
    http_url_t parsed;
    char request[HTTP_BUFFER_SIZE];
    int sockfd;
    char *raw_response;
    size_t response_len;

    /* 解析 URL */
    if (http_parse_url(url, &parsed) < 0) {
        fprintf(stderr, "[HTTP] Failed to parse URL: %s\n", url);
        return -1;
    }

    /* 构造完整路径 */
    char full_path[HTTP_PATH_MAX_LEN * 2];
    if (parsed.query[0]) {
        snprintf(full_path, sizeof(full_path), "%s?%s", parsed.path, parsed.query);
    } else {
        strncpy(full_path, parsed.path, sizeof(full_path) - 1);
    }

    /* 构造请求 */
    switch (method) {
        case HTTP_METHOD_GET:
            snprintf(request, sizeof(request), HTTP_GET_TEMPLATE, 
                     full_path, parsed.host, parsed.port);
            break;
        case HTTP_METHOD_HEAD:
            snprintf(request, sizeof(request), HTTP_HEAD_TEMPLATE,
                     full_path, parsed.host, parsed.port);
            break;
        case HTTP_METHOD_DELETE:
            snprintf(request, sizeof(request), HTTP_DELETE_TEMPLATE,
                     full_path, parsed.host, parsed.port);
            break;
        default:
            return -1;
    }

    printf("[HTTP] Connecting to %s:%d\n", parsed.host, parsed.port);
    printf("[HTTP] Request:\n%s\n", request);

    /* 建立连接 */
    sockfd = http_connect(parsed.host, parsed.port);
    if (sockfd < 0) {
        return -1;
    }

    /* 发送请求 */
    if (http_send(sockfd, request, strlen(request)) < 0) {
        fprintf(stderr, "[HTTP] Failed to send request\n");
        close(sockfd);
        return -1;
    }

    /* 接收响应 */
    raw_response = http_recv_all(sockfd, &response_len);
    close(sockfd);

    if (!raw_response) {
        fprintf(stderr, "[HTTP] Failed to receive response\n");
        return -1;
    }

    /* 解析响应 */
    int result = http_parse_response(raw_response, response_len, response);
    free(raw_response);

    return result;
}

/**
 * @brief 发送 HTTP GET 请求
 */
int http_get(const char *url, http_response_t *response) {
    return http_request(url, HTTP_METHOD_GET, response);
}

/**
 * @brief 发送 HTTP HEAD 请求
 */
int http_head(const char *url, http_response_t *response) {
    return http_request(url, HTTP_METHOD_HEAD, response);
}

/**
 * @brief 发送 HTTP DELETE 请求
 */
int http_delete(const char *url, http_response_t *response) {
    return http_request(url, HTTP_METHOD_DELETE, response);
}

/**
 * @brief 释放响应结构体内存
 */
void http_response_free(http_response_t *response) {
    if (response) {
        if (response->headers) {
            free(response->headers);
            response->headers = NULL;
        }
        if (response->body) {
            free(response->body);
            response->body = NULL;
        }
    }
}

/**
 * @brief 获取状态码描述
 */
const char *http_status_description(int status_code) {
    switch (status_code) {
        case 200: return "OK - 请求成功";
        case 301: return "Moved Permanently - 资源已永久移动";
        case 302: return "Found - 资源临时移动";
        case 400: return "Bad Request - 请求格式错误";
        case 403: return "Forbidden - 禁止访问";
        case 404: return "Not Found - 资源未找到";
        case 500: return "Internal Server Error - 服务器内部错误";
        case 501: return "Not Implemented - 方法未实现";
        case 505: return "HTTP Version Not Supported - HTTP版本不支持";
        default:  return "Unknown Status";
    }
}
