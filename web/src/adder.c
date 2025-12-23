/**
 * @file adder.c
 * @brief CGI 加法器程序
 * 
 * 从环境变量 QUERY_STRING 读取两个数字参数，计算它们的和
 * 并返回 HTML 格式的结果
 * 
 * 使用方法: 通过 URL 访问
 *   http://localhost:8080/cgi-bin/adder?1500&212
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINE 8192

int main(void) {
    char *buf, *p;
    char arg1[MAXLINE], arg2[MAXLINE], content[MAXLINE];
    int n1 = 0, n2 = 0;

    /* 从环境变量获取查询字符串 */
    buf = getenv("QUERY_STRING");
    if (buf != NULL) {
        /* 查找 '&' 分隔符 */
        p = strchr(buf, '&');
        if (p) {
            *p = '\0';
            strcpy(arg1, buf);
            strcpy(arg2, p + 1);
            n1 = atoi(arg1);
            n2 = atoi(arg2);
        }
    }

    /* 构建 HTML 响应内容 */
    sprintf(content, "<html>\r\n");
    sprintf(content, "%s<head><title>Adder Result</title></head>\r\n", content);
    sprintf(content, "%s<body>\r\n", content);
    sprintf(content, "%s<h1>Welcome to add.com</h1>\r\n", content);
    sprintf(content, "%s<p>THE Internet addition portal.</p>\r\n", content);
    sprintf(content, "%s<h2>计算结果</h2>\r\n", content);
    sprintf(content, "%s<p style='font-size:24px; color:blue;'>%d + %d = %d</p>\r\n", 
            content, n1, n2, n1 + n2);
    sprintf(content, "%s<hr>\r\n", content);
    sprintf(content, "%s<p>Thanks for visiting!</p>\r\n", content);
    sprintf(content, "%s</body>\r\n", content);
    sprintf(content, "%s</html>\r\n", content);

    /* 输出 HTTP 头部和内容 */
    printf("Content-length: %d\r\n", (int)strlen(content));
    printf("Content-type: text/html; charset=utf-8\r\n\r\n");
    printf("%s", content);
    
    fflush(stdout);
    return 0;
}
