/**
 * @file browser_main.c
 * @brief 简易浏览器主程序入口
 * 
 * 基于 GTK 的简单 Web 浏览器，支持 GET/HEAD/DELETE 请求
 */

#include <stdio.h>
#include <stdlib.h>
#include <locale.h>
#include <gtk/gtk.h>
#include "browser_gui.h"

/**
 * @brief 主函数
 */
int main(int argc, char *argv[]) {
    /* 设置本地化，支持中文显示 */
    setlocale(LC_ALL, "");

    /* 初始化 GTK */
    gtk_init(&argc, &argv);

    /* 创建浏览器窗口 */
    browser_t *browser = browser_create();
    if (!browser) {
        fprintf(stderr, "错误：无法创建浏览器窗口\n");
        return EXIT_FAILURE;
    }

    /* 如果命令行参数提供了 URL，则自动加载 */
    if (argc > 1) {
        gtk_entry_set_text(GTK_ENTRY(browser->url_entry), argv[1]);
        browser_navigate(browser, argv[1]);
    }

    printf("简易浏览器已启动\n");
    printf("使用方法:\n");
    printf("  1. 在 URL 栏输入地址 (例如: http://localhost:8080/index.html)\n");
    printf("  2. 点击 GET 按钮获取页面\n");
    printf("  3. 点击 HEAD 按钮获取头部信息\n");
    printf("  4. 点击 DELETE 按钮删除文件\n");

    /* 运行主循环 */
    browser_run(browser);

    /* 清理 */
    browser_destroy(browser);

    printf("浏览器已退出\n");
    return EXIT_SUCCESS;
}
