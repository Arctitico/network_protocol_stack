/**
 * @file browser_gui.h
 * @brief GTK 图形界面浏览器头文件
 * 
 * 提供图形化界面的浏览器功能
 */

#ifndef BROWSER_GUI_H
#define BROWSER_GUI_H

#include <gtk/gtk.h>
#include <webkit2/webkit2.h>

/* 浏览器窗口结构 */
typedef struct {
    GtkWidget *window;          /* 主窗口 */
    GtkWidget *url_entry;       /* URL 输入框 */
    GtkWidget *go_button;       /* 转到按钮 */
    GtkWidget *head_button;     /* HEAD 按钮 */
    GtkWidget *delete_button;   /* DELETE 按钮 */
    GtkWidget *web_view;        /* WebKit 网页视图 */
    GtkWidget *status_label;    /* 状态栏标签 */
    GtkWidget *raw_view;        /* 原始响应视图 (TextView) */
    GtkTextBuffer *raw_buffer;  /* 原始响应缓冲区 */
} browser_t;

/**
 * @brief 创建浏览器窗口
 * @return 浏览器结构体指针
 */
browser_t *browser_create(void);

/**
 * @brief 销毁浏览器窗口
 * @param browser 浏览器结构体指针
 */
void browser_destroy(browser_t *browser);

/**
 * @brief 导航到指定 URL
 * @param browser 浏览器结构体指针
 * @param url 目标 URL
 */
void browser_navigate(browser_t *browser, const char *url);

/**
 * @brief 发送 HEAD 请求
 * @param browser 浏览器结构体指针
 * @param url 目标 URL
 */
void browser_head(browser_t *browser, const char *url);

/**
 * @brief 发送 DELETE 请求
 * @param browser 浏览器结构体指针
 * @param url 目标 URL
 */
void browser_delete(browser_t *browser, const char *url);

/**
 * @brief 更新状态栏
 * @param browser 浏览器结构体指针
 * @param status 状态文本
 */
void browser_set_status(browser_t *browser, const char *status);

/**
 * @brief 显示内容
 * @param browser 浏览器结构体指针
 * @param content 要显示的内容
 */
void browser_set_content(browser_t *browser, const char *content);

/**
 * @brief 显示原始响应
 * @param browser 浏览器结构体指针
 * @param raw 原始响应文本
 */
void browser_set_raw_response(browser_t *browser, const char *raw);

/**
 * @brief 运行浏览器主循环
 * @param browser 浏览器结构体指针
 */
void browser_run(browser_t *browser);

#endif /* BROWSER_GUI_H */
