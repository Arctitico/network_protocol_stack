/**
 * @file browser_gui.c
 * @brief GTK + WebKit 图形界面浏览器实现
 */

#include "../include/browser_gui.h"
#include "../include/http_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_WIDTH  1024
#define DEFAULT_HEIGHT 768

/* 回调函数声明 */
static void on_go_button_clicked(GtkWidget *widget, gpointer data);
static void on_head_button_clicked(GtkWidget *widget, gpointer data);
static void on_delete_button_clicked(GtkWidget *widget, gpointer data);
static void on_url_entry_activate(GtkWidget *widget, gpointer data);
static gboolean on_window_delete(GtkWidget *widget, GdkEvent *event, gpointer data);

static GtkWidget *create_toolbar(browser_t *browser) {
    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_set_margin_start(toolbar, 5);
    gtk_widget_set_margin_end(toolbar, 5);
    gtk_widget_set_margin_top(toolbar, 5);
    gtk_widget_set_margin_bottom(toolbar, 5);

    GtkWidget *url_label = gtk_label_new("URL:");
    gtk_box_pack_start(GTK_BOX(toolbar), url_label, FALSE, FALSE, 0);

    browser->url_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(browser->url_entry), 
                                   "http://localhost:8080/index.html");
    gtk_widget_set_hexpand(browser->url_entry, TRUE);
    g_signal_connect(browser->url_entry, "activate", G_CALLBACK(on_url_entry_activate), browser);
    gtk_box_pack_start(GTK_BOX(toolbar), browser->url_entry, TRUE, TRUE, 0);

    browser->go_button = gtk_button_new_with_label("GET");
    g_signal_connect(browser->go_button, "clicked", G_CALLBACK(on_go_button_clicked), browser);
    gtk_box_pack_start(GTK_BOX(toolbar), browser->go_button, FALSE, FALSE, 0);

    browser->head_button = gtk_button_new_with_label("HEAD");
    g_signal_connect(browser->head_button, "clicked", G_CALLBACK(on_head_button_clicked), browser);
    gtk_box_pack_start(GTK_BOX(toolbar), browser->head_button, FALSE, FALSE, 0);

    browser->delete_button = gtk_button_new_with_label("DELETE");
    g_signal_connect(browser->delete_button, "clicked", G_CALLBACK(on_delete_button_clicked), browser);
    gtk_box_pack_start(GTK_BOX(toolbar), browser->delete_button, FALSE, FALSE, 0);

    return toolbar;
}

static GtkWidget *create_content_area(browser_t *browser) {
    GtkWidget *notebook = gtk_notebook_new();

    /* WebKit 渲染视图 */
    GtkWidget *web_scroll = gtk_scrolled_window_new(NULL, NULL);
    browser->web_view = webkit_web_view_new();
    gtk_container_add(GTK_CONTAINER(web_scroll), browser->web_view);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), web_scroll, gtk_label_new("页面内容"));

    /* 原始响应视图 */
    GtkWidget *raw_scroll = gtk_scrolled_window_new(NULL, NULL);
    browser->raw_view = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(browser->raw_view), GTK_WRAP_WORD_CHAR);
    gtk_text_view_set_editable(GTK_TEXT_VIEW(browser->raw_view), FALSE);
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(browser->raw_view), 10);
    browser->raw_buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(browser->raw_view));
    gtk_container_add(GTK_CONTAINER(raw_scroll), browser->raw_view);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), raw_scroll, gtk_label_new("原始响应"));

    return notebook;
}

static GtkWidget *create_status_bar(browser_t *browser) {
    GtkWidget *status_bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_widget_set_margin_start(status_bar, 5);
    gtk_widget_set_margin_bottom(status_bar, 2);
    browser->status_label = gtk_label_new("就绪");
    gtk_label_set_xalign(GTK_LABEL(browser->status_label), 0.0);
    gtk_box_pack_start(GTK_BOX(status_bar), browser->status_label, TRUE, TRUE, 0);
    return status_bar;
}

browser_t *browser_create(void) {
    browser_t *browser = calloc(1, sizeof(browser_t));
    if (!browser) return NULL;

    browser->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(browser->window), "简易浏览器");
    gtk_window_set_default_size(GTK_WINDOW(browser->window), DEFAULT_WIDTH, DEFAULT_HEIGHT);
    gtk_window_set_position(GTK_WINDOW(browser->window), GTK_WIN_POS_CENTER);
    g_signal_connect(browser->window, "delete-event", G_CALLBACK(on_window_delete), browser);

    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(browser->window), main_box);

    gtk_box_pack_start(GTK_BOX(main_box), create_toolbar(browser), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), create_content_area(browser), TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), gtk_separator_new(GTK_ORIENTATION_HORIZONTAL), FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(main_box), create_status_bar(browser), FALSE, FALSE, 0);

    /* 显示欢迎页 */
    const char *welcome = "<html><body><h1>简易浏览器</h1><p>在上方输入 URL 后点击 GET 获取页面</p></body></html>";
    webkit_web_view_load_html(WEBKIT_WEB_VIEW(browser->web_view), welcome, NULL);

    return browser;
}

void browser_destroy(browser_t *browser) {
    if (browser) {
        if (browser->window) gtk_widget_destroy(browser->window);
        free(browser);
    }
}

void browser_set_status(browser_t *browser, const char *status) {
    if (browser && browser->status_label)
        gtk_label_set_text(GTK_LABEL(browser->status_label), status);
}

void browser_set_content(browser_t *browser, const char *content) {
    if (browser && browser->web_view && content)
        webkit_web_view_load_html(WEBKIT_WEB_VIEW(browser->web_view), content, NULL);
}

void browser_set_raw_response(browser_t *browser, const char *raw) {
    if (browser && browser->raw_buffer && raw)
        gtk_text_buffer_set_text(browser->raw_buffer, raw, -1);
}

void browser_navigate(browser_t *browser, const char *url) {
    if (!browser || !url || strlen(url) == 0) return;

    char status_msg[256];
    snprintf(status_msg, sizeof(status_msg), "正在加载: %s", url);
    browser_set_status(browser, status_msg);

    http_response_t response;
    memset(&response, 0, sizeof(response));

    if (http_get(url, &response) < 0) {
        browser_set_content(browser, "<html><body><h1>错误</h1><p>无法连接到服务器</p></body></html>");
        browser_set_status(browser, "连接失败");
        return;
    }

    /* 显示原始响应 */
    char raw_display[8192];
    snprintf(raw_display, sizeof(raw_display),
             "状态码: %d %s\nContent-Type: %s\nContent-Length: %d\n\n--- 头部 ---\n%s\n\n--- 响应体 ---\n%s",
             response.status_code, response.status_msg, response.content_type,
             response.content_length, response.headers ? response.headers : "",
             response.body ? response.body : "");
    browser_set_raw_response(browser, raw_display);

    if (response.status_code == 200 && response.body) {
        webkit_web_view_load_html(WEBKIT_WEB_VIEW(browser->web_view), response.body, url);
        snprintf(status_msg, sizeof(status_msg), "完成 - %d %s", response.status_code, response.status_msg);
    } else {
        char error_html[2048];
        snprintf(error_html, sizeof(error_html),
                 "<html><body><h1>HTTP %d</h1><p>%s</p><pre>%s</pre></body></html>",
                 response.status_code, response.status_msg, response.body ? response.body : "");
        browser_set_content(browser, error_html);
        snprintf(status_msg, sizeof(status_msg), "错误 - %d %s", response.status_code, response.status_msg);
    }
    browser_set_status(browser, status_msg);
    http_response_free(&response);
}

void browser_head(browser_t *browser, const char *url) {
    if (!browser || !url || strlen(url) == 0) return;

    browser_set_status(browser, "正在获取头部...");

    http_response_t response;
    memset(&response, 0, sizeof(response));

    if (http_head(url, &response) < 0) {
        browser_set_content(browser, "<html><body><h1>错误</h1><p>无法连接到服务器</p></body></html>");
        browser_set_status(browser, "连接失败");
        return;
    }

    char display[4096];
    snprintf(display, sizeof(display),
             "<html><body><h1>HEAD 请求结果</h1><p>URL: %s</p>"
             "<p>状态码: %d %s</p><h2>响应头部</h2><pre>%s</pre></body></html>",
             url, response.status_code, response.status_msg,
             response.headers ? response.headers : "");
    browser_set_content(browser, display);
    browser_set_raw_response(browser, response.headers ? response.headers : "");

    char status_msg[128];
    snprintf(status_msg, sizeof(status_msg), "HEAD 完成 - %d", response.status_code);
    browser_set_status(browser, status_msg);
    http_response_free(&response);
}

void browser_delete(browser_t *browser, const char *url) {
    if (!browser || !url || strlen(url) == 0) return;

    GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(browser->window),
        GTK_DIALOG_MODAL, GTK_MESSAGE_WARNING, GTK_BUTTONS_YES_NO,
        "确定要删除 %s 吗？", url);
    gint result = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    if (result != GTK_RESPONSE_YES) return;

    browser_set_status(browser, "正在删除...");

    http_response_t response;
    memset(&response, 0, sizeof(response));

    if (http_delete(url, &response) < 0) {
        browser_set_content(browser, "<html><body><h1>错误</h1><p>无法连接到服务器</p></body></html>");
        browser_set_status(browser, "连接失败");
        return;
    }

    char display[4096];
    snprintf(display, sizeof(display),
             "<html><body><h1>DELETE 请求结果</h1><p>URL: %s</p>"
             "<p>状态码: %d %s</p><pre>%s</pre></body></html>",
             url, response.status_code, response.status_msg,
             response.body ? response.body : "");
    browser_set_content(browser, display);

    char status_msg[128];
    snprintf(status_msg, sizeof(status_msg), "DELETE 完成 - %d", response.status_code);
    browser_set_status(browser, status_msg);
    http_response_free(&response);
}

void browser_run(browser_t *browser) {
    if (browser && browser->window) {
        gtk_widget_show_all(browser->window);
        gtk_main();
    }
}

static void on_go_button_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    browser_t *browser = (browser_t *)data;
    browser_navigate(browser, gtk_entry_get_text(GTK_ENTRY(browser->url_entry)));
}

static void on_head_button_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    browser_t *browser = (browser_t *)data;
    browser_head(browser, gtk_entry_get_text(GTK_ENTRY(browser->url_entry)));
}

static void on_delete_button_clicked(GtkWidget *widget, gpointer data) {
    (void)widget;
    browser_t *browser = (browser_t *)data;
    browser_delete(browser, gtk_entry_get_text(GTK_ENTRY(browser->url_entry)));
}

static void on_url_entry_activate(GtkWidget *widget, gpointer data) {
    (void)widget;
    browser_t *browser = (browser_t *)data;
    browser_navigate(browser, gtk_entry_get_text(GTK_ENTRY(browser->url_entry)));
}

static gboolean on_window_delete(GtkWidget *widget, GdkEvent *event, gpointer data) {
    (void)widget; (void)event; (void)data;
    gtk_main_quit();
    return FALSE;
}
