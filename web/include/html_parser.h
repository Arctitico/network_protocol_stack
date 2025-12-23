/**
 * @file html_parser.h
 * @brief 简单 HTML 解析器头文件
 * 
 * 提供基本的 HTML 标签解析和文本提取功能
 */

#ifndef HTML_PARSER_H
#define HTML_PARSER_H

#include <stddef.h>

/* HTML 元素类型 */
typedef enum {
    HTML_ELEMENT_TEXT,      /* 纯文本 */
    HTML_ELEMENT_H1,        /* 一级标题 */
    HTML_ELEMENT_H2,        /* 二级标题 */
    HTML_ELEMENT_H3,        /* 三级标题 */
    HTML_ELEMENT_P,         /* 段落 */
    HTML_ELEMENT_BR,        /* 换行 */
    HTML_ELEMENT_IMG,       /* 图片 */
    HTML_ELEMENT_A,         /* 链接 */
    HTML_ELEMENT_TITLE,     /* 页面标题 */
    HTML_ELEMENT_HR,        /* 水平线 */
    HTML_ELEMENT_UNKNOWN    /* 未知元素 */
} html_element_type_t;

/* HTML 元素节点 */
typedef struct html_element {
    html_element_type_t type;       /* 元素类型 */
    char *content;                  /* 文本内容 */
    char *attr_src;                 /* src 属性 (用于 IMG) */
    char *attr_href;                /* href 属性 (用于 A) */
    char *attr_alt;                 /* alt 属性 */
    int attr_width;                 /* width 属性 */
    int attr_height;                /* height 属性 */
    struct html_element *next;      /* 下一个元素 */
} html_element_t;

/* 解析结果 */
typedef struct {
    char *title;                    /* 页面标题 */
    html_element_t *elements;       /* 元素链表 */
    int element_count;              /* 元素数量 */
} html_document_t;

/**
 * @brief 解析 HTML 文档
 * @param html HTML 字符串
 * @param len HTML 长度
 * @return 解析后的文档结构
 */
html_document_t *html_parse(const char *html, size_t len);

/**
 * @brief 释放文档内存
 * @param doc 文档指针
 */
void html_document_free(html_document_t *doc);

/**
 * @brief 将解析后的 HTML 转换为纯文本 (用于 GTK TextView 显示)
 * @param doc 文档指针
 * @return 格式化的文本字符串 (需要调用者 free)
 */
char *html_to_plain_text(html_document_t *doc);

/**
 * @brief 将解析后的 HTML 转换为 Pango Markup (用于 GTK 渲染)
 * @param doc 文档指针
 * @return Pango Markup 字符串 (需要调用者 free)
 */
char *html_to_pango_markup(html_document_t *doc);

/**
 * @brief HTML 实体解码
 * @param text 含有实体的文本
 * @return 解码后的文本 (需要调用者 free)
 */
char *html_decode_entities(const char *text);

#endif /* HTML_PARSER_H */
