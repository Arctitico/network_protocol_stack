/**
 * @file html_parser.c
 * @brief 简单 HTML 解析器实现
 * 
 * 提供基本的 HTML 标签解析和文本提取功能
 */

#include "../include/html_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* 辅助函数：创建新元素 */
static html_element_t *create_element(html_element_type_t type) {
    html_element_t *elem = calloc(1, sizeof(html_element_t));
    if (elem) {
        elem->type = type;
    }
    return elem;
}

/* 辅助函数：添加元素到链表 */
static void append_element(html_document_t *doc, html_element_t *elem) {
    if (!doc || !elem) return;

    if (!doc->elements) {
        doc->elements = elem;
    } else {
        html_element_t *curr = doc->elements;
        while (curr->next) {
            curr = curr->next;
        }
        curr->next = elem;
    }
    doc->element_count++;
}

/* 辅助函数：跳过空白字符 */
static const char *skip_whitespace(const char *p) {
    while (*p && isspace((unsigned char)*p)) p++;
    return p;
}

/* 辅助函数：提取标签名 */
static int get_tag_name(const char *tag_start, char *name, size_t max_len) {
    const char *p = tag_start + 1;  /* 跳过 '<' */
    
    /* 跳过结束标签的 '/' */
    if (*p == '/') p++;
    
    size_t i = 0;
    while (*p && !isspace((unsigned char)*p) && *p != '>' && *p != '/' && i < max_len - 1) {
        name[i++] = tolower((unsigned char)*p);
        p++;
    }
    name[i] = '\0';
    return i > 0;
}

/* 辅助函数：提取属性值 */
static char *get_attribute(const char *tag, const char *attr_name) {
    char search[64];
    snprintf(search, sizeof(search), "%s=", attr_name);
    
    const char *attr = strcasestr(tag, search);
    if (!attr) return NULL;
    
    attr += strlen(search);
    
    char quote = 0;
    if (*attr == '"' || *attr == '\'') {
        quote = *attr;
        attr++;
    }
    
    const char *end;
    if (quote) {
        end = strchr(attr, quote);
    } else {
        end = attr;
        while (*end && !isspace((unsigned char)*end) && *end != '>') end++;
    }
    
    if (!end) return NULL;
    
    size_t len = end - attr;
    char *value = malloc(len + 1);
    if (value) {
        strncpy(value, attr, len);
        value[len] = '\0';
    }
    return value;
}

/* 辅助函数：提取标签间的内容 */
static char *extract_content(const char *start, const char *end) {
    if (!start || !end || end <= start) return NULL;
    
    size_t len = end - start;
    char *content = malloc(len + 1);
    if (content) {
        strncpy(content, start, len);
        content[len] = '\0';
        
        /* 去除前后空白 */
        char *p = content;
        while (*p && isspace((unsigned char)*p)) p++;
        
        if (p != content) {
            memmove(content, p, strlen(p) + 1);
        }
        
        size_t clen = strlen(content);
        while (clen > 0 && isspace((unsigned char)content[clen - 1])) {
            content[--clen] = '\0';
        }
    }
    return content;
}

/* 辅助函数：查找结束标签 */
static const char *find_end_tag(const char *html, const char *tag_name) {
    char search[64];
    snprintf(search, sizeof(search), "</%s>", tag_name);
    return strcasestr(html, search);
}

/* 辅助函数：获取元素类型 */
static html_element_type_t get_element_type(const char *tag_name) {
    if (strcasecmp(tag_name, "h1") == 0) return HTML_ELEMENT_H1;
    if (strcasecmp(tag_name, "h2") == 0) return HTML_ELEMENT_H2;
    if (strcasecmp(tag_name, "h3") == 0) return HTML_ELEMENT_H3;
    if (strcasecmp(tag_name, "p") == 0) return HTML_ELEMENT_P;
    if (strcasecmp(tag_name, "br") == 0) return HTML_ELEMENT_BR;
    if (strcasecmp(tag_name, "img") == 0) return HTML_ELEMENT_IMG;
    if (strcasecmp(tag_name, "a") == 0) return HTML_ELEMENT_A;
    if (strcasecmp(tag_name, "title") == 0) return HTML_ELEMENT_TITLE;
    if (strcasecmp(tag_name, "hr") == 0) return HTML_ELEMENT_HR;
    return HTML_ELEMENT_UNKNOWN;
}

/**
 * @brief 解析 HTML 文档
 */
html_document_t *html_parse(const char *html, size_t len) {
    if (!html || len == 0) return NULL;

    html_document_t *doc = calloc(1, sizeof(html_document_t));
    if (!doc) return NULL;

    const char *p = html;
    const char *end = html + len;
    
    /* 跳过 DOCTYPE 和其他预处理 */
    const char *body_start = strcasestr(html, "<body");
    if (body_start) {
        /* 找到 body 标签的结束 > */
        const char *body_tag_end = strchr(body_start, '>');
        if (body_tag_end) {
            p = body_tag_end + 1;
        }
    }

    while (p && p < end) {
        /* 跳过空白 */
        p = skip_whitespace(p);
        if (!p || p >= end) break;

        if (*p == '<') {
            /* 这是一个标签 */
            const char *tag_end = strchr(p, '>');
            if (!tag_end) break;

            /* 跳过注释 */
            if (strncmp(p, "<!--", 4) == 0) {
                const char *comment_end = strstr(p, "-->");
                if (comment_end) {
                    p = comment_end + 3;
                    continue;
                }
            }

            /* 跳过结束标签 */
            if (p[1] == '/') {
                p = tag_end + 1;
                continue;
            }

            char tag_name[32];
            if (!get_tag_name(p, tag_name, sizeof(tag_name))) {
                p = tag_end + 1;
                continue;
            }

            html_element_type_t type = get_element_type(tag_name);

            /* 处理不同类型的标签 */
            switch (type) {
                case HTML_ELEMENT_TITLE: {
                    const char *content_start = tag_end + 1;
                    const char *content_end = find_end_tag(content_start, "title");
                    if (content_end) {
                        doc->title = extract_content(content_start, content_end);
                        p = content_end + strlen("</title>");
                    } else {
                        p = tag_end + 1;
                    }
                    break;
                }

                case HTML_ELEMENT_H1:
                case HTML_ELEMENT_H2:
                case HTML_ELEMENT_H3:
                case HTML_ELEMENT_P:
                case HTML_ELEMENT_A: {
                    html_element_t *elem = create_element(type);
                    if (elem) {
                        /* 提取 href 属性（用于链接） */
                        if (type == HTML_ELEMENT_A) {
                            char tag_copy[512];
                            size_t tag_len = tag_end - p + 1;
                            if (tag_len < sizeof(tag_copy)) {
                                strncpy(tag_copy, p, tag_len);
                                tag_copy[tag_len] = '\0';
                                elem->attr_href = get_attribute(tag_copy, "href");
                            }
                        }

                        const char *content_start = tag_end + 1;
                        const char *content_end = find_end_tag(content_start, tag_name);
                        if (content_end) {
                            elem->content = extract_content(content_start, content_end);
                            p = content_end + strlen(tag_name) + 3;
                        } else {
                            p = tag_end + 1;
                        }
                        append_element(doc, elem);
                    } else {
                        p = tag_end + 1;
                    }
                    break;
                }

                case HTML_ELEMENT_IMG: {
                    html_element_t *elem = create_element(type);
                    if (elem) {
                        char tag_copy[512];
                        size_t tag_len = tag_end - p + 1;
                        if (tag_len < sizeof(tag_copy)) {
                            strncpy(tag_copy, p, tag_len);
                            tag_copy[tag_len] = '\0';
                            elem->attr_src = get_attribute(tag_copy, "src");
                            elem->attr_alt = get_attribute(tag_copy, "alt");
                            
                            char *width_str = get_attribute(tag_copy, "width");
                            if (width_str) {
                                elem->attr_width = atoi(width_str);
                                free(width_str);
                            }
                            
                            char *height_str = get_attribute(tag_copy, "height");
                            if (height_str) {
                                elem->attr_height = atoi(height_str);
                                free(height_str);
                            }
                        }
                        append_element(doc, elem);
                    }
                    p = tag_end + 1;
                    break;
                }

                case HTML_ELEMENT_BR: {
                    html_element_t *elem = create_element(type);
                    if (elem) {
                        append_element(doc, elem);
                    }
                    p = tag_end + 1;
                    break;
                }

                case HTML_ELEMENT_HR: {
                    html_element_t *elem = create_element(type);
                    if (elem) {
                        append_element(doc, elem);
                    }
                    p = tag_end + 1;
                    break;
                }

                default:
                    p = tag_end + 1;
                    break;
            }
        } else {
            /* 这是纯文本 */
            const char *text_end = strchr(p, '<');
            if (!text_end) text_end = end;

            char *content = extract_content(p, text_end);
            if (content && strlen(content) > 0) {
                html_element_t *elem = create_element(HTML_ELEMENT_TEXT);
                if (elem) {
                    elem->content = content;
                    append_element(doc, elem);
                } else {
                    free(content);
                }
            } else {
                free(content);
            }

            p = text_end;
        }
    }

    return doc;
}

/**
 * @brief 释放文档内存
 */
void html_document_free(html_document_t *doc) {
    if (!doc) return;

    free(doc->title);

    html_element_t *elem = doc->elements;
    while (elem) {
        html_element_t *next = elem->next;
        free(elem->content);
        free(elem->attr_src);
        free(elem->attr_href);
        free(elem->attr_alt);
        free(elem);
        elem = next;
    }

    free(doc);
}

/**
 * @brief 将解析后的 HTML 转换为纯文本
 */
char *html_to_plain_text(html_document_t *doc) {
    if (!doc) return NULL;

    size_t buf_size = 4096;
    char *buffer = malloc(buf_size);
    if (!buffer) return NULL;

    size_t offset = 0;
    buffer[0] = '\0';

    /* 添加标题 */
    if (doc->title) {
        offset += snprintf(buffer + offset, buf_size - offset, 
                          "=== %s ===\n\n", doc->title);
    }

    /* 遍历所有元素 */
    html_element_t *elem = doc->elements;
    while (elem) {
        /* 检查缓冲区是否足够 */
        if (offset > buf_size - 512) {
            buf_size *= 2;
            char *new_buf = realloc(buffer, buf_size);
            if (!new_buf) {
                free(buffer);
                return NULL;
            }
            buffer = new_buf;
        }

        switch (elem->type) {
            case HTML_ELEMENT_H1:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "\n【%s】\n\n", elem->content);
                }
                break;

            case HTML_ELEMENT_H2:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "\n◆ %s\n\n", elem->content);
                }
                break;

            case HTML_ELEMENT_H3:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "\n● %s\n\n", elem->content);
                }
                break;

            case HTML_ELEMENT_P:
            case HTML_ELEMENT_TEXT:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "%s\n", elem->content);
                }
                break;

            case HTML_ELEMENT_A:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "[%s]", elem->content);
                    if (elem->attr_href) {
                        offset += snprintf(buffer + offset, buf_size - offset,
                                          "(%s)", elem->attr_href);
                    }
                    offset += snprintf(buffer + offset, buf_size - offset, "\n");
                }
                break;

            case HTML_ELEMENT_IMG:
                offset += snprintf(buffer + offset, buf_size - offset,
                                  "[图片: %s]\n", 
                                  elem->attr_alt ? elem->attr_alt : 
                                  (elem->attr_src ? elem->attr_src : "无描述"));
                break;

            case HTML_ELEMENT_BR:
                offset += snprintf(buffer + offset, buf_size - offset, "\n");
                break;

            case HTML_ELEMENT_HR:
                offset += snprintf(buffer + offset, buf_size - offset,
                                  "────────────────────────────────\n");
                break;

            default:
                break;
        }

        elem = elem->next;
    }

    return buffer;
}

/**
 * @brief 将解析后的 HTML 转换为 Pango Markup
 */
char *html_to_pango_markup(html_document_t *doc) {
    if (!doc) return NULL;

    size_t buf_size = 8192;
    char *buffer = malloc(buf_size);
    if (!buffer) return NULL;

    size_t offset = 0;
    buffer[0] = '\0';

    /* 添加标题 */
    if (doc->title) {
        offset += snprintf(buffer + offset, buf_size - offset,
                          "<span size='x-large' weight='bold'>%s</span>\n\n", 
                          doc->title);
    }

    /* 遍历所有元素 */
    html_element_t *elem = doc->elements;
    while (elem) {
        /* 检查缓冲区是否足够 */
        if (offset > buf_size - 1024) {
            buf_size *= 2;
            char *new_buf = realloc(buffer, buf_size);
            if (!new_buf) {
                free(buffer);
                return NULL;
            }
            buffer = new_buf;
        }

        switch (elem->type) {
            case HTML_ELEMENT_H1:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "\n<span size='xx-large' weight='bold'>%s</span>\n\n", 
                                      elem->content);
                }
                break;

            case HTML_ELEMENT_H2:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "\n<span size='x-large' weight='bold'>%s</span>\n\n", 
                                      elem->content);
                }
                break;

            case HTML_ELEMENT_H3:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "\n<span size='large' weight='bold'>%s</span>\n\n", 
                                      elem->content);
                }
                break;

            case HTML_ELEMENT_P:
            case HTML_ELEMENT_TEXT:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "%s\n", elem->content);
                }
                break;

            case HTML_ELEMENT_A:
                if (elem->content) {
                    offset += snprintf(buffer + offset, buf_size - offset,
                                      "<span foreground='blue' underline='single'>%s</span>", 
                                      elem->content);
                    if (elem->attr_href) {
                        offset += snprintf(buffer + offset, buf_size - offset,
                                          " <span size='small'>(%s)</span>", 
                                          elem->attr_href);
                    }
                    offset += snprintf(buffer + offset, buf_size - offset, "\n");
                }
                break;

            case HTML_ELEMENT_IMG:
                offset += snprintf(buffer + offset, buf_size - offset,
                                  "<span foreground='gray'>[图片: %s]</span>\n",
                                  elem->attr_alt ? elem->attr_alt :
                                  (elem->attr_src ? elem->attr_src : "无描述"));
                break;

            case HTML_ELEMENT_BR:
                offset += snprintf(buffer + offset, buf_size - offset, "\n");
                break;

            case HTML_ELEMENT_HR:
                offset += snprintf(buffer + offset, buf_size - offset,
                                  "<span foreground='gray'>────────────────────────────────</span>\n");
                break;

            default:
                break;
        }

        elem = elem->next;
    }

    return buffer;
}

/**
 * @brief HTML 实体解码
 */
char *html_decode_entities(const char *text) {
    if (!text) return NULL;

    size_t len = strlen(text);
    char *result = malloc(len + 1);
    if (!result) return NULL;

    const char *src = text;
    char *dst = result;

    while (*src) {
        if (*src == '&') {
            if (strncmp(src, "&lt;", 4) == 0) {
                *dst++ = '<';
                src += 4;
            } else if (strncmp(src, "&gt;", 4) == 0) {
                *dst++ = '>';
                src += 4;
            } else if (strncmp(src, "&amp;", 5) == 0) {
                *dst++ = '&';
                src += 5;
            } else if (strncmp(src, "&quot;", 6) == 0) {
                *dst++ = '"';
                src += 6;
            } else if (strncmp(src, "&nbsp;", 6) == 0) {
                *dst++ = ' ';
                src += 6;
            } else if (strncmp(src, "&#", 2) == 0) {
                /* 数字实体 */
                int code = 0;
                const char *p = src + 2;
                while (*p >= '0' && *p <= '9') {
                    code = code * 10 + (*p - '0');
                    p++;
                }
                if (*p == ';') {
                    if (code < 128) *dst++ = (char)code;
                    src = p + 1;
                } else {
                    *dst++ = *src++;
                }
            } else {
                *dst++ = *src++;
            }
        } else {
            *dst++ = *src++;
        }
    }

    *dst = '\0';
    return result;
}
