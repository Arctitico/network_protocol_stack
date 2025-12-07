#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include "../include/logger.h"

/* Log level names */
static const char *level_names[] = {
    "DEBUG",
    "INFO ",
    "WARN ",
    "ERROR"
};

/* Log level colors (ANSI escape codes) */
static const char *level_colors[] = {
    "\033[36m",     /* DEBUG: Cyan */
    "\033[32m",     /* INFO:  Green */
    "\033[33m",     /* WARN:  Yellow */
    "\033[31m"      /* ERROR: Red */
};

static const char *color_reset = "\033[0m";

/* Role names */
static const char *role_names[] = {
    "",       /* NONE */
    "SEND",   /* SEND */
    "RECV"    /* RECV */
};

/**
 * @brief Get current timestamp string
 */
static void get_timestamp(char *buffer, size_t len)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(buffer, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

/**
 * @brief Create directory if it doesn't exist
 */
static int ensure_directory(const char *path)
{
    char *dir = strdup(path);
    char *last_slash = strrchr(dir, '/');
    
    if (last_slash != NULL)
    {
        *last_slash = '\0';
        if (strlen(dir) > 0)
        {
            struct stat st;
            if (stat(dir, &st) != 0)
            {
                if (mkdir(dir, 0755) != 0 && errno != EEXIST)
                {
                    free(dir);
                    return -1;
                }
            }
        }
    }
    
    free(dir);
    return 0;
}

int logger_init(logger_t *logger, const char *module_name,
                const char *log_file_path, log_level_t level,
                int console_enabled)
{
    if (logger == NULL || module_name == NULL)
    {
        return -1;
    }
    
    logger->module_name = module_name;
    logger->level = level;
    logger->console_enabled = console_enabled;
    logger->file = NULL;
    logger->role = LOG_ROLE_NONE;
    
    // Check LOG_DISABLE environment variable (1 = disable file logging)
    int file_enabled = 1;
    char *log_disable = getenv("LOG_DISABLE");
    if (log_disable != NULL && atoi(log_disable) == 1)
    {
        file_enabled = 0;
    }
    logger->file_enabled = file_enabled;
    
    if (log_file_path != NULL && file_enabled)
    {
        /* Ensure directory exists */
        if (ensure_directory(log_file_path) < 0)
        {
            fprintf(stderr, "Failed to create log directory\n");
            return -1;
        }
        
        /* Open log file in append mode */
        logger->file = fopen(log_file_path, "a");
        if (logger->file == NULL)
        {
            fprintf(stderr, "Failed to open log file: %s\n", log_file_path);
            return -1;
        }
        
        /* Write session header */
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(logger->file, "\n");
        fprintf(logger->file, "========================================\n");
        fprintf(logger->file, " %s Logger Started - %s\n", module_name, timestamp);
        fprintf(logger->file, "========================================\n");
        fflush(logger->file);
    }
    
    return 0;
}

void logger_close(logger_t *logger)
{
    if (logger != NULL && logger->file != NULL)
    {
        char timestamp[32];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(logger->file, "========================================\n");
        fprintf(logger->file, " %s Logger Closed - %s\n", logger->module_name, timestamp);
        fprintf(logger->file, "========================================\n\n");
        fclose(logger->file);
        logger->file = NULL;
    }
}

void logger_set_role(logger_t *logger, log_role_t role)
{
    if (logger != NULL)
    {
        logger->role = role;
    }
}

void logger_log(logger_t *logger, log_level_t level, const char *fmt, ...)
{
    if (logger == NULL || level < logger->level)
    {
        return;
    }
    
    // Fast path: if both file and console are disabled, skip all work
    int do_file = (logger->file != NULL && logger->file_enabled);
    int do_console = logger->console_enabled;
    
    if (!do_file && !do_console)
    {
        return;
    }
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    /* Build module string with optional role */
    char module_str[32];
    if (logger->role != LOG_ROLE_NONE)
    {
        snprintf(module_str, sizeof(module_str), "%s:%s", 
                 logger->module_name, role_names[logger->role]);
    }
    else
    {
        snprintf(module_str, sizeof(module_str), "%s", logger->module_name);
    }
    
    va_list args;
    
    /* Write to file (no colors) - only if file logging is enabled */
    if (do_file)
    {
        fprintf(logger->file, "[%s] [%s] [%s] ", 
                timestamp, level_names[level], module_str);
        
        va_start(args, fmt);
        vfprintf(logger->file, fmt, args);
        va_end(args);
        
        fprintf(logger->file, "\n");
        // Only flush for errors to improve performance
        if (level >= LOG_LEVEL_ERROR)
        {
            fflush(logger->file);
        }
    }
    
    /* Write to console (with colors) */
    if (do_console)
    {
        fprintf(stdout, "%s[%s]%s [%s] ", 
                level_colors[level], level_names[level], color_reset,
                module_str);
        
        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
        
        fprintf(stdout, "\n");
        fflush(stdout);
    }
}

void logger_hex_dump(logger_t *logger, log_level_t level,
                     const char *prefix, const uint8_t *data, int len)
{
    if (logger == NULL || level < logger->level || data == NULL)
    {
        return;
    }
    
    // Fast path: if both file and console are disabled, skip all work
    int do_file = (logger->file != NULL && logger->file_enabled);
    int do_console = logger->console_enabled;
    
    if (!do_file && !do_console)
    {
        return;
    }
    
    char timestamp[32];
    get_timestamp(timestamp, sizeof(timestamp));
    
    /* Build hex string */
    char hex_line[80];
    char ascii_line[20];
    int offset = 0;
    
    /* Write to file - only if file logging is enabled */
    if (logger->file != NULL && logger->file_enabled)
    {
        fprintf(logger->file, "[%s] [%s] [%s] %s (%d bytes):\n",
                timestamp, level_names[level], logger->module_name, prefix, len);
        
        for (int i = 0; i < len; i += 16)
        {
            offset = 0;
            offset += snprintf(hex_line + offset, sizeof(hex_line) - offset, 
                              "  %04X: ", i);
            
            memset(ascii_line, 0, sizeof(ascii_line));
            
            for (int j = 0; j < 16 && (i + j) < len; j++)
            {
                offset += snprintf(hex_line + offset, sizeof(hex_line) - offset,
                                  "%02X ", data[i + j]);
                ascii_line[j] = (data[i + j] >= 32 && data[i + j] < 127) 
                               ? data[i + j] : '.';
            }
            
            /* Pad if needed */
            for (int j = len - i; j < 16 && j >= 0; j++)
            {
                offset += snprintf(hex_line + offset, sizeof(hex_line) - offset, "   ");
            }
            
            fprintf(logger->file, "%s |%s|\n", hex_line, ascii_line);
        }
        fflush(logger->file);
    }
    
    /* Write to console (simplified) */
    if (logger->console_enabled)
    {
        fprintf(stdout, "%s[%s]%s [%s] %s (%d bytes)\n",
                level_colors[level], level_names[level], color_reset,
                logger->module_name, prefix, len);
        
        for (int i = 0; i < len && i < 64; i += 16)
        {
            fprintf(stdout, "  %04X: ", i);
            for (int j = 0; j < 16 && (i + j) < len; j++)
            {
                fprintf(stdout, "%02X ", data[i + j]);
            }
            fprintf(stdout, "\n");
        }
        
        if (len > 64)
        {
            fprintf(stdout, "  ... (%d more bytes, see log file for full dump)\n", len - 64);
        }
        fflush(stdout);
    }
}
