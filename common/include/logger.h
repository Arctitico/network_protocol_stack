#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>

/* Log levels */
typedef enum {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO  = 1,
    LOG_LEVEL_WARN  = 2,
    LOG_LEVEL_ERROR = 3
} log_level_t;

/* Logger roles */
typedef enum {
    LOG_ROLE_NONE = 0,      // No role specified
    LOG_ROLE_SEND = 1,      // Sender
    LOG_ROLE_RECV = 2       // Receiver
} log_role_t;

/* Logger configuration */
typedef struct {
    FILE *file;                 // Log file handle
    log_level_t level;          // Minimum log level to output
    int console_enabled;        // Also print to console (1=yes, 0=no)
    int file_enabled;           // Write to log file (1=yes, 0=no)
    const char *module_name;    // Module name (e.g., "ETHERNET", "IP", "ARP")
    log_role_t role;            // Role (SEND/RECV/NONE)
} logger_t;

/**
 * @brief Initialize logger
 * @param logger Logger instance
 * @param module_name Module name for log prefix
 * @param log_file_path Path to log file (NULL for console only)
 * @param level Minimum log level
 * @param console_enabled Whether to also print to console
 * @return 0 on success, -1 on failure
 */
int logger_init(logger_t *logger, const char *module_name, 
                const char *log_file_path, log_level_t level, 
                int console_enabled);

/**
 * @brief Close logger and release resources
 * @param logger Logger instance
 */
void logger_close(logger_t *logger);

/**
 * @brief Set logger role (SEND/RECV)
 * @param logger Logger instance
 * @param role Role to set
 */
void logger_set_role(logger_t *logger, log_role_t role);

/**
 * @brief Write log message
 * @param logger Logger instance
 * @param level Log level
 * @param fmt Format string
 * @param ... Variable arguments
 */
void logger_log(logger_t *logger, log_level_t level, const char *fmt, ...);

/**
 * @brief Log hex dump of data
 * @param logger Logger instance
 * @param level Log level
 * @param prefix Prefix string
 * @param data Data to dump
 * @param len Data length
 */
void logger_hex_dump(logger_t *logger, log_level_t level, 
                     const char *prefix, const uint8_t *data, int len);

/* Convenience macros */
#define LOG_DEBUG(logger, fmt, ...) \
    logger_log(logger, LOG_LEVEL_DEBUG, fmt, ##__VA_ARGS__)

#define LOG_INFO(logger, fmt, ...) \
    logger_log(logger, LOG_LEVEL_INFO, fmt, ##__VA_ARGS__)

#define LOG_WARN(logger, fmt, ...) \
    logger_log(logger, LOG_LEVEL_WARN, fmt, ##__VA_ARGS__)

#define LOG_ERROR(logger, fmt, ...) \
    logger_log(logger, LOG_LEVEL_ERROR, fmt, ##__VA_ARGS__)

#endif /* LOGGER_H */
