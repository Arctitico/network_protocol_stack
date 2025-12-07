#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/udp.h"
#include "../include/udp_send.h"
#include "../../common/include/logger.h"

/* Use the global UDP logger */
extern logger_t g_udp_logger;

/**
 * Display UDP header information
 */
void display_udp_header(udp_header_t *header, int data_len)
{
    LOG_INFO(&g_udp_logger, "========== UDP Header ==========");
    LOG_INFO(&g_udp_logger, "Source Port:      %d", ntohs(header->src_port));
    LOG_INFO(&g_udp_logger, "Destination Port: %d", ntohs(header->dest_port));
    LOG_INFO(&g_udp_logger, "Length:           %d bytes", ntohs(header->length));
    LOG_INFO(&g_udp_logger, "Checksum:         0x%04X", ntohs(header->checksum));
    LOG_INFO(&g_udp_logger, "Data Length:      %d bytes", data_len);
    LOG_INFO(&g_udp_logger, "================================");
}
