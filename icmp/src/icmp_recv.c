#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "../include/icmp.h"
#include "../include/icmp_recv.h"
#include "../../ip/include/ip.h"
#include "../../ip/include/ip_send.h"
#include "../../common/include/logger.h"

/* Global logger instance for ICMP module */
logger_t g_icmp_logger;
static int g_icmp_logger_initialized = 0;

/* Global context for ICMP processing */
static const char *g_local_ip = NULL;
static uint8_t g_local_mac[6] = {0};

/**
 * Initialize ICMP logger
 */
void icmp_logger_init(void)
{
    if (g_icmp_logger_initialized) return;
    
    // Check LOG_QUIET environment variable (1 = no console output)
    int console_enabled = (getenv("LOG_QUIET") == NULL) ? 1 : 0;
    
    int ret = logger_init(&g_icmp_logger, "ICMP", "output/icmp.log", 
                          LOG_LEVEL_DEBUG, console_enabled);
    if (ret == 0)
    {
        g_icmp_logger_initialized = 1;
        LOG_INFO(&g_icmp_logger, "ICMP logger initialized");
    }
}

/**
 * Close ICMP logger
 */
void icmp_logger_close(void)
{
    if (g_icmp_logger_initialized)
    {
        LOG_INFO(&g_icmp_logger, "ICMP logger closing");
        logger_close(&g_icmp_logger);
        g_icmp_logger_initialized = 0;
    }
}

/**
 * Get ICMP type name string
 */
const char* icmp_type_to_string(uint8_t type)
{
    switch (type)
    {
        case ICMP_TYPE_ECHO_REPLY:
            return "Echo Reply";
        case ICMP_TYPE_DEST_UNREACHABLE:
            return "Destination Unreachable";
        case ICMP_TYPE_SOURCE_QUENCH:
            return "Source Quench";
        case ICMP_TYPE_REDIRECT:
            return "Redirect";
        case ICMP_TYPE_ECHO_REQUEST:
            return "Echo Request";
        case ICMP_TYPE_TIME_EXCEEDED:
            return "Time Exceeded";
        case ICMP_TYPE_PARAM_PROBLEM:
            return "Parameter Problem";
        case ICMP_TYPE_TIMESTAMP:
            return "Timestamp Request";
        case ICMP_TYPE_TIMESTAMP_REPLY:
            return "Timestamp Reply";
        case ICMP_TYPE_INFO_REQUEST:
            return "Information Request";
        case ICMP_TYPE_INFO_REPLY:
            return "Information Reply";
        default:
            return "Unknown";
    }
}

/**
 * Display ICMP header information
 */
void display_icmp_header(icmp_header_t *header, int data_len)
{
    LOG_INFO(&g_icmp_logger, "========== ICMP Header ==========");
    LOG_INFO(&g_icmp_logger, "Type:       %d (%s)", header->type, icmp_type_to_string(header->type));
    LOG_INFO(&g_icmp_logger, "Code:       %d", header->code);
    LOG_INFO(&g_icmp_logger, "Checksum:   0x%04X", ntohs(header->checksum));
    LOG_INFO(&g_icmp_logger, "Identifier: %d", ntohs(header->identifier));
    LOG_INFO(&g_icmp_logger, "Sequence:   %d", ntohs(header->sequence));
    LOG_INFO(&g_icmp_logger, "Data Len:   %d bytes", data_len);
    LOG_INFO(&g_icmp_logger, "=================================");
}

/**
 * Calculate ICMP checksum
 */
uint16_t calculate_icmp_checksum(icmp_header_t *header, uint8_t *data, int data_len)
{
    uint32_t sum = 0;
    uint8_t *ptr;
    int len;
    
    // Save and clear checksum field
    uint16_t original_checksum = header->checksum;
    header->checksum = 0;
    
    // Sum ICMP header
    ptr = (uint8_t *)header;
    len = ICMP_HEADER_SIZE;
    
    while (len > 1)
    {
        uint16_t word;
        memcpy(&word, ptr, sizeof(uint16_t));
        sum += word;
        ptr += 2;
        len -= 2;
    }
    
    // Sum ICMP data
    if (data != NULL && data_len > 0)
    {
        ptr = data;
        len = data_len;
        
        while (len > 1)
        {
            uint16_t word;
            memcpy(&word, ptr, sizeof(uint16_t));
            sum += word;
            ptr += 2;
            len -= 2;
        }
        
        // Add odd byte if present
        if (len > 0)
        {
            sum += *ptr;
        }
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Restore original checksum
    header->checksum = original_checksum;
    
    // Return one's complement
    return (uint16_t)(~sum);
}

/**
 * Verify ICMP checksum
 */
int verify_icmp_checksum(icmp_header_t *header, uint8_t *data, int data_len)
{
    uint32_t sum = 0;
    uint8_t *ptr;
    int len;
    
    // Sum ICMP header (including checksum)
    ptr = (uint8_t *)header;
    len = ICMP_HEADER_SIZE;
    
    while (len > 1)
    {
        uint16_t word;
        memcpy(&word, ptr, sizeof(uint16_t));
        sum += word;
        ptr += 2;
        len -= 2;
    }
    
    // Sum ICMP data
    if (data != NULL && data_len > 0)
    {
        ptr = data;
        len = data_len;
        
        while (len > 1)
        {
            uint16_t word;
            memcpy(&word, ptr, sizeof(uint16_t));
            sum += word;
            ptr += 2;
            len -= 2;
        }
        
        // Add odd byte if present
        if (len > 0)
        {
            sum += *ptr;
        }
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Checksum is valid if result is 0xFFFF or 0x0000
    return (sum == 0xFFFF || sum == 0x0000);
}

/**
 * Set ICMP processing context
 */
void icmp_set_context(const char *local_ip, const uint8_t *local_mac)
{
    g_local_ip = local_ip;
    if (local_mac != NULL)
    {
        memcpy(g_local_mac, local_mac, 6);
    }
    LOG_DEBUG(&g_icmp_logger, "ICMP context set: local_ip=%s", local_ip);
}

/**
 * Verify ICMP packet integrity
 */
int verify_icmp_packet(const uint8_t *buffer, int len)
{
    if (len < ICMP_HEADER_SIZE)
    {
        LOG_WARN(&g_icmp_logger, "ICMP packet too small: %d bytes", len);
        return 0;
    }
    
    icmp_header_t *header = (icmp_header_t *)buffer;
    uint8_t *data = (len > ICMP_HEADER_SIZE) ? (uint8_t *)(buffer + ICMP_HEADER_SIZE) : NULL;
    int data_len = len - ICMP_HEADER_SIZE;
    
    // Verify checksum
    if (!verify_icmp_checksum(header, data, data_len))
    {
        LOG_WARN(&g_icmp_logger, "ICMP checksum verification failed");
        return 0;
    }
    
    return 1;
}

/**
 * Parse ICMP header from buffer
 */
int parse_icmp_header(const uint8_t *buffer, icmp_header_t *header)
{
    memcpy(header, buffer, sizeof(icmp_header_t));
    return 0;
}

/**
 * Build ICMP ECHO Reply packet
 */
int build_icmp_echo_reply(icmp_header_t *request_header, uint8_t *request_data,
                          int request_data_len, uint8_t *reply_buffer, int *reply_len)
{
    icmp_header_t *reply_header = (icmp_header_t *)reply_buffer;
    
    // Set type to Echo Reply (0)
    reply_header->type = ICMP_TYPE_ECHO_REPLY;
    
    // Code is always 0 for Echo Reply
    reply_header->code = 0;
    
    // Copy identifier and sequence from request
    reply_header->identifier = request_header->identifier;
    reply_header->sequence = request_header->sequence;
    
    // Copy data from request
    if (request_data != NULL && request_data_len > 0)
    {
        memcpy(reply_buffer + ICMP_HEADER_SIZE, request_data, request_data_len);
    }
    
    // Calculate checksum
    reply_header->checksum = 0;
    reply_header->checksum = calculate_icmp_checksum(reply_header, 
                                                     reply_buffer + ICMP_HEADER_SIZE, 
                                                     request_data_len);
    
    *reply_len = ICMP_HEADER_SIZE + request_data_len;
    
    LOG_DEBUG(&g_icmp_logger, "Built ICMP Echo Reply: ID=%d, Seq=%d, DataLen=%d",
              ntohs(reply_header->identifier), ntohs(reply_header->sequence), request_data_len);
    
    return 0;
}

/**
 * Send ICMP reply through IP layer
 */
int icmp_send_reply(uint8_t *icmp_packet, int icmp_len,
                    const char *src_ip, const char *dest_ip, uint8_t *dest_mac)
{
    LOG_INFO(&g_icmp_logger, "Sending ICMP reply via IP layer");
    LOG_INFO(&g_icmp_logger, "  Source IP:      %s", src_ip);
    LOG_INFO(&g_icmp_logger, "  Destination IP: %s", dest_ip);
    LOG_INFO(&g_icmp_logger, "  ICMP Length:    %d bytes", icmp_len);
    
    // Send via IP layer
    int result = ip_send(icmp_packet, icmp_len, IP_PROTO_ICMP, 
                         src_ip, dest_ip, dest_mac);
    
    if (result > 0)
    {
        LOG_INFO(&g_icmp_logger, "ICMP reply sent successfully (%d fragments)", result);
        return 1;
    }
    else
    {
        LOG_ERROR(&g_icmp_logger, "Failed to send ICMP reply");
        return -1;
    }
}

/**
 * Process received ICMP packet (main entry point)
 * 
 * According to the requirements:
 * - If ICMP ECHO Request: construct ECHO Reply and send via IP -> Ethernet
 * - Otherwise: no processing
 */
int icmp_recv(uint8_t *icmp_buffer, int icmp_len, const char *src_ip, uint8_t *dest_mac)
{
    LOG_INFO(&g_icmp_logger, "========== ICMP Packet Received ==========");
    LOG_INFO(&g_icmp_logger, "ICMP packet length: %d bytes", icmp_len);
    LOG_INFO(&g_icmp_logger, "Source IP (for reply): %s", src_ip);
    
    // Verify packet integrity
    if (!verify_icmp_packet(icmp_buffer, icmp_len))
    {
        LOG_ERROR(&g_icmp_logger, "Invalid ICMP packet, discarding");
        return -1;
    }
    LOG_DEBUG(&g_icmp_logger, "ICMP checksum verified: OK");
    
    // Parse ICMP header
    icmp_header_t header;
    parse_icmp_header(icmp_buffer, &header);
    
    // Calculate data length
    int data_len = icmp_len - ICMP_HEADER_SIZE;
    uint8_t *icmp_data = (data_len > 0) ? (icmp_buffer + ICMP_HEADER_SIZE) : NULL;
    
    // Display header information
    display_icmp_header(&header, data_len);
    
    // Check if this is an ICMP ECHO Request
    if (header.type == ICMP_TYPE_ECHO_REQUEST)
    {
        LOG_INFO(&g_icmp_logger, "Received ICMP ECHO Request (ping)");
        LOG_INFO(&g_icmp_logger, "  Identifier: %d", ntohs(header.identifier));
        LOG_INFO(&g_icmp_logger, "  Sequence:   %d", ntohs(header.sequence));
        
        // Check if we have context set
        if (g_local_ip == NULL)
        {
            LOG_ERROR(&g_icmp_logger, "ICMP context not set, cannot send reply");
            return -1;
        }
        
        // Build ICMP ECHO Reply
        uint8_t reply_buffer[ICMP_HEADER_SIZE + ICMP_MAX_DATA_SIZE];
        int reply_len = 0;
        
        if (build_icmp_echo_reply(&header, icmp_data, data_len, reply_buffer, &reply_len) < 0)
        {
            LOG_ERROR(&g_icmp_logger, "Failed to build ICMP Echo Reply");
            return -1;
        }
        
        LOG_INFO(&g_icmp_logger, "Built ICMP Echo Reply (%d bytes)", reply_len);
        
        // Send reply via IP layer
        // Source IP = local IP (our IP)
        // Destination IP = src_ip (the IP that sent the request)
        int result = icmp_send_reply(reply_buffer, reply_len, g_local_ip, src_ip, dest_mac);
        
        if (result > 0)
        {
            LOG_INFO(&g_icmp_logger, "ICMP Echo Reply sent successfully!");
            printf("[ICMP] Echo Reply sent to %s (ID=%d, Seq=%d)\n", 
                   src_ip, ntohs(header.identifier), ntohs(header.sequence));
            return 1;
        }
        else
        {
            LOG_ERROR(&g_icmp_logger, "Failed to send ICMP Echo Reply");
            return -1;
        }
    }
    else
    {
        // For other ICMP types, no processing as per requirements
        LOG_INFO(&g_icmp_logger, "ICMP type %d (%s) received, no processing required",
                 header.type, icmp_type_to_string(header.type));
        return 0;
    }
}
