#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <math.h>
#include "../include/ip_send.h"
#include "../../ethernet/include/ethernet_send.h"
#include "../../ethernet/include/ethernet.h"
#include "../../common/include/logger.h"

// Global IP identification counter
static uint16_t g_ip_id = 0;

// Global IP logger
logger_t g_ip_logger;
static int g_ip_logger_initialized = 0;

/**
 * Initialize IP logger
 */
void ip_logger_init(void)
{
    if (g_ip_logger_initialized) return;
    
    // Check LOG_QUIET environment variable (1 = no console output)
    int console_enabled = (getenv("LOG_QUIET") == NULL) ? 1 : 0;
    
    int ret = logger_init(&g_ip_logger, "IP", "output/ip.log", 
                          LOG_LEVEL_DEBUG, console_enabled);
    if (ret == 0)
    {
        g_ip_logger_initialized = 1;
        LOG_INFO(&g_ip_logger, "IP logger initialized");
    }
}

/**
 * Close IP logger
 */
void ip_logger_close(void)
{
    if (g_ip_logger_initialized)
    {
        LOG_INFO(&g_ip_logger, "IP logger closing");
        logger_close(&g_ip_logger);
        g_ip_logger_initialized = 0;
    }
}

/**
 * Calculate IP header checksum
 */
uint16_t calculate_ip_checksum(ip_header_t *header, int header_len)
{
    uint32_t sum = 0;
    uint8_t *ptr = (uint8_t *)header;
    int len = header_len;
    
    // Save and clear checksum field
    uint16_t original_checksum = header->checksum;
    header->checksum = 0;
    
    // Sum all 16-bit words
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
 * Build IP header
 */
void build_ip_header(ip_header_t *header, int data_len, uint16_t identification,
                     uint16_t flags_offset, uint8_t protocol,
                     const char *src_ip, const char *dest_ip)
{
    // Clear header
    memset(header, 0, sizeof(ip_header_t));
    
    // Version (4) and IHL (15 for 60 bytes header)
    header->version_ihl = (IP_VERSION_4 << 4) | 15;
    
    // Type of Service (default)
    header->tos = IP_DEFAULT_TOS;
    
    // Total length (header + data)
    header->total_length = htons(IP_HEADER_MAX_SIZE + data_len);
    
    // Identification
    header->identification = htons(identification);
    
    // Flags and fragment offset
    header->flags_offset = htons(flags_offset);
    
    // Time to Live
    header->ttl = IP_DEFAULT_TTL;
    
    // Protocol
    header->protocol = protocol;
    
    // Source and destination IP
    inet_pton(AF_INET, src_ip, &header->src_ip);
    inet_pton(AF_INET, dest_ip, &header->dest_ip);
    
    // Options (all zeros)
    memset(header->options, 0, IP_OPTIONS_SIZE);
    
    // Calculate checksum
    header->checksum = calculate_ip_checksum(header, IP_HEADER_MAX_SIZE);
}

/**
 * Send IP packet with fragmentation support
 */
int ip_send(uint8_t *data, int data_len, uint8_t protocol,
            const char *src_ip, const char *dest_ip, uint8_t *dest_mac)
{
    uint8_t packet_buffer[IP_MAX_PACKET_SIZE];
    int num_fragments;
    int fragment_count = 0;
    uint16_t identification = g_ip_id++;
    
    LOG_INFO(&g_ip_logger, "========== IP Layer - Sending ==========");
    LOG_INFO(&g_ip_logger, "Data length:   %d bytes", data_len);
    LOG_INFO(&g_ip_logger, "Source IP:     %s", src_ip);
    LOG_INFO(&g_ip_logger, "Destination IP: %s", dest_ip);
    
    const char *proto_str;
    switch (protocol)
    {
        case IP_PROTO_TCP:
            proto_str = "(TCP)";
            break;
        case IP_PROTO_UDP:
            proto_str = "(UDP)";
            break;
        case IP_PROTO_ICMP:
            proto_str = "(ICMP)";
            break;
        default:
            proto_str = "(Unknown)";
            break;
    }
    LOG_INFO(&g_ip_logger, "Protocol:      %d %s", protocol, proto_str);
    
    // Calculate number of fragments needed
    if (data_len <= IP_MAX_DATA_SIZE)
    {
        num_fragments = 1;
        LOG_DEBUG(&g_ip_logger, "Fragmentation: Not needed");
    }
    else
    {
        num_fragments = (int)ceil((double)data_len / IP_MAX_DATA_SIZE);
        LOG_INFO(&g_ip_logger, "Fragmentation: Required (%d fragments)", num_fragments);
    }
    
    LOG_DEBUG(&g_ip_logger, "Identification: %u", identification);
    LOG_INFO(&g_ip_logger, "========================================");
    
    // Send each fragment via Ethernet layer
    int offset = 0;
    for (int i = 0; i < num_fragments; i++)
    {
        ip_header_t *header = (ip_header_t *)packet_buffer;
        int current_data_len;
        uint16_t flags_offset;
        
        // Determine fragment data length
        if (i == num_fragments - 1)
        {
            // Last fragment
            current_data_len = data_len - offset;
            flags_offset = (offset / 8) & IP_OFFSET_MASK;  // MF=0
        }
        else
        {
            // Not last fragment
            current_data_len = IP_MAX_DATA_SIZE;
            flags_offset = IP_FLAG_MF | ((offset / 8) & IP_OFFSET_MASK);  // MF=1
        }
        
        // Build IP header
        build_ip_header(header, current_data_len, identification,
                        flags_offset, protocol, src_ip, dest_ip);
        
        // Copy data
        memcpy(packet_buffer + IP_HEADER_MAX_SIZE, data + offset, current_data_len);
        
        // Send packet via Ethernet layer
        int packet_len = IP_HEADER_MAX_SIZE + current_data_len;
        
        LOG_DEBUG(&g_ip_logger, "Fragment %d/%d:", i + 1, num_fragments);
        LOG_DEBUG(&g_ip_logger, "  Offset:       %d bytes", offset);
        LOG_DEBUG(&g_ip_logger, "  Data length:  %d bytes", current_data_len);
        LOG_DEBUG(&g_ip_logger, "  Total length: %d bytes", packet_len);
        LOG_DEBUG(&g_ip_logger, "  Flags:        MF=%d", (flags_offset & IP_FLAG_MF) ? 1 : 0);
        LOG_DEBUG(&g_ip_logger, "  Checksum:     0x%04X", ntohs(header->checksum));
        
        // Send via Ethernet layer
        uint8_t src_mac[6] = {0};  // Will be auto-filled by Ethernet layer
        if (ethernet_send(packet_buffer, packet_len, dest_mac, src_mac, ETHERNET_TYPE_IPV4) < 0)
        {
            LOG_ERROR(&g_ip_logger, "Failed to send fragment %d via Ethernet layer", i + 1);
            return -1;
        }
        
        LOG_DEBUG(&g_ip_logger, "  Sent via Ethernet layer");
        
        offset += current_data_len;
        fragment_count++;
    }
    
    LOG_INFO(&g_ip_logger, "========================================");
    LOG_INFO(&g_ip_logger, "Total fragments sent: %d", fragment_count);
    LOG_INFO(&g_ip_logger, "Data delivered to Ethernet Layer");
    LOG_INFO(&g_ip_logger, "========================================");
    
    return fragment_count;
}
