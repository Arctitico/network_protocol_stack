#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include "../include/udp.h"
#include "../include/udp_recv.h"
#include "../include/udp_send.h"
#include "../../ip/include/ip.h"
#include "../../ip/include/ip_send.h"
#include "../../icmp/include/icmp.h"
#include "../../common/include/logger.h"

/* Use the global UDP logger */
extern logger_t g_udp_logger;

/* Receive buffer for each socket */
#define UDP_RECV_BUFFER_SIZE    65507  // Max UDP payload size
#define UDP_RECV_QUEUE_SIZE     8
#define MAX_UDP_PORTS           1024

typedef struct udp_recv_entry {
    uint8_t data[UDP_RECV_BUFFER_SIZE];
    int data_len;
    char src_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    int valid;
} udp_recv_entry_t;

typedef struct udp_recv_queue {
    udp_recv_entry_t entries[UDP_RECV_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int initialized;
} udp_recv_queue_t;

/* Per-port receive queues - dynamically allocated */
static udp_recv_queue_t *g_port_queues = NULL;
static int g_recv_initialized = 0;
static pthread_mutex_t g_recv_init_mutex = PTHREAD_MUTEX_INITIALIZER;

/* Session tracking for file transfers */
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    int packet_num;
    int total_bytes;
    char filename[256];
    int active;
    FILE *file;  // Keep file open for performance
} udp_session_t;

static udp_session_t g_sessions[16];
static int g_session_count = 0;
static int g_total_packet_count = 0;

/**
 * Initialize UDP receive subsystem
 */
void udp_recv_init(void)
{
    pthread_mutex_lock(&g_recv_init_mutex);
    
    if (g_recv_initialized)
    {
        pthread_mutex_unlock(&g_recv_init_mutex);
        return;
    }
    
    // Allocate port queues for commonly used ports (0-1023 + some high ports)
    g_port_queues = (udp_recv_queue_t *)calloc(MAX_UDP_PORTS, sizeof(udp_recv_queue_t));
    if (g_port_queues == NULL)
    {
        LOG_ERROR(&g_udp_logger, "Failed to allocate UDP receive queues");
        pthread_mutex_unlock(&g_recv_init_mutex);
        return;
    }
    
    // Initialize all port queues
    for (int i = 0; i < MAX_UDP_PORTS; i++)
    {
        memset(&g_port_queues[i], 0, sizeof(udp_recv_queue_t));
        pthread_mutex_init(&g_port_queues[i].mutex, NULL);
        pthread_cond_init(&g_port_queues[i].cond, NULL);
        g_port_queues[i].initialized = 0;
    }
    
    g_recv_initialized = 1;
    LOG_INFO(&g_udp_logger, "UDP receive subsystem initialized");
    
    pthread_mutex_unlock(&g_recv_init_mutex);
}

/**
 * Get queue for a specific port (maps high ports to available slots)
 */
static udp_recv_queue_t* get_port_queue(uint16_t port)
{
    if (g_port_queues == NULL) return NULL;
    
    // Map port to queue index
    int index;
    if (port < MAX_UDP_PORTS)
    {
        index = port;
    }
    else
    {
        // Hash high ports to available slots
        index = (port % (MAX_UDP_PORTS / 2)) + (MAX_UDP_PORTS / 2);
    }
    
    return &g_port_queues[index];
}

/**
 * Verify UDP checksum
 */
int verify_udp_checksum(const char *src_ip, const char *dest_ip,
                        udp_header_t *header, uint8_t *data, int data_len)
{
    // Checksum of 0 means no checksum
    if (header->checksum == 0)
    {
        LOG_DEBUG(&g_udp_logger, "Checksum is 0, skipping verification");
        return 1;
    }
    
    // Save original checksum
    uint16_t original_checksum = header->checksum;
    
    // Calculate checksum (this clears checksum field temporarily)
    uint16_t calculated = calculate_udp_checksum(src_ip, dest_ip, header, data, data_len);
    
    // Restore checksum
    header->checksum = original_checksum;
    
    // For verification, we need to include the checksum in calculation
    // and result should be 0xFFFF
    uint32_t sum = 0;
    uint8_t *ptr;
    int len;
    
    // Build pseudo header
    udp_pseudo_header_t pseudo;
    memset(&pseudo, 0, sizeof(pseudo));
    inet_pton(AF_INET, src_ip, &pseudo.src_ip);
    inet_pton(AF_INET, dest_ip, &pseudo.dest_ip);
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTO_UDP;
    pseudo.udp_length = header->length;
    
    // Sum pseudo header
    ptr = (uint8_t *)&pseudo;
    len = sizeof(pseudo);
    while (len > 1)
    {
        uint16_t word;
        memcpy(&word, ptr, sizeof(uint16_t));
        sum += word;
        ptr += 2;
        len -= 2;
    }
    
    // Sum UDP header (including checksum)
    ptr = (uint8_t *)header;
    len = UDP_HEADER_SIZE;
    while (len > 1)
    {
        uint16_t word;
        memcpy(&word, ptr, sizeof(uint16_t));
        sum += word;
        ptr += 2;
        len -= 2;
    }
    
    // Sum UDP data
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
    
    // Result should be 0xFFFF for valid checksum
    uint16_t result = (uint16_t)sum;
    
    LOG_DEBUG(&g_udp_logger, "Checksum verification: header=0x%04X, calculated=0x%04X, result=0x%04X",
              ntohs(original_checksum), ntohs(calculated), result);
    
    return (result == 0xFFFF);
}

/**
 * Send ICMP Port Unreachable message
 */
void send_icmp_port_unreachable(const char *src_ip, uint16_t dest_port,
                                 uint8_t *original_packet, int original_len,
                                 uint8_t *dest_mac)
{
    LOG_WARN(&g_udp_logger, "Port %d unreachable, sending ICMP message to %s", 
             dest_port, src_ip);
    
    // For now, just log the event
    // Full ICMP implementation would construct and send the message
    (void)original_packet;
    (void)original_len;
    (void)dest_mac;
    
    // TODO: Implement full ICMP Port Unreachable
    // This would involve:
    // 1. Build ICMP header with type=3, code=3
    // 2. Include original IP header + first 8 bytes of UDP header
    // 3. Send via IP layer
}

/**
 * Deliver data to a socket
 */
int udp_deliver_data(uint16_t local_port, const char *src_ip, 
                     uint16_t src_port, uint8_t *data, int data_len)
{
    if (!g_recv_initialized)
    {
        udp_recv_init();
    }
    
    if (local_port == 0)
    {
        LOG_ERROR(&g_udp_logger, "deliver_data: Invalid port 0");
        return -1;
    }
    
    udp_recv_queue_t *queue = get_port_queue(local_port);
    if (queue == NULL)
    {
        LOG_ERROR(&g_udp_logger, "deliver_data: Failed to get queue for port %d", local_port);
        return -1;
    }
    
    pthread_mutex_lock(&queue->mutex);
    
    // Check if queue is full
    if (queue->count >= UDP_RECV_QUEUE_SIZE)
    {
        LOG_WARN(&g_udp_logger, "deliver_data: Queue full for port %d, dropping packet", local_port);
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }
    
    // Add entry to queue
    udp_recv_entry_t *entry = &queue->entries[queue->tail];
    
    if (data_len > UDP_RECV_BUFFER_SIZE)
    {
        data_len = UDP_RECV_BUFFER_SIZE;
    }
    
    memcpy(entry->data, data, data_len);
    entry->data_len = data_len;
    strncpy(entry->src_ip, src_ip, INET_ADDRSTRLEN - 1);
    entry->src_ip[INET_ADDRSTRLEN - 1] = '\0';
    entry->src_port = src_port;
    entry->valid = 1;
    
    queue->tail = (queue->tail + 1) % UDP_RECV_QUEUE_SIZE;
    queue->count++;
    
    LOG_DEBUG(&g_udp_logger, "deliver_data: Queued %d bytes for port %d from %s:%d",
              data_len, local_port, src_ip, src_port);
    
    // Signal waiting receivers
    pthread_cond_signal(&queue->cond);
    
    pthread_mutex_unlock(&queue->mutex);
    
    return 0;
}

/**
 * Process received UDP packet from IP layer
 */
int process_udp_packet(uint8_t *udp_packet, int packet_len,
                       const char *src_ip, const char *dest_ip)
{
    if (packet_len < UDP_HEADER_SIZE)
    {
        LOG_ERROR(&g_udp_logger, "process_udp: Packet too small: %d bytes", packet_len);
        return -1;
    }
    
    udp_header_t *header = (udp_header_t *)udp_packet;
    uint16_t udp_length = ntohs(header->length);
    int data_len = udp_length - UDP_HEADER_SIZE;
    
    // Validate length
    if (udp_length > packet_len)
    {
        LOG_ERROR(&g_udp_logger, "process_udp: Length mismatch: header=%d, packet=%d", 
                  udp_length, packet_len);
        return -1;
    }
    
    if (data_len < 0)
    {
        LOG_ERROR(&g_udp_logger, "process_udp: Invalid data length: %d", data_len);
        return -1;
    }
    
    LOG_INFO(&g_udp_logger, "========== UDP Packet Received ==========");
    display_udp_header(header, data_len);
    
    uint8_t *data = udp_packet + UDP_HEADER_SIZE;
    
    // Verify checksum
    if (!verify_udp_checksum(src_ip, dest_ip, header, data, data_len))
    {
        LOG_WARN(&g_udp_logger, "process_udp: Checksum error, dropping packet");
        return -1;
    }
    
    LOG_DEBUG(&g_udp_logger, "Checksum verified: OK");
    
    // Get port numbers
    uint16_t dest_port = ntohs(header->dest_port);
    uint16_t src_port_val = ntohs(header->src_port);
    
    // Check if there's a socket bound to this port
    udp_socket_t *sock = NULL;
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        udp_socket_t *s = get_udp_socket(i);
        if (s != NULL && s->bound && s->local_port == dest_port)
        {
            sock = s;
            break;
        }
    }
    
    if (sock == NULL)
    {
        // No socket bound to this port
        LOG_WARN(&g_udp_logger, "process_udp: No socket bound to port %d", dest_port);
        // TODO: Send ICMP Port Unreachable
        return -1;
    }
    
    // Save data directly to file (primary storage for large file transfers)
    // This happens BEFORE queue delivery to ensure no data loss
    
    // Find or create session for this source
    udp_session_t *current_session = NULL;
    for (int i = 0; i < g_session_count; i++)
    {
        if (strcmp(g_sessions[i].src_ip, src_ip) == 0 && 
            g_sessions[i].src_port == src_port_val &&
            g_sessions[i].active)
        {
            current_session = &g_sessions[i];
            break;
        }
    }
    
    if (current_session == NULL && g_session_count < 16)
    {
        // New session - use timestamp to create unique filename
        current_session = &g_sessions[g_session_count++];
        strncpy(current_session->src_ip, src_ip, INET_ADDRSTRLEN - 1);
        current_session->src_port = src_port_val;
        current_session->packet_num = 0;
        current_session->total_bytes = 0;
        current_session->active = 1;
        current_session->file = NULL;
        
        // Create unique filename with timestamp
        time_t now = time(NULL);
        struct tm *t = localtime(&now);
        snprintf(current_session->filename, sizeof(current_session->filename),
                 "output/udp_%04d%02d%02d_%02d%02d%02d.bin",
                 t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
                 t->tm_hour, t->tm_min, t->tm_sec);
        
        // Open file once and keep it open
        current_session->file = fopen(current_session->filename, "wb");
        if (current_session->file == NULL)
        {
            LOG_ERROR(&g_udp_logger, "Failed to open file: %s", current_session->filename);
        }
    }
    
    if (current_session != NULL)
    {
        current_session->packet_num++;
        current_session->total_bytes += data_len;
        g_total_packet_count++;
        
        // Write to session file (already open)
        if (current_session->file != NULL)
        {
            fwrite(data, 1, data_len, current_session->file);
            // Don't fflush every packet - let OS buffer handle it
            LOG_INFO(&g_udp_logger, "Data written to: %s (%d bytes, total: %d)", 
                     current_session->filename, data_len, current_session->total_bytes);
            
            // Print progress (compact format for large transfers)
            if (current_session->packet_num == 1)
            {
                // First packet - show full info
                printf("\n========================================\n");
                printf("  NEW FILE TRANSFER STARTED\n");
                printf("========================================\n");
                printf("    From:      %s:%d\n", src_ip, src_port_val);
                printf("    To Port:   %d\n", dest_port);
                printf("    Saving to: %s\n", current_session->filename);
                printf("========================================\n");
                printf("    Receiving: ");
                fflush(stdout);
            }
            
            // Progress indicator (dot every packet, number every 10)
            if (current_session->packet_num % 50 == 0)
            {
                printf(" [%d packets, %d bytes]\n    ", 
                       current_session->packet_num, current_session->total_bytes);
            }
            else if (current_session->packet_num % 10 == 0)
            {
                printf("%d", (current_session->packet_num / 10) % 10);
            }
            else
            {
                printf(".");
            }
            fflush(stdout);
        }
        else
        {
            LOG_ERROR(&g_udp_logger, "Failed to save data to file: %s", current_session->filename);
        }
    }
    
    // Optionally deliver to queue (for recvfrom API), but don't fail if queue is full
    udp_deliver_data(dest_port, src_ip, src_port_val, data, data_len);
    
    LOG_INFO(&g_udp_logger, "process_udp: Saved %d bytes to file", data_len);
    LOG_INFO(&g_udp_logger, "=========================================");
    
    return data_len;
}

/**
 * Receive data via UDP
 */
int udp_recvfrom(int sockid, uint8_t *buf, int buflen, int flags,
                 sockaddr_in_custom_t *src_addr, int *addrlen)
{
    (void)flags;  // Suppress unused parameter warning
    
    udp_socket_t *sock = get_udp_socket(sockid);
    if (sock == NULL)
    {
        LOG_ERROR(&g_udp_logger, "recvfrom: Invalid socket ID: %d", sockid);
        return -1;
    }
    
    if (buf == NULL || buflen <= 0)
    {
        LOG_ERROR(&g_udp_logger, "recvfrom: Invalid buffer");
        return -1;
    }
    
    if (!sock->bound)
    {
        LOG_ERROR(&g_udp_logger, "recvfrom: Socket not bound");
        return -1;
    }
    
    if (!g_recv_initialized)
    {
        udp_recv_init();
    }
    
    uint16_t local_port = sock->local_port;
    udp_recv_queue_t *queue = get_port_queue(local_port);
    if (queue == NULL)
    {
        LOG_ERROR(&g_udp_logger, "recvfrom: Failed to get queue for port %d", local_port);
        return -1;
    }
    
    LOG_DEBUG(&g_udp_logger, "recvfrom: Waiting for data on port %d", local_port);
    
    pthread_mutex_lock(&queue->mutex);
    
    // Wait for data
    while (queue->count == 0)
    {
        pthread_cond_wait(&queue->cond, &queue->mutex);
    }
    
    // Get entry from queue
    udp_recv_entry_t *entry = &queue->entries[queue->head];
    
    int copy_len = (entry->data_len < buflen) ? entry->data_len : buflen;
    memcpy(buf, entry->data, copy_len);
    
    // Fill source address if requested
    if (src_addr != NULL)
    {
        memset(src_addr, 0, sizeof(sockaddr_in_custom_t));
        src_addr->sin_family = AF_INET_CUSTOM;
        src_addr->sin_port = htons(entry->src_port);
        inet_pton(AF_INET, entry->src_ip, &src_addr->sin_addr);
        
        if (addrlen != NULL)
        {
            *addrlen = sizeof(sockaddr_in_custom_t);
        }
    }
    
    // Update five-tuple with source info
    strncpy(sock->target_address, entry->src_ip, sizeof(sock->target_address) - 1);
    sock->target_port = entry->src_port;
    
    // Clear and advance queue
    entry->valid = 0;
    queue->head = (queue->head + 1) % UDP_RECV_QUEUE_SIZE;
    queue->count--;
    
    pthread_mutex_unlock(&queue->mutex);
    
    LOG_INFO(&g_udp_logger, "========== UDP recvfrom ==========");
    LOG_INFO(&g_udp_logger, "Socket ID:      %d", sockid);
    LOG_INFO(&g_udp_logger, "Source:         %s:%d", sock->target_address, sock->target_port);
    LOG_INFO(&g_udp_logger, "Received:       %d bytes", copy_len);
    LOG_INFO(&g_udp_logger, "==================================");
    
    return copy_len;
}

/**
 * Print summary of all received file transfers
 */
void udp_recv_print_summary(void)
{
    // First, close all open file handles
    for (int i = 0; i < g_session_count; i++)
    {
        if (g_sessions[i].file != NULL)
        {
            fclose(g_sessions[i].file);
            g_sessions[i].file = NULL;
        }
    }
    
    printf("\n========================================\n");
    printf("  FILE TRANSFER SUMMARY\n");
    printf("========================================\n");
    
    if (g_session_count == 0)
    {
        printf("    No files received.\n");
    }
    else
    {
        int total_bytes = 0;
        for (int i = 0; i < g_session_count; i++)
        {
            if (g_sessions[i].active)
            {
                printf("    File #%d:\n", i + 1);
                printf("      From:    %s:%d\n", g_sessions[i].src_ip, g_sessions[i].src_port);
                printf("      Packets: %d\n", g_sessions[i].packet_num);
                printf("      Size:    %d bytes\n", g_sessions[i].total_bytes);
                printf("      Saved:   %s\n", g_sessions[i].filename);
                total_bytes += g_sessions[i].total_bytes;
            }
        }
        printf("----------------------------------------\n");
        printf("    Total: %d files, %d bytes\n", g_session_count, total_bytes);
    }
    printf("========================================\n\n");
}
