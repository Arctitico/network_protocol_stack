#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include "../include/udp.h"
#include "../include/udp_send.h"
#include "../../ip/include/ip.h"
#include "../../ip/include/ip_send.h"
#include "../../common/include/logger.h"

/* Global UDP logger */
logger_t g_udp_logger;
static int g_udp_logger_initialized = 0;

/* Socket management */
static udp_socket_t g_sockets[MAX_SOCKETS];
static int g_socket_initialized = 0;

/* Ephemeral port counter (dynamic ports start from 49152) */
static uint16_t g_ephemeral_port = 49152;

/**
 * Get local IP address for socket initialization
 * Returns "0.0.0.0" as default
 */
static void get_default_local_ip(char *ip_str, size_t len)
{
    strncpy(ip_str, "0.0.0.0", len);
    ip_str[len - 1] = '\0';
}

/**
 * Initialize socket subsystem
 */
static void init_socket_system(void)
{
    if (g_socket_initialized) return;
    
    memset(g_sockets, 0, sizeof(g_sockets));
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        g_sockets[i].valid = 0;
        g_sockets[i].bound = 0;
        g_sockets[i].local_port = -1;
        g_sockets[i].target_port = -1;
    }
    
    g_socket_initialized = 1;
}

/**
 * Get UDP socket by socket ID
 */
udp_socket_t* get_udp_socket(int sockid)
{
    if (sockid < 0 || sockid >= MAX_SOCKETS)
    {
        return NULL;
    }
    
    if (!g_sockets[sockid].valid)
    {
        return NULL;
    }
    
    return &g_sockets[sockid];
}

/**
 * Initialize UDP logger
 */
void udp_logger_init(void)
{
    if (g_udp_logger_initialized) return;
    
    // Check LOG_QUIET environment variable (0 = enable console output)
    int console_enabled = (getenv("LOG_QUIET") != NULL && atoi(getenv("LOG_QUIET")) == 0) ? 1 : 0;
    
    int ret = logger_init(&g_udp_logger, "UDP", "output/udp.log", 
                          LOG_LEVEL_DEBUG, console_enabled);
    if (ret == 0)
    {
        g_udp_logger_initialized = 1;
        LOG_INFO(&g_udp_logger, "UDP logger initialized");
    }
    
    // Initialize socket system
    init_socket_system();
}

/**
 * Close UDP logger
 */
void udp_logger_close(void)
{
    if (g_udp_logger_initialized)
    {
        LOG_INFO(&g_udp_logger, "UDP logger closing");
        logger_close(&g_udp_logger);
        g_udp_logger_initialized = 0;
    }
}

/**
 * Calculate UDP checksum (includes pseudo header)
 */
uint16_t calculate_udp_checksum(const char *src_ip, const char *dest_ip,
                                 udp_header_t *header, uint8_t *data, int data_len)
{
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
    pseudo.udp_length = header->length;  // Already in network byte order
    
    // Save and clear checksum field
    uint16_t original_checksum = header->checksum;
    header->checksum = 0;
    
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
    
    // Sum UDP header
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
    
    // Return one's complement (0xFFFF if result is 0)
    uint16_t result = (uint16_t)(~sum);
    return (result == 0) ? 0xFFFF : result;
}

/**
 * Build UDP header
 */
void build_udp_header(udp_header_t *header, uint16_t src_port, 
                      uint16_t dest_port, int data_len)
{
    // Clear header
    memset(header, 0, sizeof(udp_header_t));
    
    // Source and destination ports (network byte order)
    header->src_port = htons(src_port);
    header->dest_port = htons(dest_port);
    
    // Length (header + data)
    header->length = htons(UDP_HEADER_SIZE + data_len);
    
    // Checksum will be calculated later
    header->checksum = 0;
}

/**
 * Create a UDP socket
 */
int udp_socket(int af, int type, int protocol)
{
    // Validate parameters
    if (af != AF_INET_CUSTOM && af != AF_INET)
    {
        LOG_ERROR(&g_udp_logger, "socket: Invalid address family: %d", af);
        return INVALID_SOCKET_CUSTOM;
    }
    
    if (type != SOCK_DGRAM_CUSTOM && type != SOCK_DGRAM)
    {
        LOG_ERROR(&g_udp_logger, "socket: Invalid socket type: %d", type);
        return INVALID_SOCKET_CUSTOM;
    }
    
    // Suppress unused parameter warning
    (void)protocol;
    
    // Initialize socket system if needed
    init_socket_system();
    
    // Find free socket slot
    int sockid = -1;
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (!g_sockets[i].valid)
        {
            sockid = i;
            break;
        }
    }
    
    if (sockid < 0)
    {
        LOG_ERROR(&g_udp_logger, "socket: No free socket slots");
        return INVALID_SOCKET_CUSTOM;
    }
    
    // Initialize socket structure
    udp_socket_t *sock = &g_sockets[sockid];
    memset(sock, 0, sizeof(udp_socket_t));
    
    // Initialize five-tuple
    get_default_local_ip(sock->local_address, sizeof(sock->local_address));
    sock->local_port = g_ephemeral_port++;
    if (g_ephemeral_port == 0) g_ephemeral_port = 49152;  // Wrap around
    
    strcpy(sock->target_address, "");
    sock->target_port = -1;
    sock->socket_type = SOCK_DGRAM_CUSTOM;
    sock->valid = 1;
    sock->bound = 0;
    
    LOG_INFO(&g_udp_logger, "========== UDP Socket Created ==========");
    LOG_INFO(&g_udp_logger, "Socket ID:     %d", sockid);
    LOG_INFO(&g_udp_logger, "Local Address: %s", sock->local_address);
    LOG_INFO(&g_udp_logger, "Local Port:    %d (ephemeral)", sock->local_port);
    LOG_INFO(&g_udp_logger, "Socket Type:   SOCK_DGRAM");
    LOG_INFO(&g_udp_logger, "========================================");
    
    return sockid;
}

/**
 * Bind a socket to a local address
 */
int udp_bind(int sockid, sockaddr_in_custom_t *addr, int addrlen)
{
    (void)addrlen;  // Suppress unused parameter warning
    
    udp_socket_t *sock = get_udp_socket(sockid);
    if (sock == NULL)
    {
        LOG_ERROR(&g_udp_logger, "bind: Invalid socket ID: %d", sockid);
        return SOCKET_ERROR_CUSTOM;
    }
    
    if (addr == NULL)
    {
        LOG_ERROR(&g_udp_logger, "bind: NULL address");
        return SOCKET_ERROR_CUSTOM;
    }
    
    // Check if port is already in use
    uint16_t port = ntohs(addr->sin_port);
    for (int i = 0; i < MAX_SOCKETS; i++)
    {
        if (g_sockets[i].valid && g_sockets[i].bound && 
            g_sockets[i].local_port == port && i != sockid)
        {
            LOG_ERROR(&g_udp_logger, "bind: Port %d already in use", port);
            return SOCKET_ERROR_CUSTOM;
        }
    }
    
    // Update socket with bound address
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, INET_ADDRSTRLEN);
    
    strncpy(sock->local_address, ip_str, sizeof(sock->local_address) - 1);
    sock->local_port = port;
    sock->bound = 1;
    
    LOG_INFO(&g_udp_logger, "========== UDP Socket Bound ==========");
    LOG_INFO(&g_udp_logger, "Socket ID:     %d", sockid);
    LOG_INFO(&g_udp_logger, "Bound Address: %s", sock->local_address);
    LOG_INFO(&g_udp_logger, "Bound Port:    %d", sock->local_port);
    LOG_INFO(&g_udp_logger, "======================================");
    
    return 0;
}

/**
 * Send data via UDP
 */
int udp_sendto(int sockid, const uint8_t *buf, int buflen, int flags,
               sockaddr_in_custom_t *dest_addr, int addrlen, uint8_t *dest_mac)
{
    (void)flags;    // Suppress unused parameter warning
    (void)addrlen;  // Suppress unused parameter warning
    
    udp_socket_t *sock = get_udp_socket(sockid);
    if (sock == NULL)
    {
        LOG_ERROR(&g_udp_logger, "sendto: Invalid socket ID: %d", sockid);
        return -1;
    }
    
    if (buf == NULL || buflen <= 0)
    {
        LOG_ERROR(&g_udp_logger, "sendto: Invalid buffer");
        return -1;
    }
    
    if (dest_addr == NULL)
    {
        LOG_ERROR(&g_udp_logger, "sendto: NULL destination address");
        return -1;
    }
    
    if (buflen > UDP_MAX_DATA_SIZE)
    {
        LOG_ERROR(&g_udp_logger, "sendto: Data too large: %d > %d", buflen, UDP_MAX_DATA_SIZE);
        return -1;
    }
    
    // Step 1: Update five-tuple with destination
    char dest_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_addr->sin_addr, dest_ip_str, INET_ADDRSTRLEN);
    uint16_t dest_port = ntohs(dest_addr->sin_port);
    
    strncpy(sock->target_address, dest_ip_str, sizeof(sock->target_address) - 1);
    sock->target_port = dest_port;
    
    LOG_INFO(&g_udp_logger, "========== UDP sendto ==========");
    LOG_INFO(&g_udp_logger, "Socket ID:        %d", sockid);
    LOG_INFO(&g_udp_logger, "Source:           %s:%d", sock->local_address, sock->local_port);
    LOG_INFO(&g_udp_logger, "Destination:      %s:%d", sock->target_address, sock->target_port);
    LOG_INFO(&g_udp_logger, "Data Length:      %d bytes", buflen);
    
    // Step 2: Build UDP header
    uint8_t udp_packet[UDP_MAX_PACKET_SIZE];
    udp_header_t *header = (udp_header_t *)udp_packet;
    
    build_udp_header(header, sock->local_port, dest_port, buflen);
    
    // Step 3: Copy data after header
    memcpy(udp_packet + UDP_HEADER_SIZE, buf, buflen);
    
    // Step 4: Calculate UDP checksum
    header->checksum = calculate_udp_checksum(sock->local_address, sock->target_address,
                                               header, (uint8_t *)buf, buflen);
    
    LOG_DEBUG(&g_udp_logger, "UDP Checksum:     0x%04X", ntohs(header->checksum));
    
    // Display UDP header
    display_udp_header(header, buflen);
    
    // Step 5: Send via IP layer
    int total_len = UDP_HEADER_SIZE + buflen;
    int result = ip_send(udp_packet, total_len, IP_PROTO_UDP,
                         sock->local_address, sock->target_address, dest_mac);
    
    if (result < 0)
    {
        LOG_ERROR(&g_udp_logger, "sendto: IP layer send failed");
        return -1;
    }
    
    LOG_INFO(&g_udp_logger, "sendto: Sent %d bytes successfully", buflen);
    LOG_INFO(&g_udp_logger, "================================");
    
    return buflen;
}

/**
 * Close a UDP socket
 */
int udp_closesocket(int sockid)
{
    udp_socket_t *sock = get_udp_socket(sockid);
    if (sock == NULL)
    {
        LOG_ERROR(&g_udp_logger, "closesocket: Invalid socket ID: %d", sockid);
        return -1;
    }
    
    LOG_INFO(&g_udp_logger, "========== UDP Socket Closed ==========");
    LOG_INFO(&g_udp_logger, "Socket ID:     %d", sockid);
    LOG_INFO(&g_udp_logger, "Local Address: %s:%d", sock->local_address, sock->local_port);
    LOG_INFO(&g_udp_logger, "=======================================");
    
    // Clear socket structure
    memset(sock, 0, sizeof(udp_socket_t));
    sock->valid = 0;
    sock->bound = 0;
    sock->local_port = -1;
    sock->target_port = -1;
    
    return 0;
}
