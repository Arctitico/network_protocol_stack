#ifndef UDP_H
#define UDP_H

#include <stdint.h>
#include <netinet/in.h>

/* UDP constants */
#define UDP_HEADER_SIZE         8       // UDP header size
#define UDP_MAX_DATA_SIZE       65507   // Maximum UDP data size (65535 - 8 - 20)
#define UDP_MAX_PACKET_SIZE     65535   // Maximum UDP packet size

/* Socket constants */
#define AF_INET_CUSTOM          2       // Address family: Internet
#define SOCK_DGRAM_CUSTOM       2       // Socket type: Datagram (UDP)
#define IPPROTO_IP_CUSTOM       0       // IP protocol

#define INVALID_SOCKET_CUSTOM   (-1)
#define SOCKET_ERROR_CUSTOM     (-1)

/* Maximum number of sockets */
#define MAX_SOCKETS             64

/**
 * @brief UDP header structure (RFC 768)
 * 
 * Format:
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port          |       Destination Port        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Length             |           Checksum            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct udp_header {
    uint16_t src_port;          // Source port
    uint16_t dest_port;         // Destination port
    uint16_t length;            // UDP length (header + data)
    uint16_t checksum;          // Checksum
} __attribute__((packed)) udp_header_t;

/**
 * @brief UDP pseudo header for checksum calculation (RFC 768)
 */
typedef struct udp_pseudo_header {
    uint32_t src_ip;            // Source IP address
    uint32_t dest_ip;           // Destination IP address
    uint8_t  zero;              // Reserved (must be zero)
    uint8_t  protocol;          // Protocol (17 for UDP)
    uint16_t udp_length;        // UDP length
} __attribute__((packed)) udp_pseudo_header_t;

/**
 * @brief Complete UDP packet structure
 */
typedef struct udp_packet {
    udp_header_t header;
    uint8_t data[UDP_MAX_DATA_SIZE];
    int data_len;               // Actual data length
} udp_packet_t;

/**
 * @brief Socket address structure (compatible with sockaddr_in)
 */
typedef struct sockaddr_in_custom {
    uint16_t sin_family;        // Address family (AF_INET)
    uint16_t sin_port;          // Port number (network byte order)
    struct in_addr sin_addr;    // IP address
    char sin_zero[8];           // Padding
} sockaddr_in_custom_t;

/**
 * @brief UDP Five-tuple socket structure
 * Represents a UDP communication endpoint
 */
typedef struct udp_socket {
    char     local_address[16];     // Local IP address string
    int      local_port;            // Local port number
    char     target_address[16];    // Target IP address string
    int      target_port;           // Target port number
    int      socket_type;           // Socket type (SOCK_DGRAM)
    int      valid;                 // Socket validity flag
    int      bound;                 // Socket is bound flag
} udp_socket_t;

/* Helper function prototypes */

/**
 * @brief Display UDP header information
 * 
 * @param header Pointer to UDP header
 * @param data_len Length of UDP data
 */
void display_udp_header(udp_header_t *header, int data_len);

/**
 * @brief Get UDP socket by socket ID
 * 
 * @param sockid Socket ID
 * @return Pointer to UDP socket, or NULL if invalid
 */
udp_socket_t* get_udp_socket(int sockid);

#endif /* UDP_H */
