#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <netinet/in.h>

/* IP constants */
#define IP_VERSION_4            4
#define IP_HEADER_MIN_SIZE      20      // Minimum IP header size (without options)
#define IP_HEADER_MAX_SIZE      60      // Maximum IP header size (with options)
#define IP_OPTIONS_SIZE         40      // Options size
#define IP_MAX_DATA_SIZE        1400    // Maximum data per IP packet
#define IP_MAX_PACKET_SIZE      65535   // Maximum total packet size

/* IP Protocol Numbers */
#define IP_PROTO_ICMP           1
#define IP_PROTO_IGMP           2
#define IP_PROTO_TCP            6
#define IP_PROTO_UDP            17

/* IP Flags */
#define IP_FLAG_RESERVED        0x8000  // Reserved bit (must be 0)
#define IP_FLAG_DF              0x4000  // Don't Fragment
#define IP_FLAG_MF              0x2000  // More Fragments
#define IP_OFFSET_MASK          0x1FFF  // Fragment offset mask (13 bits)

/* Default values */
#define IP_DEFAULT_TTL          64
#define IP_DEFAULT_TOS          0x00

/**
 * @brief IPv4 header structure (RFC 791)
 * 
 * Format:
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options (if IHL > 5)                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct ip_header {
    uint8_t  version_ihl;        // Version (4 bits) + IHL (4 bits)
    uint8_t  tos;                // Type of Service
    uint16_t total_length;       // Total length (header + data)
    uint16_t identification;     // Identification for fragmentation
    uint16_t flags_offset;       // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t  ttl;                // Time To Live
    uint8_t  protocol;           // Upper layer protocol
    uint16_t checksum;           // Header checksum
    struct in_addr src_ip;       // Source IP address
    struct in_addr dest_ip;      // Destination IP address
    uint8_t  options[IP_OPTIONS_SIZE];  // Options (40 bytes)
} ip_header_t;

/**
 * @brief Complete IP packet structure
 */
typedef struct ip_packet {
    ip_header_t header;
    uint8_t data[IP_MAX_DATA_SIZE];
    int data_len;                // Actual data length
} ip_packet_t;

/**
 * @brief Fragment information for reassembly
 */
typedef struct fragment_info {
    uint16_t identification;     // IP identification
    uint8_t protocol;            // Protocol
    struct in_addr src_ip;       // Source IP
    struct in_addr dest_ip;      // Destination IP
    uint8_t buffer[IP_MAX_PACKET_SIZE];  // Reassembly buffer
    int received_size;           // Current received size
    int total_size;              // Total expected size (-1 if not known)
    time_t first_fragment_time;  // Time of first fragment arrival
    int is_complete;             // Reassembly complete flag
} fragment_info_t;

#endif /* IP_H */
