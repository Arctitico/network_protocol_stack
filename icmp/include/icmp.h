#ifndef ICMP_H
#define ICMP_H

#include <stdint.h>

/* ICMP constants */
#define ICMP_HEADER_SIZE        8       // ICMP header size (type + code + checksum + id + seq)
#define ICMP_MAX_DATA_SIZE      1472    // Maximum ICMP data size (MTU 1500 - IP 20 - ICMP 8)

/* ICMP message types */
#define ICMP_TYPE_ECHO_REPLY        0   // Echo Reply
#define ICMP_TYPE_DEST_UNREACHABLE  3   // Destination Unreachable
#define ICMP_TYPE_SOURCE_QUENCH     4   // Source Quench
#define ICMP_TYPE_REDIRECT          5   // Redirect
#define ICMP_TYPE_ECHO_REQUEST      8   // Echo Request (ping)
#define ICMP_TYPE_TIME_EXCEEDED     11  // Time Exceeded
#define ICMP_TYPE_PARAM_PROBLEM     12  // Parameter Problem
#define ICMP_TYPE_TIMESTAMP         13  // Timestamp Request
#define ICMP_TYPE_TIMESTAMP_REPLY   14  // Timestamp Reply
#define ICMP_TYPE_INFO_REQUEST      15  // Information Request
#define ICMP_TYPE_INFO_REPLY        16  // Information Reply

/* ICMP code values for Destination Unreachable */
#define ICMP_CODE_NET_UNREACHABLE   0   // Network Unreachable
#define ICMP_CODE_HOST_UNREACHABLE  1   // Host Unreachable
#define ICMP_CODE_PROTO_UNREACHABLE 2   // Protocol Unreachable
#define ICMP_CODE_PORT_UNREACHABLE  3   // Port Unreachable
#define ICMP_CODE_FRAG_NEEDED       4   // Fragmentation Needed
#define ICMP_CODE_SRC_ROUTE_FAILED  5   // Source Route Failed

/* ICMP code values for Time Exceeded */
#define ICMP_CODE_TTL_EXCEEDED      0   // TTL Exceeded in Transit
#define ICMP_CODE_FRAG_REASSEMBLY   1   // Fragment Reassembly Time Exceeded

/**
 * @brief ICMP header structure (RFC 792)
 * 
 * Format:
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Type      |     Code      |          Checksum             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identifier            |        Sequence Number        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Data                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct icmp_header {
    uint8_t  type;              // ICMP message type
    uint8_t  code;              // ICMP message code
    uint16_t checksum;          // ICMP checksum
    uint16_t identifier;        // Identifier (used in Echo Request/Reply)
    uint16_t sequence;          // Sequence number (used in Echo Request/Reply)
} __attribute__((packed)) icmp_header_t;

/**
 * @brief Complete ICMP packet structure
 */
typedef struct icmp_packet {
    icmp_header_t header;
    uint8_t data[ICMP_MAX_DATA_SIZE];
    int data_len;               // Actual data length
} icmp_packet_t;

/**
 * @brief Get ICMP type name string
 * 
 * @param type ICMP type value
 * @return const char* Human-readable type name
 */
const char* icmp_type_to_string(uint8_t type);

/**
 * @brief Display ICMP header information
 * 
 * @param header Pointer to ICMP header
 * @param data_len Length of ICMP data
 */
void display_icmp_header(icmp_header_t *header, int data_len);

/**
 * @brief Calculate ICMP checksum
 * 
 * @param header Pointer to ICMP header
 * @param data Pointer to ICMP data (can be NULL if data_len is 0)
 * @param data_len Length of ICMP data
 * @return Calculated checksum
 */
uint16_t calculate_icmp_checksum(icmp_header_t *header, uint8_t *data, int data_len);

/**
 * @brief Verify ICMP checksum
 * 
 * @param header Pointer to ICMP header
 * @param data Pointer to ICMP data
 * @param data_len Length of ICMP data
 * @return int 1 if valid, 0 if invalid
 */
int verify_icmp_checksum(icmp_header_t *header, uint8_t *data, int data_len);

#endif /* ICMP_H */
