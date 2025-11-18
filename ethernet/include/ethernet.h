#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdint.h>

/* Ethernet frame constants */
#define ETHERNET_HEADER_SIZE    14      // 6 + 6 + 2 bytes
#define ETHERNET_CRC_SIZE       4       // 4 bytes
#define ETHERNET_MIN_DATA_SIZE  46      // Minimum data size
#define ETHERNET_MAX_DATA_SIZE  1500    // Maximum data size (MTU)
#define ETHERNET_MIN_FRAME_SIZE 64      // Minimum frame size (including CRC)
#define ETHERNET_MAX_FRAME_SIZE 1518    // Maximum frame size (including CRC)
#define MAX_FRAME_BUFFER_SIZE   2048    // Buffer size for frame operations

/* Ethernet Type field values */
#define ETHERNET_TYPE_IPV4      0x0800
#define ETHERNET_TYPE_ARP       0x0806
#define ETHERNET_TYPE_RARP      0x8035
#define ETHERNET_TYPE_IPV6      0x86DD
#define ETHERNET_TYPE_ICMP      0x0001
#define ETHERNET_TYPE_IGMP      0x0002

/**
 * @brief Ethernet frame header structure
 * 
 * Format:
 * +-------------------+-------------------+-------------+
 * | Dest MAC (6 bytes)| Src MAC (6 bytes) | Type (2 bytes)|
 * +-------------------+-------------------+-------------+
 */
typedef struct ethernet_header {
    uint8_t  dest_mac[6];    // Destination MAC address
    uint8_t  src_mac[6];     // Source MAC address
    uint16_t ethernet_type;  // Protocol type (network byte order)
} __attribute__((packed)) ethernet_header_t;

/**
 * @brief Complete Ethernet frame structure
 */
typedef struct ethernet_frame {
    ethernet_header_t header;
    uint8_t data[ETHERNET_MAX_DATA_SIZE];
    uint32_t crc;            // CRC32 checksum
    int data_len;            // Actual data length
} ethernet_frame_t;

#endif /* ETHERNET_H */
