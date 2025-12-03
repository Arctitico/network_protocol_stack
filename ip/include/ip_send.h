#ifndef IP_SEND_H
#define IP_SEND_H

#include "ip.h"
#include "../../common/include/logger.h"

/* Global IP logger */
extern logger_t g_ip_logger;

/**
 * @brief Initialize IP logger
 */
void ip_logger_init(void);

/**
 * @brief Close IP logger
 */
void ip_logger_close(void);

/**
 * @brief Calculate IP header checksum
 * 
 * @param header Pointer to IP header
 * @param header_len Header length in bytes
 * @return Calculated checksum
 */
uint16_t calculate_ip_checksum(ip_header_t *header, int header_len);

/**
 * @brief Build IP header for a packet or fragment
 * 
 * @param header Pointer to IP header structure
 * @param data_len Length of data to be carried
 * @param identification IP identification for fragmentation
 * @param flags_offset Flags and fragment offset (network byte order)
 * @param protocol Upper layer protocol
 * @param src_ip Source IP address string
 * @param dest_ip Destination IP address string
 */
void build_ip_header(ip_header_t *header, int data_len, uint16_t identification,
                     uint16_t flags_offset, uint8_t protocol,
                     const char *src_ip, const char *dest_ip);

/**
 * @brief Send IP packet via Ethernet layer (with fragmentation if needed)
 * 
 * @param data Data to send (from transport layer)
 * @param data_len Length of data
 * @param protocol Upper layer protocol number
 * @param src_ip Source IP address string
 * @param dest_ip Destination IP address string
 * @param dest_mac Destination MAC address
 * @return Number of fragments sent on success, -1 on error
 */
int ip_send(uint8_t *data, int data_len, uint8_t protocol,
            const char *src_ip, const char *dest_ip, uint8_t *dest_mac);

#endif /* IP_SEND_H */
