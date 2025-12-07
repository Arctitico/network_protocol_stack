#ifndef UDP_SEND_H
#define UDP_SEND_H

#include "udp.h"
#include "../../common/include/logger.h"

/* Global UDP logger */
extern logger_t g_udp_logger;

/**
 * @brief Initialize UDP logger
 */
void udp_logger_init(void);

/**
 * @brief Close UDP logger
 */
void udp_logger_close(void);

/**
 * @brief Calculate UDP checksum (includes pseudo header)
 * 
 * @param src_ip Source IP address string
 * @param dest_ip Destination IP address string
 * @param header Pointer to UDP header
 * @param data Pointer to UDP data
 * @param data_len Length of UDP data
 * @return Calculated checksum
 */
uint16_t calculate_udp_checksum(const char *src_ip, const char *dest_ip,
                                 udp_header_t *header, uint8_t *data, int data_len);

/**
 * @brief Build UDP header
 * 
 * @param header Pointer to UDP header structure
 * @param src_port Source port
 * @param dest_port Destination port
 * @param data_len Length of data
 */
void build_udp_header(udp_header_t *header, uint16_t src_port, 
                      uint16_t dest_port, int data_len);

/**
 * @brief Create a UDP socket
 * 
 * Creates and initializes a UDP socket (five-tuple structure).
 * 
 * @param af Address family (AF_INET_CUSTOM)
 * @param type Socket type (SOCK_DGRAM_CUSTOM)
 * @param protocol Protocol (IPPROTO_IP_CUSTOM)
 * @return Socket ID on success, INVALID_SOCKET_CUSTOM on error
 */
int udp_socket(int af, int type, int protocol);

/**
 * @brief Bind a socket to a local address
 * 
 * Associates the socket with a specific IP address and port.
 * 
 * @param sockid Socket ID
 * @param addr Pointer to sockaddr_in_custom structure
 * @param addrlen Length of address structure
 * @return 0 on success, SOCKET_ERROR_CUSTOM on error
 */
int udp_bind(int sockid, sockaddr_in_custom_t *addr, int addrlen);

/**
 * @brief Send data via UDP
 * 
 * Constructs and sends a UDP datagram to the specified destination.
 * 
 * @param sockid Socket ID
 * @param buf Data buffer to send
 * @param buflen Length of data
 * @param flags Flags (currently unused)
 * @param dest_addr Destination address
 * @param addrlen Length of destination address structure
 * @param dest_mac Destination MAC address (required for sending)
 * @return Number of bytes sent on success, -1 on error
 */
int udp_sendto(int sockid, const uint8_t *buf, int buflen, int flags,
               sockaddr_in_custom_t *dest_addr, int addrlen, uint8_t *dest_mac);

/**
 * @brief Close a UDP socket
 * 
 * Releases resources associated with the socket.
 * 
 * @param sockid Socket ID
 * @return 0 on success, -1 on error
 */
int udp_closesocket(int sockid);

#endif /* UDP_SEND_H */
