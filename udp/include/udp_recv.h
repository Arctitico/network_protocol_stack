#ifndef UDP_RECV_H
#define UDP_RECV_H

#include "udp.h"

/**
 * @brief Verify UDP checksum
 * 
 * @param src_ip Source IP address string
 * @param dest_ip Destination IP address string
 * @param header Pointer to UDP header
 * @param data Pointer to UDP data
 * @param data_len Length of UDP data
 * @return 1 if valid, 0 if invalid
 */
int verify_udp_checksum(const char *src_ip, const char *dest_ip,
                        udp_header_t *header, uint8_t *data, int data_len);

/**
 * @brief Process received UDP packet from IP layer
 * 
 * Handles an incoming UDP datagram, verifies checksum, and extracts data.
 * 
 * @param udp_packet Raw UDP packet data (header + data)
 * @param packet_len Total length of UDP packet
 * @param src_ip Source IP address string
 * @param dest_ip Destination IP address string
 * @return Number of bytes processed on success, -1 on error
 */
int process_udp_packet(uint8_t *udp_packet, int packet_len,
                       const char *src_ip, const char *dest_ip);

/**
 * @brief Receive data via UDP
 * 
 * Receives a UDP datagram and extracts the source address.
 * This function is blocking and waits for data.
 * 
 * @param sockid Socket ID
 * @param buf Buffer to store received data
 * @param buflen Maximum length of buffer
 * @param flags Flags (currently unused)
 * @param src_addr Source address (filled by function)
 * @param addrlen Pointer to address length (input/output)
 * @return Number of bytes received on success, -1 on error
 */
int udp_recvfrom(int sockid, uint8_t *buf, int buflen, int flags,
                 sockaddr_in_custom_t *src_addr, int *addrlen);

/**
 * @brief Set received UDP data for a socket
 * 
 * Called by IP layer to deliver data to the appropriate socket.
 * 
 * @param local_port Local port number
 * @param src_ip Source IP address string
 * @param src_port Source port number
 * @param data Received data
 * @param data_len Length of received data
 * @return 0 on success, -1 on error
 */
int udp_deliver_data(uint16_t local_port, const char *src_ip, 
                     uint16_t src_port, uint8_t *data, int data_len);

/**
 * @brief Initialize UDP receive subsystem
 */
void udp_recv_init(void);

/**
 * @brief Send ICMP Port Unreachable message
 * 
 * @param src_ip Source IP of original packet (becomes destination)
 * @param dest_port The unreachable port
 * @param original_packet Original UDP packet data
 * @param original_len Length of original packet
 * @param dest_mac Destination MAC address
 */
void send_icmp_port_unreachable(const char *src_ip, uint16_t dest_port,
                                 uint8_t *original_packet, int original_len,
                                 uint8_t *dest_mac);

/**
 * @brief Print summary of all received file transfers
 * 
 * Call this when server shuts down to show what files were received.
 */
void udp_recv_print_summary(void);

#endif /* UDP_RECV_H */
