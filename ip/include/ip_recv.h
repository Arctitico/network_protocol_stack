#ifndef IP_RECV_H
#define IP_RECV_H

#include "ip.h"

/**
 * @brief Verify IP header checksum
 * 
 * @param header Pointer to IP header
 * @param header_len Header length in bytes
 * @return 1 if checksum is valid, 0 otherwise
 */
int verify_ip_checksum(ip_header_t *header, int header_len);

/**
 * @brief Check if IP packet is addressed to this host
 * 
 * @param dest_ip Destination IP address
 * @param local_ip Local IP address string
 * @return 1 if match or broadcast, 0 otherwise
 */
int check_destination_ip(struct in_addr dest_ip, const char *local_ip);

/**
 * @brief Display IP header information
 * 
 * @param header Pointer to IP header
 */
void display_ip_header(ip_header_t *header);

/**
 * @brief Reassemble IP fragments
 * 
 * @param header Pointer to IP header
 * @param packet_data Pointer to packet data (header + data)
 * @param packet_len Total packet length
 * @param reassembled_data Output buffer for reassembled data
 * @param reassembled_len Output length of reassembled data
 * @return 1 if reassembly complete, 0 if waiting for more fragments, -1 on error
 */
int reassemble_fragments(ip_header_t *header, uint8_t *packet_data, int packet_len,
                         uint8_t *reassembled_data, int *reassembled_len);

/**
 * @brief Process received IP packet from Ethernet layer
 * 
 * @param ip_packet IP packet data
 * @param packet_len Total packet length
 * @param local_ip Local IP address string
 * @param output_file File to write received data (to transport layer)
 * @return 1 on success, 0 if packet discarded, -1 on error
 */
int process_ip_packet(uint8_t *ip_packet, int packet_len, 
                      const char *local_ip, const char *output_file);

/**
 * @brief Start IP receiver via Ethernet layer
 * 
 * @param local_ip Local IP address string
 * @param output_file File to write received data (to transport layer)
 * @return 1 on success, -1 on error
 */
int ip_receive(const char *local_ip, const char *output_file);

#endif /* IP_RECV_H */
