#ifndef IP_RECV_H
#define IP_RECV_H

#include "ip.h"

/**
 * @brief Verify IP header checksum
 */
int verify_ip_checksum(ip_header_t *header, int header_len);

/**
 * @brief Check if IP packet is addressed to this host
 */
int check_destination_ip(struct in_addr dest_ip, const char *local_ip);

/**
 * @brief Display IP header information
 */
void display_ip_header(ip_header_t *header);

/**
 * @brief Reassemble IP fragments
 */
int reassemble_fragments(ip_header_t *header, uint8_t *packet_data, int packet_len,
                         uint8_t *reassembled_data, int *reassembled_len);

/**
 * @brief Process received IP packet from Ethernet layer
 */
int process_ip_packet(uint8_t *ip_packet, int packet_len, 
                      const char *local_ip, const char *output_file);

/* Forward declaration for ARP types */
struct network_config;
struct arp_cache;

/**
 * @brief Start integrated network stack receiver
 * 
 * Starts the Ethernet layer in dispatch mode with both IP and ARP
 * protocol handlers registered.
 * 
 * @param local_ip Local IP address string
 * @param output_file File to write received data (to transport layer)
 * @param net_config Network configuration for ARP
 * @param arp_cache ARP cache for storing learned addresses
 * @param packet_count Number of packets to capture (0 for infinite)
 * @return int Number of packets processed, or -1 on error
 */
int network_stack_receive(const char *local_ip, const char *output_file,
                          struct network_config *net_config, 
                          struct arp_cache *arp_cache,
                          int packet_count);

#endif /* IP_RECV_H */
