#ifndef ARP_RECV_H
#define ARP_RECV_H

#include "arp.h"
#include "arp_send.h"

/**
 * @brief Callback function type for ARP reply notification
 * 
 * @param sender_ip IP address of the ARP reply sender (4 bytes)
 * @param sender_mac MAC address of the ARP reply sender (6 bytes)
 * @param user_data User-provided context data
 */
typedef void (*arp_reply_callback_t)(const uint8_t *sender_ip, 
                                     const uint8_t *sender_mac, 
                                     void *user_data);

/**
 * @brief Verify ARP packet integrity
 * 
 * @param buffer ARP packet buffer
 * @param len Length of buffer
 * @return int 1 if valid, 0 if invalid
 */
int verify_arp_packet(const uint8_t *buffer, int len);

/**
 * @brief Parse ARP header from buffer
 * 
 * @param buffer Input buffer containing ARP packet
 * @param header Output ARP header structure
 * @return int 0 on success, -1 on error
 */
int parse_arp_header(const uint8_t *buffer, arp_header_t *header);

/**
 * @brief Process received ARP packet
 * 
 * Handles both ARP requests and replies:
 * - For requests: Updates cache and sends reply if target is local IP
 * - For replies: Updates cache with sender's IP-MAC mapping
 * 
 * @param buffer ARP packet data
 * @param len Length of ARP packet
 * @param config Local network configuration
 * @param cache ARP cache to update
 * @return int 1 on success, 0 on error or not for us
 */
int arp_process_packet(const uint8_t *buffer, int len,
                       network_config_t *config, arp_cache_t *cache);

/**
 * @brief Handle ARP request
 * 
 * @param header Parsed ARP header
 * @param config Local network configuration
 * @param cache ARP cache
 * @return int 1 if reply sent, 0 otherwise
 */
int arp_handle_request(arp_header_t *header, network_config_t *config,
                       arp_cache_t *cache);

/**
 * @brief Handle ARP reply
 * 
 * @param header Parsed ARP header
 * @param config Local network configuration
 * @param cache ARP cache
 * @return int 1 if processed, 0 otherwise
 */
int arp_handle_reply(arp_header_t *header, network_config_t *config,
                     arp_cache_t *cache);

/**
 * @brief Start ARP receiver
 * 
 * Listens for ARP packets on selected interface and processes them
 * 
 * @param config Network configuration
 * @param cache ARP cache
 * @return int 0 on success, -1 on error
 */
int arp_receive(network_config_t *config, arp_cache_t *cache);

/**
 * @brief Set callback for ARP reply notification
 * 
 * @param callback Callback function
 * @param user_data User-provided context data
 */
void arp_set_reply_callback(arp_reply_callback_t callback, void *user_data);

/**
 * @brief Ethernet callback for ARP processing
 * 
 * This function is called by the Ethernet layer when an ARP frame is received
 * 
 * @param data ARP packet data (payload from Ethernet frame)
 * @param data_len Length of ARP packet
 * @param user_data User context (contains network_config and arp_cache)
 */
void arp_ethernet_callback(uint8_t *data, int data_len, void *user_data);

#endif /* ARP_RECV_H */
