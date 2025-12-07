#ifndef ETHERNET_RECV_H
#define ETHERNET_RECV_H

#include <stdint.h>
#include "ethernet.h"

/**
 * @brief Check if MAC address matches
 */
int mac_address_match(uint8_t *mac1, uint8_t *mac2);

/**
 * @brief Check if destination MAC is broadcast
 */
int is_broadcast_mac(uint8_t *mac);

/**
 * @brief Verify frame integrity (CRC, MAC, length)
 */
int verify_frame(uint8_t *buffer, int frame_size, uint8_t *my_mac);

/**
 * @brief Parse and display Ethernet frame header
 */
void display_ethernet_header(uint8_t *buffer);

/**
 * @brief Callback function type for upper layer processing
 */
typedef int (*ethernet_recv_callback_t)(uint8_t *data, int data_len, void *user_data);

/**
 * @brief Register a protocol handler for a specific EtherType
 */
int ethernet_register_protocol(uint16_t ether_type, ethernet_recv_callback_t callback, void *user_data);

/**
 * @brief Unregister a protocol handler
 */
int ethernet_unregister_protocol(uint16_t ether_type);

/**
 * @brief Get the source MAC address of the last received frame
 * 
 * This function returns the source MAC address from the most recently
 * received Ethernet frame. Useful for upper layer protocols (like ICMP)
 * that need to send a reply to the source.
 * 
 * @param mac Buffer to store MAC address (6 bytes)
 */
void ethernet_get_last_src_mac(uint8_t *mac);

/**
 * @brief Clear all registered protocol handlers
 */
void ethernet_clear_protocols(void);

/**
 * @brief Start receiving Ethernet frames with protocol dispatching
 */
int ethernet_receive_dispatch(int packet_count);

/**
 * @brief Stop the current pcap capture loop
 * 
 * This function can be called from a signal handler to gracefully
 * stop the packet capture started by ethernet_receive_dispatch().
 */
void ethernet_stop_capture(void);

#endif /* ETHERNET_RECV_H */
