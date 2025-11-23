#ifndef ETHERNET_RECV_H
#define ETHERNET_RECV_H

#include <stdint.h>
#include "ethernet.h"

/**
 * @brief Check if MAC address matches
 * 
 * @param mac1 First MAC address
 * @param mac2 Second MAC address
 * @return int 1 if match, 0 otherwise
 */
int mac_address_match(uint8_t *mac1, uint8_t *mac2);

/**
 * @brief Check if destination MAC is broadcast
 * 
 * @param mac MAC address to check
 * @return int 1 if broadcast, 0 otherwise
 */
int is_broadcast_mac(uint8_t *mac);

/**
 * @brief Verify frame integrity (CRC, MAC, length)
 * 
 * @param buffer Frame buffer
 * @param frame_size Total frame size
 * @param my_mac Local MAC address to check against
 * @return int 1 if valid, 0 otherwise
 */
int verify_frame(uint8_t *buffer, int frame_size, uint8_t *my_mac);

/**
 * @brief Parse and display Ethernet frame header
 * 
 * @param buffer Frame buffer
 */
void display_ethernet_header(uint8_t *buffer);

/**
 * @brief Extract data from Ethernet frame and save to file
 * 
 * @param buffer Frame buffer
 * @param frame_size Total frame size
 * @param output_file Path to output file for upper layer
 * @return int Length of extracted data, or -1 on error
 */
int extract_frame_data(uint8_t *buffer, int frame_size, const char *output_file);

/**
 * @brief Callback function type for upper layer processing
 * 
 * @param data Pointer to extracted data (upper layer payload)
 * @param data_len Length of extracted data
 * @param user_data User-defined data passed to callback
 * @return int Return value from callback (implementation-defined)
 */
typedef int (*ethernet_recv_callback_t)(uint8_t *data, int data_len, void *user_data);

/**
 * @brief Receive and process Ethernet frame from network interface
 * 
 * @param output_file Path to output file for upper layer data (NULL if using callback)
 * @return int 1 on success, 0 if discarded, -1 on error
 */
int ethernet_receive(const char *output_file);

/**
 * @brief Receive and process Ethernet frames with callback
 * 
 * @param callback Function to call when frame is received
 * @param user_data User data to pass to callback
 * @param packet_count Number of packets to capture (0 for infinite)
 * @return int Number of packets processed, or -1 on error
 */
int ethernet_receive_callback(ethernet_recv_callback_t callback, void *user_data, int packet_count);

#endif /* ETHERNET_RECV_H */
