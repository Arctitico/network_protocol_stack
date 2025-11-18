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
 * @brief Receive and process Ethernet frame from network interface
 * 
 * @param output_file Path to output file for upper layer data
 * @return int 1 on success, 0 if discarded, -1 on error
 */
int ethernet_receive(const char *output_file);

#endif /* ETHERNET_RECV_H */
