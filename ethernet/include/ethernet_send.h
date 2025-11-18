#ifndef ETHERNET_SEND_H
#define ETHERNET_SEND_H

#include <stdint.h>
#include "ethernet.h"

/**
 * @brief Load Ethernet header into frame buffer
 * 
 * @param buffer Frame buffer
 * @param dest_mac Destination MAC address (6 bytes)
 * @param src_mac Source MAC address (6 bytes)
 * @param ethernet_type Protocol type (e.g., 0x0800 for IPv4)
 */
void load_ethernet_header(uint8_t *buffer, uint8_t *dest_mac, uint8_t *src_mac, uint16_t ethernet_type);

/**
 * @brief Load data into Ethernet frame
 * 
 * @param buffer Frame buffer (should point after header)
 * @param data Data to be encapsulated
 * @param data_len Length of data
 * @return int Size of data + CRC, or -1 on error
 */
int load_ethernet_data(uint8_t *buffer, uint8_t *data, int data_len);

/**
 * @brief Send Ethernet frame via network interface
 * 
 * @param buffer Frame buffer containing complete frame
 * @param frame_size Total frame size
 * @return int 1 on success, -1 on error
 */
int send_ethernet_frame(uint8_t *buffer, int frame_size);

/**
 * @brief High-level function to encapsulate and send data
 * 
 * @param data Data to send
 * @param data_len Length of data
 * @param dest_mac Destination MAC address
 * @param src_mac Source MAC address (if NULL, will be auto-filled from selected interface)
 * @param ethernet_type Protocol type
 * @return int 1 on success, -1 on error
 */
int ethernet_send(uint8_t *data, int data_len, 
                  uint8_t *dest_mac, uint8_t *src_mac, uint16_t ethernet_type);

#endif /* ETHERNET_SEND_H */
