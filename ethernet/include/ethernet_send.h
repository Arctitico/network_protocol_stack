#ifndef ETHERNET_SEND_H
#define ETHERNET_SEND_H

#include <stdint.h>
#include "ethernet.h"
#include "logger.h"

/* Global logger for ethernet module */
extern logger_t g_ethernet_logger;

/**
 * @brief Initialize ethernet logger
 */
void ethernet_logger_init(void);

/**
 * @brief Close ethernet logger
 */
void ethernet_logger_close(void);

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

/**
 * @brief Set the cached interface for sending
 * 
 * @param ifname Interface name to cache
 * @param src_mac Source MAC address of the interface
 */
void ethernet_send_set_interface(const char *ifname, const uint8_t *src_mac);

/**
 * @brief Get the cached interface name
 * 
 * @return const char* Cached interface name, or NULL if not set
 */
const char* ethernet_send_get_interface(void);

/**
 * @brief Get the cached source MAC address
 * 
 * @param mac Buffer to copy MAC address to (6 bytes)
 * @return int 1 if interface is set, 0 otherwise
 */
int ethernet_send_get_src_mac(uint8_t *mac);

/**
 * @brief Check if interface is already selected
 * 
 * @return int 1 if interface is selected, 0 otherwise
 */
int ethernet_send_is_interface_selected(void);

#endif /* ETHERNET_SEND_H */
