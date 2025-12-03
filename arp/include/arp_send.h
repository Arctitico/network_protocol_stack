#ifndef ARP_SEND_H
#define ARP_SEND_H

#include "arp.h"
#include "logger.h"

/* Global logger for ARP module */
extern logger_t g_arp_logger;

/**
 * @brief Initialize ARP logger
 */
void arp_logger_init(void);

/**
 * @brief Close ARP logger
 */
void arp_logger_close(void);

/**
 * @brief Initialize ARP cache
 * 
 * @param cache Pointer to ARP cache structure
 */
void arp_cache_init(arp_cache_t *cache);

/**
 * @brief Add entry to ARP cache
 * 
 * @param cache Pointer to ARP cache
 * @param ip_addr IP address (4 bytes)
 * @param mac_addr MAC address (6 bytes)
 * @param state Entry state (static/dynamic/log)
 * @return int 0 on success, -1 on failure
 */
int arp_cache_add(arp_cache_t *cache, const uint8_t *ip_addr, 
                  const uint8_t *mac_addr, uint8_t state);

/**
 * @brief Lookup MAC address in ARP cache
 * 
 * @param cache Pointer to ARP cache
 * @param ip_addr IP address to lookup (4 bytes)
 * @param mac_addr Buffer to store found MAC address (6 bytes)
 * @return int 1 if found, 0 if not found
 */
int arp_cache_lookup(arp_cache_t *cache, const uint8_t *ip_addr, uint8_t *mac_addr);

/**
 * @brief Remove entry from ARP cache
 * 
 * @param cache Pointer to ARP cache
 * @param ip_addr IP address to remove (4 bytes)
 * @return int 0 on success, -1 if not found
 */
int arp_cache_remove(arp_cache_t *cache, const uint8_t *ip_addr);

/**
 * @brief Clean expired entries from ARP cache
 * 
 * @param cache Pointer to ARP cache
 * @return int Number of entries removed
 */
int arp_cache_cleanup(arp_cache_t *cache);

/**
 * @brief Display ARP cache contents
 * 
 * @param cache Pointer to ARP cache
 */
void arp_cache_display(arp_cache_t *cache);

/**
 * @brief Build ARP request packet
 * 
 * @param buffer Output buffer for ARP packet
 * @param sender_mac Sender MAC address (6 bytes)
 * @param sender_ip Sender IP address (4 bytes)
 * @param target_ip Target IP address to resolve (4 bytes)
 * @return int Size of ARP packet on success, -1 on error
 */
int build_arp_request(uint8_t *buffer, const uint8_t *sender_mac,
                      const uint8_t *sender_ip, const uint8_t *target_ip);

/**
 * @brief Build ARP reply packet
 * 
 * @param buffer Output buffer for ARP packet
 * @param sender_mac Sender MAC address (6 bytes)
 * @param sender_ip Sender IP address (4 bytes)
 * @param target_mac Target MAC address (6 bytes)
 * @param target_ip Target IP address (4 bytes)
 * @return int Size of ARP packet on success, -1 on error
 */
int build_arp_reply(uint8_t *buffer, const uint8_t *sender_mac,
                    const uint8_t *sender_ip, const uint8_t *target_mac,
                    const uint8_t *target_ip);

/**
 * @brief Send ARP request and wait for reply
 * 
 * @param config Network configuration
 * @param cache ARP cache
 * @param target_ip Target IP address to resolve (4 bytes)
 * @param result_mac Buffer to store resolved MAC address (6 bytes)
 * @return int 1 on success, 0 on timeout/failure
 */
int arp_resolve(network_config_t *config, arp_cache_t *cache,
                const uint8_t *target_ip, uint8_t *result_mac);

/**
 * @brief High-level function to resolve IP to MAC address
 * 
 * Determines if target is in same subnet and resolves appropriately
 * (direct resolution or via gateway)
 * 
 * @param config Network configuration
 * @param cache ARP cache
 * @param dest_ip Destination IP address (4 bytes)
 * @param result_mac Buffer to store resolved MAC address (6 bytes)
 * @return int 1 on success, 0 on failure
 */
int arp_get_mac(network_config_t *config, arp_cache_t *cache,
                const uint8_t *dest_ip, uint8_t *result_mac);

/**
 * @brief Send ARP request packet via Ethernet layer
 * 
 * @param sender_mac Sender MAC address
 * @param sender_ip Sender IP address
 * @param target_ip Target IP address
 * @return int 1 on success, -1 on error
 */
int arp_send_request(const uint8_t *sender_mac, const uint8_t *sender_ip,
                     const uint8_t *target_ip);

/**
 * @brief Send ARP reply packet via Ethernet layer
 * 
 * @param sender_mac Sender MAC address
 * @param sender_ip Sender IP address
 * @param target_mac Target MAC address
 * @param target_ip Target IP address
 * @return int 1 on success, -1 on error
 */
int arp_send_reply(const uint8_t *sender_mac, const uint8_t *sender_ip,
                   const uint8_t *target_mac, const uint8_t *target_ip);

#endif /* ARP_SEND_H */
