#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include <netinet/in.h>

/* ARP constants */
#define ARP_HEADER_SIZE         28      // ARP header size (without padding)
#define ARP_HARDWARE_ETHERNET   0x0001  // Hardware type: Ethernet
#define ARP_PROTOCOL_IPV4       0x0800  // Protocol type: IPv4
#define ARP_HARDWARE_ADDR_LEN   6       // Ethernet address length
#define ARP_PROTOCOL_ADDR_LEN   4       // IPv4 address length

/* ARP Operation codes */
#define ARP_OP_REQUEST          1       // ARP Request
#define ARP_OP_REPLY            2       // ARP Reply
#define ARP_OP_RARP_REQUEST     3       // RARP Request
#define ARP_OP_RARP_REPLY       4       // RARP Reply

/* ARP cache constants */
#define ARP_CACHE_SIZE          256     // Maximum ARP cache entries
#define ARP_CACHE_TIMEOUT       300     // Cache entry timeout in seconds (5 minutes)
#define ARP_REQUEST_TIMEOUT     10      // Request timeout in seconds
#define ARP_REQUEST_RETRIES     3       // Maximum retry count

/* ARP cache entry states */
#define ARP_STATE_STATIC        1       // Static entry (manually configured)
#define ARP_STATE_DYNAMIC       2       // Dynamic entry (learned via ARP)
#define ARP_STATE_LOG           3       // Log entry (pending or invalid)

/**
 * @brief ARP header structure (RFC 826)
 * 
 * Format:
 * +---------------------+---------------------+
 * | Hardware Type (2B)  | Protocol Type (2B)  |
 * +---------------------+---------------------+
 * | HLEN (1B) | PLEN (1B) | Operation (2B)    |
 * +---------------------+---------------------+
 * |     Sender Hardware Address (6B)          |
 * +-------------------------------------------+
 * |     Sender Protocol Address (4B)          |
 * +-------------------------------------------+
 * |     Target Hardware Address (6B)          |
 * +-------------------------------------------+
 * |     Target Protocol Address (4B)          |
 * +-------------------------------------------+
 */
typedef struct arp_header {
    uint16_t hardware_type;     // Hardware type (0x0001 for Ethernet)
    uint16_t protocol_type;     // Protocol type (0x0800 for IPv4)
    uint8_t  hardware_len;      // Hardware address length (6 for Ethernet)
    uint8_t  protocol_len;      // Protocol address length (4 for IPv4)
    uint16_t operation;         // Operation code (1=request, 2=reply)
    uint8_t  sender_mac[6];     // Sender MAC address
    uint8_t  sender_ip[4];      // Sender IP address
    uint8_t  target_mac[6];     // Target MAC address
    uint8_t  target_ip[4];      // Target IP address
} __attribute__((packed)) arp_header_t;

/**
 * @brief ARP cache entry structure
 */
typedef struct arp_cache_entry {
    uint8_t  ip_addr[4];        // IP address
    uint8_t  mac_addr[6];       // MAC address
    uint8_t  state;             // Entry state (static, dynamic, log)
    time_t   timestamp;         // Last update time
    int      valid;             // Entry validity flag
} arp_cache_entry_t;

/**
 * @brief ARP cache structure
 */
typedef struct arp_cache {
    arp_cache_entry_t entries[ARP_CACHE_SIZE];
    int count;                  // Current number of entries
} arp_cache_t;

/**
 * @brief Network configuration structure
 */
typedef struct network_config {
    uint8_t local_ip[4];        // Local IP address
    uint8_t subnet_mask[4];     // Subnet mask
    uint8_t gateway_ip[4];      // Default gateway IP
    uint8_t local_mac[6];       // Local MAC address
    int dhcp_flag;              // DHCP enabled flag (1=enabled, 0=disabled)
} network_config_t;

/* Helper function prototypes */

/**
 * @brief Convert IP string to byte array
 */
void ip_str_to_bytes(const char *ip_str, uint8_t *ip_bytes);

/**
 * @brief Convert byte array to IP string
 */
void ip_bytes_to_str(const uint8_t *ip_bytes, char *ip_str);

/**
 * @brief Convert MAC string to byte array
 */
int mac_str_to_bytes(const char *mac_str, uint8_t *mac_bytes);

/**
 * @brief Convert byte array to MAC string
 */
void mac_bytes_to_str(const uint8_t *mac_bytes, char *mac_str);

/**
 * @brief Check if two IPs are in the same subnet
 */
int is_same_subnet(const uint8_t *ip1, const uint8_t *ip2, const uint8_t *mask);

/**
 * @brief Display ARP header information
 */
void display_arp_header(arp_header_t *header);

#endif /* ARP_H */
