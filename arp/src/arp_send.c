#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <unistd.h>
#include "../include/arp.h"
#include "../include/arp_send.h"
#include "../../ethernet/include/ethernet_send.h"
#include "../../ethernet/include/ethernet.h"
#include "../../common/include/logger.h"

/* Global logger instance for ARP module */
logger_t g_arp_logger;
static int g_arp_logger_initialized = 0;

/**
 * Initialize ARP logger
 */
void arp_logger_init(void)
{
    if (g_arp_logger_initialized) return;
    
    // Check LOG_QUIET environment variable (1 = no console output)
    int console_enabled = (getenv("LOG_QUIET") == NULL) ? 1 : 0;
    
    int ret = logger_init(&g_arp_logger, "ARP", "output/arp.log", 
                          LOG_LEVEL_DEBUG, console_enabled);
    if (ret == 0)
    {
        g_arp_logger_initialized = 1;
        LOG_INFO(&g_arp_logger, "ARP logger initialized");
    }
}

/**
 * Close ARP logger
 */
void arp_logger_close(void)
{
    if (g_arp_logger_initialized)
    {
        LOG_INFO(&g_arp_logger, "ARP logger closing");
        logger_close(&g_arp_logger);
        g_arp_logger_initialized = 0;
    }
}

/* Global variables for ARP resolution */
static int g_reply_received = 0;
static uint8_t g_resolved_mac[6];
static uint8_t g_expected_ip[4];

/* Cached interface information */
static char g_selected_interface[IFNAMSIZ] = {0};
static int g_interface_selected = 0;

/**
 * Get MAC address of a network interface
 */
static int get_interface_mac(const char *ifname, uint8_t *mac)
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sock < 0)
    {
        LOG_ERROR(&g_arp_logger, "Failed to create socket for MAC lookup");
        return -1;
    }
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        LOG_ERROR(&g_arp_logger, "ioctl SIOCGIFHWADDR failed for %s", ifname);
        close(sock);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    
    return 0;
}

/**
 * Get IP address of a network interface
 */
static int get_interface_ip(const char *ifname, uint8_t *ip)
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sock < 0)
    {
        LOG_ERROR(&g_arp_logger, "Failed to create socket for IP lookup");
        return -1;
    }
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        LOG_ERROR(&g_arp_logger, "ioctl SIOCGIFADDR failed for %s", ifname);
        close(sock);
        return -1;
    }
    
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(ip, &addr->sin_addr.s_addr, 4);
    close(sock);
    
    return 0;
}

/**
 * Initialize ARP cache
 */
void arp_cache_init(arp_cache_t *cache)
{
    memset(cache, 0, sizeof(arp_cache_t));
    cache->count = 0;
    LOG_INFO(&g_arp_logger, "ARP cache initialized");
}

/**
 * Add entry to ARP cache
 */
int arp_cache_add(arp_cache_t *cache, const uint8_t *ip_addr, 
                  const uint8_t *mac_addr, uint8_t state)
{
    // Check if entry already exists
    for (int i = 0; i < cache->count; i++)
    {
        if (cache->entries[i].valid &&
            memcmp(cache->entries[i].ip_addr, ip_addr, 4) == 0)
        {
            // Update existing entry
            memcpy(cache->entries[i].mac_addr, mac_addr, 6);
            cache->entries[i].state = state;
            cache->entries[i].timestamp = time(NULL);
            
            char ip_str[16], mac_str[18];
            ip_bytes_to_str(ip_addr, ip_str);
            mac_bytes_to_str(mac_addr, mac_str);
            LOG_INFO(&g_arp_logger, "ARP cache updated: %s -> %s (state=%d)", ip_str, mac_str, state);
            return 0;
        }
    }
    
    // Find empty slot or oldest entry
    int slot = -1;
    time_t oldest_time = time(NULL);
    int oldest_slot = 0;
    
    for (int i = 0; i < ARP_CACHE_SIZE; i++)
    {
        if (!cache->entries[i].valid)
        {
            slot = i;
            break;
        }
        if (cache->entries[i].timestamp < oldest_time)
        {
            oldest_time = cache->entries[i].timestamp;
            oldest_slot = i;
        }
    }
    
    // If no empty slot, use oldest entry
    if (slot < 0)
    {
        slot = oldest_slot;
    }
    
    // Add new entry
    memcpy(cache->entries[slot].ip_addr, ip_addr, 4);
    memcpy(cache->entries[slot].mac_addr, mac_addr, 6);
    cache->entries[slot].state = state;
    cache->entries[slot].timestamp = time(NULL);
    cache->entries[slot].valid = 1;
    
    if (slot >= cache->count)
    {
        cache->count = slot + 1;
    }
    
    char ip_str[16], mac_str[18];
    ip_bytes_to_str(ip_addr, ip_str);
    mac_bytes_to_str(mac_addr, mac_str);
    LOG_INFO(&g_arp_logger, "ARP cache added: %s -> %s (state=%d)", ip_str, mac_str, state);
    
    return 0;
}

/**
 * Lookup MAC address in ARP cache
 */
int arp_cache_lookup(arp_cache_t *cache, const uint8_t *ip_addr, uint8_t *mac_addr)
{
    time_t current_time = time(NULL);
    
    for (int i = 0; i < cache->count; i++)
    {
        if (cache->entries[i].valid &&
            memcmp(cache->entries[i].ip_addr, ip_addr, 4) == 0)
        {
            // Check if entry is expired (only for dynamic entries)
            if (cache->entries[i].state == ARP_STATE_DYNAMIC &&
                current_time - cache->entries[i].timestamp > ARP_CACHE_TIMEOUT)
            {
                cache->entries[i].valid = 0;
                return 0;  // Entry expired
            }
            
            // Check if entry is valid (not log state)
            if (cache->entries[i].state == ARP_STATE_STATIC ||
                cache->entries[i].state == ARP_STATE_DYNAMIC)
            {
                memcpy(mac_addr, cache->entries[i].mac_addr, 6);
                return 1;  // Found
            }
        }
    }
    
    return 0;  // Not found
}

/**
 * Remove entry from ARP cache
 */
int arp_cache_remove(arp_cache_t *cache, const uint8_t *ip_addr)
{
    for (int i = 0; i < cache->count; i++)
    {
        if (cache->entries[i].valid &&
            memcmp(cache->entries[i].ip_addr, ip_addr, 4) == 0)
        {
            cache->entries[i].valid = 0;
            return 0;
        }
    }
    return -1;  // Not found
}

/**
 * Clean expired entries from ARP cache
 */
int arp_cache_cleanup(arp_cache_t *cache)
{
    time_t current_time = time(NULL);
    int removed = 0;
    
    for (int i = 0; i < cache->count; i++)
    {
        if (cache->entries[i].valid &&
            cache->entries[i].state == ARP_STATE_DYNAMIC &&
            current_time - cache->entries[i].timestamp > ARP_CACHE_TIMEOUT)
        {
            cache->entries[i].valid = 0;
            removed++;
        }
    }
    
    return removed;
}

/**
 * Display ARP cache contents
 */
void arp_cache_display(arp_cache_t *cache)
{
    LOG_INFO(&g_arp_logger, "========== ARP Cache ==========");
    LOG_INFO(&g_arp_logger, "%-16s  %-18s  %-8s  %-10s", "IP Address", "MAC Address", "State", "Age(s)");
    LOG_INFO(&g_arp_logger, "--------------------------------------------------------------");
    
    time_t current_time = time(NULL);
    int valid_count = 0;
    
    for (int i = 0; i < cache->count; i++)
    {
        if (cache->entries[i].valid)
        {
            char ip_str[16], mac_str[18];
            ip_bytes_to_str(cache->entries[i].ip_addr, ip_str);
            mac_bytes_to_str(cache->entries[i].mac_addr, mac_str);
            
            const char *state_str;
            switch (cache->entries[i].state)
            {
                case ARP_STATE_STATIC:
                    state_str = "static";
                    break;
                case ARP_STATE_DYNAMIC:
                    state_str = "dynamic";
                    break;
                case ARP_STATE_LOG:
                    state_str = "log";
                    break;
                default:
                    state_str = "unknown";
                    break;
            }
            
            long age = (long)(current_time - cache->entries[i].timestamp);
            LOG_INFO(&g_arp_logger, "%-16s  %-18s  %-8s  %ld", ip_str, mac_str, state_str, age);
            valid_count++;
        }
    }
    
    if (valid_count == 0)
    {
        LOG_INFO(&g_arp_logger, "(empty)");
    }
    
    LOG_INFO(&g_arp_logger, "===============================");
    LOG_INFO(&g_arp_logger, "Total entries: %d", valid_count);
}

/**
 * Build ARP request packet
 */
int build_arp_request(uint8_t *buffer, const uint8_t *sender_mac,
                      const uint8_t *sender_ip, const uint8_t *target_ip)
{
    arp_header_t *arp = (arp_header_t *)buffer;
    
    // Fill ARP header
    arp->hardware_type = htons(ARP_HARDWARE_ETHERNET);
    arp->protocol_type = htons(ARP_PROTOCOL_IPV4);
    arp->hardware_len = ARP_HARDWARE_ADDR_LEN;
    arp->protocol_len = ARP_PROTOCOL_ADDR_LEN;
    arp->operation = htons(ARP_OP_REQUEST);
    
    // Sender addresses
    memcpy(arp->sender_mac, sender_mac, 6);
    memcpy(arp->sender_ip, sender_ip, 4);
    
    // Target addresses (MAC is all zeros for request)
    memset(arp->target_mac, 0, 6);
    memcpy(arp->target_ip, target_ip, 4);
    
    return sizeof(arp_header_t);
}

/**
 * Build ARP reply packet
 */
int build_arp_reply(uint8_t *buffer, const uint8_t *sender_mac,
                    const uint8_t *sender_ip, const uint8_t *target_mac,
                    const uint8_t *target_ip)
{
    arp_header_t *arp = (arp_header_t *)buffer;
    
    // Fill ARP header
    arp->hardware_type = htons(ARP_HARDWARE_ETHERNET);
    arp->protocol_type = htons(ARP_PROTOCOL_IPV4);
    arp->hardware_len = ARP_HARDWARE_ADDR_LEN;
    arp->protocol_len = ARP_PROTOCOL_ADDR_LEN;
    arp->operation = htons(ARP_OP_REPLY);
    
    // Sender addresses (our addresses)
    memcpy(arp->sender_mac, sender_mac, 6);
    memcpy(arp->sender_ip, sender_ip, 4);
    
    // Target addresses (requester's addresses)
    memcpy(arp->target_mac, target_mac, 6);
    memcpy(arp->target_ip, target_ip, 4);
    
    return sizeof(arp_header_t);
}

/**
 * Build complete ARP Ethernet frame (header + ARP packet + padding)
 */
static int build_arp_frame(uint8_t *frame_buffer, const uint8_t *sender_mac,
                           const uint8_t *sender_ip, const uint8_t *target_mac,
                           const uint8_t *target_ip, uint16_t operation)
{
    // Ethernet header (14 bytes)
    // Destination MAC
    if (operation == ARP_OP_REQUEST)
    {
        // Broadcast for request
        memset(frame_buffer, 0xFF, 6);
    }
    else
    {
        // Unicast for reply
        memcpy(frame_buffer, target_mac, 6);
    }
    // Source MAC
    memcpy(frame_buffer + 6, sender_mac, 6);
    // EtherType (0x0806 for ARP)
    frame_buffer[12] = 0x08;
    frame_buffer[13] = 0x06;
    
    // ARP packet (28 bytes)
    arp_header_t *arp = (arp_header_t *)(frame_buffer + 14);
    arp->hardware_type = htons(ARP_HARDWARE_ETHERNET);
    arp->protocol_type = htons(ARP_PROTOCOL_IPV4);
    arp->hardware_len = ARP_HARDWARE_ADDR_LEN;
    arp->protocol_len = ARP_PROTOCOL_ADDR_LEN;
    arp->operation = htons(operation);
    memcpy(arp->sender_mac, sender_mac, 6);
    memcpy(arp->sender_ip, sender_ip, 4);
    if (operation == ARP_OP_REQUEST)
    {
        memset(arp->target_mac, 0, 6);
    }
    else
    {
        memcpy(arp->target_mac, target_mac, 6);
    }
    memcpy(arp->target_ip, target_ip, 4);
    
    // Pad to minimum Ethernet frame size (64 bytes including CRC, but we skip CRC)
    // 14 (eth header) + 28 (arp) = 42, need to pad to 60 (64 - 4 CRC)
    int frame_len = 14 + 28;
    if (frame_len < 60)
    {
        memset(frame_buffer + frame_len, 0, 60 - frame_len);
        frame_len = 60;
    }
    
    return frame_len;
}

/**
 * Send ARP request packet via Ethernet layer
 */
int arp_send_request(const uint8_t *sender_mac, const uint8_t *sender_ip,
                     const uint8_t *target_ip)
{
    uint8_t arp_buffer[64];  // ARP packet buffer
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    
    // Build ARP request
    int arp_len = build_arp_request(arp_buffer, sender_mac, sender_ip, target_ip);
    
    // Pad to minimum Ethernet data size (46 bytes)
    if (arp_len < 46)
    {
        memset(arp_buffer + arp_len, 0, 46 - arp_len);
        arp_len = 46;
    }
    
    char target_ip_str[16];
    ip_bytes_to_str(target_ip, target_ip_str);
    LOG_INFO(&g_arp_logger, "Sending ARP request for %s (broadcast)", target_ip_str);
    
    // Send via Ethernet layer
    return ethernet_send(arp_buffer, arp_len, broadcast_mac, 
                         (uint8_t *)sender_mac, ETHERNET_TYPE_ARP);
}

/**
 * Send ARP reply packet via Ethernet layer
 */
int arp_send_reply(const uint8_t *sender_mac, const uint8_t *sender_ip,
                   const uint8_t *target_mac, const uint8_t *target_ip)
{
    uint8_t arp_buffer[64];  // ARP packet buffer
    
    // Build ARP reply
    int arp_len = build_arp_reply(arp_buffer, sender_mac, sender_ip,
                                   target_mac, target_ip);
    
    // Pad to minimum Ethernet data size (46 bytes)
    if (arp_len < 46)
    {
        memset(arp_buffer + arp_len, 0, 46 - arp_len);
        arp_len = 46;
    }
    
    char target_ip_str[16], target_mac_str[18];
    ip_bytes_to_str(target_ip, target_ip_str);
    mac_bytes_to_str(target_mac, target_mac_str);
    LOG_INFO(&g_arp_logger, "Sending ARP reply to %s (%s)", target_ip_str, target_mac_str);
    
    // Send via Ethernet layer (unicast to requester)
    return ethernet_send(arp_buffer, arp_len, (uint8_t *)target_mac,
                         (uint8_t *)sender_mac, ETHERNET_TYPE_ARP);
}

/* Callback for processing ARP replies during resolution */
static void arp_reply_callback_internal(unsigned char *user_data,
                                        const struct pcap_pkthdr *pkthdr,
                                        const unsigned char *packet)
{
    (void)user_data;
    (void)pkthdr;
    
    // Skip Ethernet header (14 bytes)
    const arp_header_t *arp = (const arp_header_t *)(packet + 14);
    
    // Check if it's an ARP reply
    if (ntohs(arp->operation) == ARP_OP_REPLY)
    {
        // Check if it's the reply we're waiting for
        if (memcmp(arp->sender_ip, g_expected_ip, 4) == 0)
        {
            memcpy(g_resolved_mac, arp->sender_mac, 6);
            g_reply_received = 1;
            
            char ip_str[16], mac_str[18];
            ip_bytes_to_str(arp->sender_ip, ip_str);
            mac_bytes_to_str(arp->sender_mac, mac_str);
            LOG_INFO(&g_arp_logger, "Received ARP reply: %s -> %s", ip_str, mac_str);
        }
    }
}

/**
 * Send ARP request and wait for reply
 */
int arp_resolve(network_config_t *config, arp_cache_t *cache,
                const uint8_t *target_ip, uint8_t *result_mac)
{
    pcap_if_t *alldevs = NULL;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum, i = 0;
    const char *interface_to_use = NULL;
    
    // First check cache
    if (arp_cache_lookup(cache, target_ip, result_mac))
    {
        char ip_str[16], mac_str[18];
        ip_bytes_to_str(target_ip, ip_str);
        mac_bytes_to_str(result_mac, mac_str);
        LOG_INFO(&g_arp_logger, "ARP cache hit: %s -> %s", ip_str, mac_str);
        return 1;
    }
    
    // Reset global state
    g_reply_received = 0;
    memcpy(g_expected_ip, target_ip, 4);
    
    // Check if interface is already pre-selected via ethernet_send
    if (ethernet_send_is_interface_selected())
    {
        interface_to_use = ethernet_send_get_interface();
        ethernet_send_get_src_mac(config->local_mac);
        
        char mac_str[18];
        mac_bytes_to_str(config->local_mac, mac_str);
        LOG_DEBUG(&g_arp_logger, "Using pre-selected interface: %s (MAC: %s)", interface_to_use, mac_str);
    }
    else
    {
        // Select network interface
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            LOG_ERROR(&g_arp_logger, "Error in pcap_findalldevs: %s", errbuf);
            return 0;
        }
        
        printf("\n=== Available Network Interfaces ===\n");
        for (device = alldevs; device != NULL; device = device->next)
        {
            printf("%d. %s", ++i, device->name);
            if (device->description)
                printf(" (%s)\n", device->description);
            else
                printf(" (No description available)\n");
        }
        
        if (i == 0)
        {
            LOG_ERROR(&g_arp_logger, "No interfaces found!");
            return 0;
        }
        
        printf("\nEnter the interface number (1-%d): ", i);
        if (scanf("%d", &inum) != 1)
        {
            LOG_ERROR(&g_arp_logger, "Invalid input");
            pcap_freealldevs(alldevs);
            return 0;
        }
        
        if (inum < 1 || inum > i)
        {
            LOG_ERROR(&g_arp_logger, "Interface number out of range");
            pcap_freealldevs(alldevs);
            return 0;
        }
        
        // Jump to the selected adapter
        for (device = alldevs, i = 0; i < inum - 1; device = device->next, i++);
        
        strncpy(g_selected_interface, device->name, IFNAMSIZ - 1);
        g_selected_interface[IFNAMSIZ - 1] = '\0';
        g_interface_selected = 1;
        interface_to_use = g_selected_interface;
        
        // Get local MAC and IP from interface
        if (get_interface_mac(device->name, config->local_mac) < 0)
        {
            LOG_ERROR(&g_arp_logger, "Failed to get MAC address");
            pcap_freealldevs(alldevs);
            return 0;
        }
        
        if (get_interface_ip(device->name, config->local_ip) < 0)
        {
            LOG_WARN(&g_arp_logger, "Failed to get IP address from interface");
        }
        
        // Notify ethernet_send module about the selected interface
        ethernet_send_set_interface(device->name, config->local_mac);
        
        char mac_str[18], ip_str[16];
        mac_bytes_to_str(config->local_mac, mac_str);
        ip_bytes_to_str(config->local_ip, ip_str);
        LOG_INFO(&g_arp_logger, "Selected interface: %s", device->name);
        LOG_INFO(&g_arp_logger, "Local MAC: %s", mac_str);
        LOG_INFO(&g_arp_logger, "Local IP: %s", ip_str);
        
        pcap_freealldevs(alldevs);
    }
    
    // Open the device for capture
    handle = pcap_open_live(interface_to_use, 65536, 1, 100, errbuf);
    if (handle == NULL)
    {
        LOG_ERROR(&g_arp_logger, "Unable to open adapter: %s", errbuf);
        return 0;
    }
    
    // Set filter for ARP packets
    struct bpf_program fcode;
    if (pcap_compile(handle, &fcode, "arp", 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        LOG_ERROR(&g_arp_logger, "Unable to compile filter");
        pcap_close(handle);
        return 0;
    }
    
    if (pcap_setfilter(handle, &fcode) < 0)
    {
        LOG_ERROR(&g_arp_logger, "Unable to set filter");
        pcap_freecode(&fcode);
        pcap_close(handle);
        return 0;
    }
    
    // Try ARP resolution with retries
    for (int retry = 0; retry < ARP_REQUEST_RETRIES; retry++)
    {
        if (retry > 0)
        {
            LOG_INFO(&g_arp_logger, "Retry %d/%d...", retry, ARP_REQUEST_RETRIES - 1);
        }
        
        // Build and send ARP request frame directly via pcap
        uint8_t frame_buffer[64];
        int frame_len = build_arp_frame(frame_buffer, config->local_mac,
                                        config->local_ip, NULL, target_ip,
                                        ARP_OP_REQUEST);
        
        char target_ip_str[16];
        ip_bytes_to_str(target_ip, target_ip_str);
        LOG_INFO(&g_arp_logger, "Sending ARP request for %s (broadcast)", target_ip_str);
        
        if (pcap_sendpacket(handle, frame_buffer, frame_len) != 0)
        {
            LOG_ERROR(&g_arp_logger, "Failed to send ARP request: %s", pcap_geterr(handle));
            continue;
        }
        LOG_DEBUG(&g_arp_logger, "ARP request sent (%d bytes)", frame_len);
        
        // Wait for reply with timeout
        time_t start_time = time(NULL);
        while (time(NULL) - start_time < ARP_REQUEST_TIMEOUT)
        {
            struct pcap_pkthdr *header;
            const unsigned char *packet;
            int res = pcap_next_ex(handle, &header, &packet);
            
            if (res == 1)
            {
                arp_reply_callback_internal(NULL, header, packet);
                if (g_reply_received)
                {
                    memcpy(result_mac, g_resolved_mac, 6);
                    
                    // Add to cache
                    arp_cache_add(cache, target_ip, result_mac, ARP_STATE_DYNAMIC);
                    
                    pcap_freecode(&fcode);
                    pcap_close(handle);
                    return 1;
                }
            }
            else if (res == 0)
            {
                // Timeout on pcap_next_ex, continue waiting
                continue;
            }
            else
            {
                // Error
                break;
            }
        }
        
        char timeout_ip_str[16];
        ip_bytes_to_str(target_ip, timeout_ip_str);
        LOG_WARN(&g_arp_logger, "ARP request timeout for %s", timeout_ip_str);
    }
    
    pcap_freecode(&fcode);
    pcap_close(handle);
    
    char fail_ip_str[16];
    ip_bytes_to_str(target_ip, fail_ip_str);
    LOG_ERROR(&g_arp_logger, "ARP resolution failed for %s", fail_ip_str);
    
    return 0;
}

/**
 * High-level function to resolve IP to MAC address
 */
int arp_get_mac(network_config_t *config, arp_cache_t *cache,
                const uint8_t *dest_ip, uint8_t *result_mac)
{
    uint8_t target_ip[4];
    
    LOG_INFO(&g_arp_logger, "========== ARP Resolution ==========");
    
    // Determine if dest_ip is in same subnet
    if (is_same_subnet(config->local_ip, dest_ip, config->subnet_mask))
    {
        // Same subnet - resolve dest_ip directly
        char ip_str[16];
        ip_bytes_to_str(dest_ip, ip_str);
        LOG_INFO(&g_arp_logger, "Target %s is in the same subnet", ip_str);
        LOG_DEBUG(&g_arp_logger, "Resolving destination IP directly");
        memcpy(target_ip, dest_ip, 4);
    }
    else
    {
        // Different subnet - resolve gateway IP
        char dest_str[16], gw_str[16];
        ip_bytes_to_str(dest_ip, dest_str);
        ip_bytes_to_str(config->gateway_ip, gw_str);
        LOG_INFO(&g_arp_logger, "Target %s is in a different subnet", dest_str);
        LOG_DEBUG(&g_arp_logger, "Resolving gateway IP %s instead", gw_str);
        memcpy(target_ip, config->gateway_ip, 4);
    }
    
    LOG_INFO(&g_arp_logger, "====================================");
    
    // Perform ARP resolution
    return arp_resolve(config, cache, target_ip, result_mac);
}
