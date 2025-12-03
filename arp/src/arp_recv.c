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
#include "../include/arp_recv.h"
#include "../include/arp_send.h"
#include "../../ethernet/include/ethernet_recv.h"
#include "../../ethernet/include/ethernet_send.h"
#include "../../ethernet/include/ethernet.h"
#include "../../common/include/logger.h"

/* Use the global ARP logger from arp_send.c */
extern logger_t g_arp_logger;

/* Global variables for ARP receiver */
static arp_reply_callback_t g_reply_callback = NULL;
static void *g_callback_user_data = NULL;
static network_config_t *g_config = NULL;
static arp_cache_t *g_cache = NULL;
static int g_running = 0;

/**
 * Verify ARP packet integrity
 */
int verify_arp_packet(const uint8_t *buffer, int len)
{
    if (len < (int)sizeof(arp_header_t))
    {
        LOG_WARN(&g_arp_logger, "ARP packet too small: %d bytes", len);
        return 0;
    }
    
    const arp_header_t *arp = (const arp_header_t *)buffer;
    
    // Verify hardware type (must be Ethernet)
    if (ntohs(arp->hardware_type) != ARP_HARDWARE_ETHERNET)
    {
        LOG_WARN(&g_arp_logger, "Invalid hardware type: 0x%04X", ntohs(arp->hardware_type));
        return 0;
    }
    
    // Verify protocol type (must be IPv4)
    if (ntohs(arp->protocol_type) != ARP_PROTOCOL_IPV4)
    {
        LOG_WARN(&g_arp_logger, "Invalid protocol type: 0x%04X", ntohs(arp->protocol_type));
        return 0;
    }
    
    // Verify address lengths
    if (arp->hardware_len != ARP_HARDWARE_ADDR_LEN ||
        arp->protocol_len != ARP_PROTOCOL_ADDR_LEN)
    {
        LOG_WARN(&g_arp_logger, "Invalid address lengths: HLEN=%d, PLEN=%d",
                 arp->hardware_len, arp->protocol_len);
        return 0;
    }
    
    // Verify operation code
    uint16_t op = ntohs(arp->operation);
    if (op != ARP_OP_REQUEST && op != ARP_OP_REPLY &&
        op != ARP_OP_RARP_REQUEST && op != ARP_OP_RARP_REPLY)
    {
        LOG_WARN(&g_arp_logger, "Invalid operation code: %d", op);
        return 0;
    }
    
    return 1;
}

/**
 * Parse ARP header from buffer
 */
int parse_arp_header(const uint8_t *buffer, arp_header_t *header)
{
    memcpy(header, buffer, sizeof(arp_header_t));
    return 0;
}

/**
 * Handle ARP request
 */
int arp_handle_request(arp_header_t *header, network_config_t *config,
                       arp_cache_t *cache)
{
    char sender_ip_str[16], target_ip_str[16];
    char sender_mac_str[18];
    
    ip_bytes_to_str(header->sender_ip, sender_ip_str);
    ip_bytes_to_str(header->target_ip, target_ip_str);
    mac_bytes_to_str(header->sender_mac, sender_mac_str);
    
    LOG_INFO(&g_arp_logger, "Received ARP Request:");
    LOG_INFO(&g_arp_logger, "  Who has %s? Tell %s (%s)", 
             target_ip_str, sender_ip_str, sender_mac_str);
    
    // Update ARP cache with sender's information
    arp_cache_add(cache, header->sender_ip, header->sender_mac, ARP_STATE_DYNAMIC);
    
    // Check if target IP is our IP
    if (memcmp(header->target_ip, config->local_ip, 4) == 0)
    {
        LOG_INFO(&g_arp_logger, "  -> Target IP is our IP! Sending reply...");
        
        // Send ARP reply
        if (arp_send_reply(config->local_mac, config->local_ip,
                          header->sender_mac, header->sender_ip) > 0)
        {
            LOG_INFO(&g_arp_logger, "  -> ARP reply sent successfully");
            return 1;
        }
        else
        {
            LOG_ERROR(&g_arp_logger, "  -> Failed to send ARP reply");
            return 0;
        }
    }
    else
    {
        char local_ip_str[16];
        ip_bytes_to_str(config->local_ip, local_ip_str);
        LOG_DEBUG(&g_arp_logger, "  -> Target IP (%s) is not our IP (%s), ignoring",
                  target_ip_str, local_ip_str);
        return 0;
    }
}

/**
 * Handle ARP reply
 */
int arp_handle_reply(arp_header_t *header, network_config_t *config,
                     arp_cache_t *cache)
{
    (void)config;  // May be used for additional validation
    
    char sender_ip_str[16], sender_mac_str[18];
    
    ip_bytes_to_str(header->sender_ip, sender_ip_str);
    mac_bytes_to_str(header->sender_mac, sender_mac_str);
    
    LOG_INFO(&g_arp_logger, "Received ARP Reply:");
    LOG_INFO(&g_arp_logger, "  %s is at %s", sender_ip_str, sender_mac_str);
    
    // Update ARP cache
    arp_cache_add(cache, header->sender_ip, header->sender_mac, ARP_STATE_DYNAMIC);
    
    // Call user callback if set
    if (g_reply_callback != NULL)
    {
        g_reply_callback(header->sender_ip, header->sender_mac, g_callback_user_data);
    }
    
    return 1;
}

/**
 * Process received ARP packet
 */
int arp_process_packet(const uint8_t *buffer, int len,
                       network_config_t *config, arp_cache_t *cache)
{
    // Verify packet
    if (!verify_arp_packet(buffer, len))
    {
        LOG_WARN(&g_arp_logger, "Invalid ARP packet discarded");
        return 0;
    }
    
    // Parse header
    arp_header_t header;
    parse_arp_header(buffer, &header);
    
    // Display packet info
    display_arp_header(&header);
    
    // Process based on operation type
    uint16_t op = ntohs(header.operation);
    
    switch (op)
    {
        case ARP_OP_REQUEST:
            return arp_handle_request(&header, config, cache);
            
        case ARP_OP_REPLY:
            return arp_handle_reply(&header, config, cache);
            
        case ARP_OP_RARP_REQUEST:
        case ARP_OP_RARP_REPLY:
            LOG_WARN(&g_arp_logger, "RARP not supported");
            return 0;
            
        default:
            LOG_WARN(&g_arp_logger, "Unknown ARP operation: %d", op);
            return 0;
    }
}

/**
 * Ethernet callback for ARP processing
 */
void arp_ethernet_callback(uint8_t *data, int data_len, void *user_data)
{
    (void)user_data;
    
    LOG_INFO(&g_arp_logger, "========================================");
    LOG_INFO(&g_arp_logger, "ARP packet received from Ethernet layer");
    LOG_DEBUG(&g_arp_logger, "Packet size: %d bytes", data_len);
    
    if (g_config != NULL && g_cache != NULL)
    {
        arp_process_packet(data, data_len, g_config, g_cache);
    }
    else
    {
        LOG_ERROR(&g_arp_logger, "ARP context not initialized");
    }
    
    LOG_INFO(&g_arp_logger, "========================================");
}

/**
 * Set callback for ARP reply notification
 */
void arp_set_reply_callback(arp_reply_callback_t callback, void *user_data)
{
    g_reply_callback = callback;
    g_callback_user_data = user_data;
}

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
 * Packet handler for pcap_loop
 */
static void arp_packet_handler(unsigned char *user_data,
                               const struct pcap_pkthdr *pkthdr,
                               const unsigned char *packet)
{
    (void)user_data;
    
    LOG_INFO(&g_arp_logger, "========================================");
    LOG_INFO(&g_arp_logger, "Captured ARP packet");
    LOG_DEBUG(&g_arp_logger, "Capture time: %ld.%06ld", (long)pkthdr->ts.tv_sec, (long)pkthdr->ts.tv_usec);
    LOG_DEBUG(&g_arp_logger, "Packet length: %d bytes", pkthdr->len);
    
    // Skip Ethernet header (14 bytes)
    if (pkthdr->len > 14)
    {
        const uint8_t *arp_data = packet + 14;
        int arp_len = pkthdr->len - 14;
        
        arp_process_packet(arp_data, arp_len, g_config, g_cache);
    }
    
    // Display current ARP cache
    arp_cache_display(g_cache);
    
    LOG_INFO(&g_arp_logger, "========================================");
}

/**
 * Start ARP receiver
 */
int arp_receive(network_config_t *config, arp_cache_t *cache)
{
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fcode;
    int inum, i = 0;
    
    // Store global pointers
    g_config = config;
    g_cache = cache;
    g_running = 1;
    
    // Retrieve the device list
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        LOG_ERROR(&g_arp_logger, "Error in pcap_findalldevs: %s", errbuf);
        return -1;
    }
    
    // Print the list (user interaction - keep printf)
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
        LOG_ERROR(&g_arp_logger, "No interfaces found! Make sure you have the proper permissions.");
        return -1;
    }
    
    printf("\nEnter the interface number (1-%d): ", i);
    if (scanf("%d", &inum) != 1)
    {
        LOG_ERROR(&g_arp_logger, "Invalid input");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    if (inum < 1 || inum > i)
    {
        LOG_ERROR(&g_arp_logger, "Interface number out of range");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Jump to the selected adapter
    for (device = alldevs, i = 0; i < inum - 1; device = device->next, i++);
    
    LOG_INFO(&g_arp_logger, "Selected interface: %s", device->name);
    
    // Get local MAC address from interface
    if (get_interface_mac(device->name, config->local_mac) < 0)
    {
        LOG_ERROR(&g_arp_logger, "Failed to get MAC address for %s", device->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Get local IP address from interface
    if (get_interface_ip(device->name, config->local_ip) < 0)
    {
        LOG_WARN(&g_arp_logger, "Failed to get IP address from interface");
    }
    
    char mac_str[18], ip_str[16];
    mac_bytes_to_str(config->local_mac, mac_str);
    ip_bytes_to_str(config->local_ip, ip_str);
    LOG_INFO(&g_arp_logger, "Local MAC: %s", mac_str);
    LOG_INFO(&g_arp_logger, "Local IP: %s", ip_str);
    
    // Open the device
    handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    
    if (handle == NULL)
    {
        LOG_ERROR(&g_arp_logger, "Unable to open the adapter. %s is not supported", device->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Set filter for ARP packets
    if (pcap_compile(handle, &fcode, "arp", 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        LOG_ERROR(&g_arp_logger, "Unable to compile the packet filter");
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    if (pcap_setfilter(handle, &fcode) < 0)
    {
        LOG_ERROR(&g_arp_logger, "Error setting the filter");
        pcap_freecode(&fcode);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    pcap_freealldevs(alldevs);
    
    LOG_INFO(&g_arp_logger, "========================================");
    LOG_INFO(&g_arp_logger, "    ARP Receiver Started");
    LOG_INFO(&g_arp_logger, "    Listening for ARP packets...");
    LOG_INFO(&g_arp_logger, "    Press Ctrl+C to stop");
    LOG_INFO(&g_arp_logger, "========================================");
    
    // Start capturing
    pcap_loop(handle, 0, arp_packet_handler, NULL);
    
    pcap_freecode(&fcode);
    pcap_close(handle);
    
    return 0;
}
