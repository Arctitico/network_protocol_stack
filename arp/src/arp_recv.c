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
#include "arp.h"
#include "arp_recv.h"
#include "arp_send.h"
#include "../../ethernet/include/ethernet_recv.h"
#include "../../ethernet/include/ethernet_send.h"
#include "../../ethernet/include/ethernet.h"

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
        printf("ARP packet too small: %d bytes\n", len);
        return 0;
    }
    
    const arp_header_t *arp = (const arp_header_t *)buffer;
    
    // Verify hardware type (must be Ethernet)
    if (ntohs(arp->hardware_type) != ARP_HARDWARE_ETHERNET)
    {
        printf("Invalid hardware type: 0x%04X\n", ntohs(arp->hardware_type));
        return 0;
    }
    
    // Verify protocol type (must be IPv4)
    if (ntohs(arp->protocol_type) != ARP_PROTOCOL_IPV4)
    {
        printf("Invalid protocol type: 0x%04X\n", ntohs(arp->protocol_type));
        return 0;
    }
    
    // Verify address lengths
    if (arp->hardware_len != ARP_HARDWARE_ADDR_LEN ||
        arp->protocol_len != ARP_PROTOCOL_ADDR_LEN)
    {
        printf("Invalid address lengths: HLEN=%d, PLEN=%d\n",
               arp->hardware_len, arp->protocol_len);
        return 0;
    }
    
    // Verify operation code
    uint16_t op = ntohs(arp->operation);
    if (op != ARP_OP_REQUEST && op != ARP_OP_REPLY &&
        op != ARP_OP_RARP_REQUEST && op != ARP_OP_RARP_REPLY)
    {
        printf("Invalid operation code: %d\n", op);
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
    
    printf("\nReceived ARP Request:\n");
    printf("  Who has %s? Tell %s (%s)\n", 
           target_ip_str, sender_ip_str, sender_mac_str);
    
    // Update ARP cache with sender's information
    arp_cache_add(cache, header->sender_ip, header->sender_mac, ARP_STATE_DYNAMIC);
    
    // Check if target IP is our IP
    if (memcmp(header->target_ip, config->local_ip, 4) == 0)
    {
        printf("  -> Target IP is our IP! Sending reply...\n");
        
        // Send ARP reply
        if (arp_send_reply(config->local_mac, config->local_ip,
                          header->sender_mac, header->sender_ip) > 0)
        {
            printf("  -> ARP reply sent successfully\n");
            return 1;
        }
        else
        {
            printf("  -> Failed to send ARP reply\n");
            return 0;
        }
    }
    else
    {
        char local_ip_str[16];
        ip_bytes_to_str(config->local_ip, local_ip_str);
        printf("  -> Target IP (%s) is not our IP (%s), ignoring\n",
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
    
    printf("\nReceived ARP Reply:\n");
    printf("  %s is at %s\n", sender_ip_str, sender_mac_str);
    
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
        printf("Invalid ARP packet discarded\n");
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
            printf("RARP not supported\n");
            return 0;
            
        default:
            printf("Unknown ARP operation: %d\n", op);
            return 0;
    }
}

/**
 * Ethernet callback for ARP processing
 */
void arp_ethernet_callback(uint8_t *data, int data_len, void *user_data)
{
    (void)user_data;
    
    printf("\n========================================\n");
    printf("ARP packet received from Ethernet layer\n");
    printf("Packet size: %d bytes\n", data_len);
    
    if (g_config != NULL && g_cache != NULL)
    {
        arp_process_packet(data, data_len, g_config, g_cache);
    }
    else
    {
        printf("Error: ARP context not initialized\n");
    }
    
    printf("========================================\n");
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
        perror("socket");
        return -1;
    }
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
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
        perror("socket");
        return -1;
    }
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        perror("ioctl");
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
    
    printf("\n========================================\n");
    printf("Captured ARP packet\n");
    printf("Capture time: %ld.%06ld\n", (long)pkthdr->ts.tv_sec, (long)pkthdr->ts.tv_usec);
    printf("Packet length: %d bytes\n", pkthdr->len);
    
    // Skip Ethernet header (14 bytes)
    if (pkthdr->len > 14)
    {
        const uint8_t *arp_data = packet + 14;
        int arp_len = pkthdr->len - 14;
        
        arp_process_packet(arp_data, arp_len, g_config, g_cache);
    }
    
    // Display current ARP cache
    arp_cache_display(g_cache);
    
    printf("========================================\n");
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
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return -1;
    }
    
    // Print the list
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
        printf("\nNo interfaces found! Make sure you have the proper permissions.\n");
        return -1;
    }
    
    printf("\nEnter the interface number (1-%d): ", i);
    if (scanf("%d", &inum) != 1)
    {
        fprintf(stderr, "Invalid input\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Jump to the selected adapter
    for (device = alldevs, i = 0; i < inum - 1; device = device->next, i++);
    
    printf("\nSelected interface: %s\n", device->name);
    
    // Get local MAC address from interface
    if (get_interface_mac(device->name, config->local_mac) < 0)
    {
        fprintf(stderr, "Failed to get MAC address for %s\n", device->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Get local IP address from interface
    if (get_interface_ip(device->name, config->local_ip) < 0)
    {
        fprintf(stderr, "Warning: Failed to get IP address from interface\n");
    }
    
    char mac_str[18], ip_str[16];
    mac_bytes_to_str(config->local_mac, mac_str);
    ip_bytes_to_str(config->local_ip, ip_str);
    printf("Local MAC: %s\n", mac_str);
    printf("Local IP: %s\n", ip_str);
    
    // Open the device
    handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    
    if (handle == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported\n", device->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Set filter for ARP packets
    if (pcap_compile(handle, &fcode, "arp", 1, PCAP_NETMASK_UNKNOWN) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter.\n");
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    if (pcap_setfilter(handle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        pcap_freecode(&fcode);
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    pcap_freealldevs(alldevs);
    
    printf("\n========================================\n");
    printf("    ARP Receiver Started\n");
    printf("    Listening for ARP packets...\n");
    printf("    Press Ctrl+C to stop\n");
    printf("========================================\n\n");
    
    // Start capturing
    pcap_loop(handle, 0, arp_packet_handler, NULL);
    
    pcap_freecode(&fcode);
    pcap_close(handle);
    
    return 0;
}
