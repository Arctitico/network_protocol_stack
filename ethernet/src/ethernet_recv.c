#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <unistd.h>
#include "../include/ethernet_recv.h"
#include "../include/ethernet.h"
#include "../include/ethernet_send.h"
#include "../include/crc32.h"
#include "../../common/include/logger.h"

// Maximum number of protocol handlers
#define MAX_PROTOCOL_HANDLERS 16

// Protocol handler entry
typedef struct {
    uint16_t ether_type;
    ethernet_recv_callback_t callback;
    void *user_data;
    int active;
} protocol_handler_t;

// Global variables for packet callback
static uint8_t *g_my_mac = NULL;
static uint8_t g_cached_local_mac[6] = {0};
static int g_packet_count = 0;

// Last received packet source MAC (for ICMP reply etc.)
static uint8_t g_last_src_mac[6] = {0};

// Protocol dispatch table
static protocol_handler_t g_protocol_handlers[MAX_PROTOCOL_HANDLERS];

// Global pcap handle for stopping capture
static pcap_t *g_pcap_handle = NULL;

// Get MAC address of a network interface
static int get_interface_mac(const char *ifname, uint8_t *mac)
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sock < 0)
    {
        LOG_ERROR(&g_ethernet_logger, "Failed to create socket for MAC lookup");
        return -1;
    }
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0)
    {
        LOG_ERROR(&g_ethernet_logger, "ioctl SIOCGIFHWADDR failed for %s", ifname);
        close(sock);
        return -1;
    }
    
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);
    
    return 0;
}

/**
 * Check if two MAC addresses match
 */
int mac_address_match(uint8_t *mac1, uint8_t *mac2)
{
    return memcmp(mac1, mac2, 6) == 0;
}

/**
 * Check if MAC address is broadcast (FF:FF:FF:FF:FF:FF)
 */
int is_broadcast_mac(uint8_t *mac)
{
    uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return mac_address_match(mac, broadcast);
}

/**
 * Verify frame integrity
 */
int verify_frame(uint8_t *buffer, int frame_size, uint8_t *my_mac)
{
    ethernet_header_t *header = (ethernet_header_t *)buffer;
    
    // Check minimum frame size (pcap doesn't include CRC, so use 60 bytes)
    if (frame_size < ETHERNET_MIN_FRAME_SIZE_NO_CRC)
    {
        LOG_DEBUG(&g_ethernet_logger, "Frame discarded: Too small (%d < %d bytes)", 
                  frame_size, ETHERNET_MIN_FRAME_SIZE_NO_CRC);
        return 0;
    }
    
    // Check maximum frame size
    if (frame_size > ETHERNET_MAX_FRAME_SIZE_NO_CRC)
    {
        LOG_DEBUG(&g_ethernet_logger, "Frame discarded: Too large (%d > %d bytes)", 
                  frame_size, ETHERNET_MAX_FRAME_SIZE_NO_CRC);
        return 0;
    }
    
    // Check destination MAC address
    if (!mac_address_match(header->dest_mac, my_mac) && 
        !is_broadcast_mac(header->dest_mac))
    {
        LOG_DEBUG(&g_ethernet_logger, "Frame discarded: Dest MAC %02X:%02X:%02X:%02X:%02X:%02X does not match",
                  header->dest_mac[0], header->dest_mac[1], header->dest_mac[2],
                  header->dest_mac[3], header->dest_mac[4], header->dest_mac[5]);
        return 0;
    }
    
    // Calculate data length
    int data_len = frame_size - ETHERNET_HEADER_SIZE;
    
    if (data_len < 0 || data_len > ETHERNET_MAX_DATA_SIZE)
    {
        LOG_DEBUG(&g_ethernet_logger, "Frame discarded: Invalid data length (%d bytes)", data_len);
        return 0;
    }
    
    return 1;
}

/**
 * Display Ethernet frame header information
 */
void display_ethernet_header(uint8_t *buffer)
{
    ethernet_header_t *header = (ethernet_header_t *)buffer;
    uint16_t eth_type = ntohs(header->ethernet_type);
    
    const char *type_str;
    switch (eth_type)
    {
        case ETHERNET_TYPE_IPV4: type_str = "IPv4"; break;
        case ETHERNET_TYPE_ARP:  type_str = "ARP";  break;
        case ETHERNET_TYPE_RARP: type_str = "RARP"; break;
        case ETHERNET_TYPE_IPV6: type_str = "IPv6"; break;
        default: type_str = "Unknown"; break;
    }
    
    LOG_INFO(&g_ethernet_logger, "Ethernet Frame: Src=%02X:%02X:%02X:%02X:%02X:%02X Dst=%02X:%02X:%02X:%02X:%02X:%02X Type=0x%04X(%s)",
             header->src_mac[0], header->src_mac[1], header->src_mac[2],
             header->src_mac[3], header->src_mac[4], header->src_mac[5],
             header->dest_mac[0], header->dest_mac[1], header->dest_mac[2],
             header->dest_mac[3], header->dest_mac[4], header->dest_mac[5],
             eth_type, type_str);
}

/**
 * Packet handler callback for pcap_loop - dispatches by EtherType
 */
static void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    (void)user_data;
    
    ++g_packet_count;
    LOG_DEBUG(&g_ethernet_logger, "Captured packet #%d, length=%d bytes", g_packet_count, pkthdr->len);
    
    // Verify frame
    if (!verify_frame((uint8_t *)packet, pkthdr->len, g_my_mac))
    {
        return;
    }
    
    LOG_INFO(&g_ethernet_logger, "Frame #%d accepted", g_packet_count);
    
    // Display header
    display_ethernet_header((uint8_t *)packet);
    
    // Get EtherType and data
    ethernet_header_t *header = (ethernet_header_t *)packet;
    uint16_t ether_type = ntohs(header->ethernet_type);
    int data_len = pkthdr->len - ETHERNET_HEADER_SIZE;
    uint8_t *data_start = (uint8_t *)packet + ETHERNET_HEADER_SIZE;
    
    // Store source MAC for upper layer use (e.g., ICMP reply)
    memcpy(g_last_src_mac, header->src_mac, 6);
    
    // Find and call handler for this EtherType
    for (int i = 0; i < MAX_PROTOCOL_HANDLERS; i++)
    {
        if (g_protocol_handlers[i].active && 
            g_protocol_handlers[i].ether_type == ether_type)
        {
            LOG_DEBUG(&g_ethernet_logger, "Dispatching %d bytes to protocol 0x%04X handler", 
                     data_len, ether_type);
            g_protocol_handlers[i].callback(data_start, data_len, 
                                            g_protocol_handlers[i].user_data);
            return;
        }
    }
    
    LOG_DEBUG(&g_ethernet_logger, "No handler for EtherType 0x%04X, dropping frame", ether_type);
}

/**
 * Register a protocol handler for a specific EtherType
 */
int ethernet_register_protocol(uint16_t ether_type, ethernet_recv_callback_t callback, void *user_data)
{
    // First check if this EtherType is already registered
    for (int i = 0; i < MAX_PROTOCOL_HANDLERS; i++)
    {
        if (g_protocol_handlers[i].active && 
            g_protocol_handlers[i].ether_type == ether_type)
        {
            // Update existing entry
            g_protocol_handlers[i].callback = callback;
            g_protocol_handlers[i].user_data = user_data;
            LOG_DEBUG(&g_ethernet_logger, "Updated protocol handler for EtherType 0x%04X", ether_type);
            return 0;
        }
    }
    
    // Find an empty slot
    for (int i = 0; i < MAX_PROTOCOL_HANDLERS; i++)
    {
        if (!g_protocol_handlers[i].active)
        {
            g_protocol_handlers[i].ether_type = ether_type;
            g_protocol_handlers[i].callback = callback;
            g_protocol_handlers[i].user_data = user_data;
            g_protocol_handlers[i].active = 1;
            LOG_INFO(&g_ethernet_logger, "Registered protocol handler for EtherType 0x%04X", ether_type);
            return 0;
        }
    }
    
    LOG_ERROR(&g_ethernet_logger, "Protocol handler table full, cannot register 0x%04X", ether_type);
    return -1;
}

/**
 * Unregister a protocol handler
 */
int ethernet_unregister_protocol(uint16_t ether_type)
{
    for (int i = 0; i < MAX_PROTOCOL_HANDLERS; i++)
    {
        if (g_protocol_handlers[i].active && 
            g_protocol_handlers[i].ether_type == ether_type)
        {
            g_protocol_handlers[i].active = 0;
            g_protocol_handlers[i].callback = NULL;
            g_protocol_handlers[i].user_data = NULL;
            LOG_INFO(&g_ethernet_logger, "Unregistered protocol handler for EtherType 0x%04X", ether_type);
            return 0;
        }
    }
    
    LOG_WARN(&g_ethernet_logger, "Protocol handler for EtherType 0x%04X not found", ether_type);
    return -1;
}

/**
 * Get the source MAC address of the last received frame
 */
void ethernet_get_last_src_mac(uint8_t *mac)
{
    if (mac != NULL)
    {
        memcpy(mac, g_last_src_mac, 6);
    }
}

/**
 * Clear all registered protocol handlers
 */
void ethernet_clear_protocols(void)
{
    for (int i = 0; i < MAX_PROTOCOL_HANDLERS; i++)
    {
        g_protocol_handlers[i].active = 0;
        g_protocol_handlers[i].callback = NULL;
        g_protocol_handlers[i].user_data = NULL;
    }
    LOG_INFO(&g_ethernet_logger, "Cleared all protocol handlers");
}

/**
 * Start receiving Ethernet frames with protocol dispatching
 */
int ethernet_receive_dispatch(int packet_count)
{
    pcap_if_t *alldevs = NULL;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fcode;
    bpf_u_int32 netmask;
    int inum, i = 0;
    uint8_t local_mac[6];
    const char *interface_to_use = NULL;
    
    g_packet_count = 0;
    
    // Check if interface is already pre-selected
    if (ethernet_send_is_interface_selected())
    {
        interface_to_use = ethernet_send_get_interface();
        ethernet_send_get_src_mac(local_mac);
        
        memcpy(g_cached_local_mac, local_mac, 6);
        g_my_mac = g_cached_local_mac;
        
        printf("\nUsing pre-selected interface: %s\n", interface_to_use);
        printf("Local MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               local_mac[0], local_mac[1], local_mac[2],
               local_mac[3], local_mac[4], local_mac[5]);
        LOG_INFO(&g_ethernet_logger, "Using pre-selected interface: %s", interface_to_use);
    }
    else
    {
        // Retrieve the device list
        if (pcap_findalldevs(&alldevs, errbuf) == -1)
        {
            LOG_ERROR(&g_ethernet_logger, "pcap_findalldevs failed: %s", errbuf);
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
            LOG_ERROR(&g_ethernet_logger, "Invalid input for interface selection");
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
        
        interface_to_use = device->name;
        printf("\nSelected interface: %s\n", device->name);
        LOG_INFO(&g_ethernet_logger, "Selected interface: %s", device->name);
        
        // Get local MAC address
        if (get_interface_mac(device->name, local_mac) < 0)
        {
            LOG_ERROR(&g_ethernet_logger, "Failed to get MAC address for %s", device->name);
            pcap_freealldevs(alldevs);
            return -1;
        }
        
        printf("Local MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
               local_mac[0], local_mac[1], local_mac[2], 
               local_mac[3], local_mac[4], local_mac[5]);
        LOG_INFO(&g_ethernet_logger, "Local MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
                 local_mac[0], local_mac[1], local_mac[2], 
                 local_mac[3], local_mac[4], local_mac[5]);
        
        memcpy(g_cached_local_mac, local_mac, 6);
        g_my_mac = g_cached_local_mac;
        
        // Notify ethernet_send module
        ethernet_send_set_interface(device->name, local_mac);
    }
    
    // Open the device - use shorter timeout for better responsiveness
    handle = pcap_open_live(interface_to_use, 65536, 1, 10, errbuf);
    
    // Store handle globally for stop_capture
    g_pcap_handle = handle;
    
    if (handle == NULL)
    {
        LOG_ERROR(&g_ethernet_logger, "Unable to open adapter %s: %s", interface_to_use, errbuf);
        if (alldevs) pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Check the link layer
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        LOG_ERROR(&g_ethernet_logger, "This program works only on Ethernet networks");
        pcap_close(handle);
        if (alldevs) pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Compile and set the filter
    netmask = 0xffffff;
    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp),
             "ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether broadcast",
             local_mac[0], local_mac[1], local_mac[2], 
             local_mac[3], local_mac[4], local_mac[5]);
    
    printf("\nSetting filter: %s\n", filter_exp);
    LOG_DEBUG(&g_ethernet_logger, "Setting filter: %s", filter_exp);
    
    if (pcap_compile(handle, &fcode, filter_exp, 1, netmask) < 0)
    {
        LOG_ERROR(&g_ethernet_logger, "Unable to compile packet filter");
        pcap_close(handle);
        if (alldevs) pcap_freealldevs(alldevs);
        return -1;
    }
    
    if (pcap_setfilter(handle, &fcode) < 0)
    {
        LOG_ERROR(&g_ethernet_logger, "Error setting the filter");
        pcap_close(handle);
        if (alldevs) pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nListening on %s...\n", interface_to_use);
    printf("Waiting for Ethernet frames (Press Ctrl+C to stop)...\n");
    LOG_INFO(&g_ethernet_logger, "Starting on %s", interface_to_use);
    
    // Free alldevs now if it was allocated
    if (alldevs) pcap_freealldevs(alldevs);
    
    // Start the capture
    int captured = pcap_loop(handle, packet_count, packet_handler, NULL);
    
    LOG_INFO(&g_ethernet_logger, "Capture finished. Total packets: %d", g_packet_count);
    printf("\nCapture finished. Total packets received: %d\n", g_packet_count);
    
    pcap_close(handle);
    g_pcap_handle = NULL;
    
    return captured;
}

/**
 * Stop the current pcap capture loop
 */
void ethernet_stop_capture(void)
{
    if (g_pcap_handle != NULL)
    {
        pcap_breakloop(g_pcap_handle);
        LOG_INFO(&g_ethernet_logger, "Capture loop stopped by user request");
    }
}
