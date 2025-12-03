#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <unistd.h>
#include "ethernet_recv.h"
#include "ethernet.h"
#include "ethernet_send.h"
#include "crc32.h"

// Global variables for packet callback
static uint8_t *g_my_mac = NULL;
static uint8_t g_cached_local_mac[6] = {0};  // Cached MAC address
static const char *g_output_file = NULL;
static int g_packet_count = 0;
static ethernet_recv_callback_t g_upper_layer_callback = NULL;
static void *g_user_data = NULL;

// Get MAC address of a network interface
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
        printf("Frame discarded: Too small (%d bytes < %d bytes)\n", 
               frame_size, ETHERNET_MIN_FRAME_SIZE_NO_CRC);
        return 0;
    }
    
    // Check maximum frame size (pcap doesn't include CRC, so use 1514 bytes)
    if (frame_size > ETHERNET_MAX_FRAME_SIZE_NO_CRC)
    {
        printf("Frame discarded: Too large (%d bytes > %d bytes)\n", 
               frame_size, ETHERNET_MAX_FRAME_SIZE_NO_CRC);
        return 0;
    }
    
    // Check destination MAC address
    if (!mac_address_match(header->dest_mac, my_mac) && 
        !is_broadcast_mac(header->dest_mac))
    {
        printf("Frame discarded: Destination MAC does not match\n");
        printf("  Expected: %02X:%02X:%02X:%02X:%02X:%02X\n",
               my_mac[0], my_mac[1], my_mac[2], my_mac[3], my_mac[4], my_mac[5]);
        printf("  Received: %02X:%02X:%02X:%02X:%02X:%02X\n",
               header->dest_mac[0], header->dest_mac[1], header->dest_mac[2],
               header->dest_mac[3], header->dest_mac[4], header->dest_mac[5]);
        return 0;
    }
    
    // Calculate data length (pcap doesn't include CRC)
    int data_len = frame_size - ETHERNET_HEADER_SIZE;
    
    // Check data length (allow minimum of 28 bytes for ARP, max is MTU 1500)
    // Note: Ethernet padding may be present for frames < 60 bytes total
    if (data_len < 0 || data_len > ETHERNET_MAX_DATA_SIZE)
    {
        printf("Frame discarded: Invalid data length (%d bytes)\n", data_len);
        return 0;
    }
    
    // Note: We skip CRC verification since pcap doesn't capture the FCS
    // The NIC already verified the CRC before passing the frame to the OS
    
    return 1;
}

/**
 * Display Ethernet frame header information
 */
void display_ethernet_header(uint8_t *buffer)
{
    ethernet_header_t *header = (ethernet_header_t *)buffer;
    uint16_t eth_type = ntohs(header->ethernet_type);
    
    printf("\n========== Ethernet Frame Header ==========\n");
    
    // Display source MAC
    printf("Source MAC:      %02X:%02X:%02X:%02X:%02X:%02X\n",
           header->src_mac[0], header->src_mac[1], header->src_mac[2],
           header->src_mac[3], header->src_mac[4], header->src_mac[5]);
    
    // Display destination MAC
    printf("Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X",
           header->dest_mac[0], header->dest_mac[1], header->dest_mac[2],
           header->dest_mac[3], header->dest_mac[4], header->dest_mac[5]);
    
    if (is_broadcast_mac(header->dest_mac))
    {
        printf(" (Broadcast)\n");
    }
    else
    {
        printf("\n");
    }
    
    // Display Ethernet type
    printf("Ethernet Type:   0x%04X ", eth_type);
    switch (eth_type)
    {
        case ETHERNET_TYPE_IPV4:
            printf("(IPv4)\n");
            break;
        case ETHERNET_TYPE_ARP:
            printf("(ARP)\n");
            break;
        case ETHERNET_TYPE_RARP:
            printf("(RARP)\n");
            break;
        case ETHERNET_TYPE_IPV6:
            printf("(IPv6)\n");
            break;
        case ETHERNET_TYPE_ICMP:
            printf("(ICMP)\n");
            break;
        case ETHERNET_TYPE_IGMP:
            printf("(IGMP)\n");
            break;
        default:
            printf("(Unknown)\n");
            break;
    }
    
    printf("===========================================\n\n");
}

/**
 * Extract data from frame and save to file
 */
int extract_frame_data(uint8_t *buffer, int frame_size, const char *output_file)
{
    int data_len = frame_size - ETHERNET_HEADER_SIZE - ETHERNET_CRC_SIZE;
    uint8_t *data_start = buffer + ETHERNET_HEADER_SIZE;
    
    // Display data in hex format
    printf("Data (hex): ");
    for (int i = 0; i < data_len && i < 64; i++)  // Show first 64 bytes
    {
        printf("%02X ", data_start[i]);
        if ((i + 1) % 16 == 0)
            printf("\n            ");
    }
    if (data_len > 64)
        printf("... (%d bytes total)", data_len);
    printf("\n");
    
    // Display CRC
    uint32_t crc;
    memcpy(&crc, data_start + data_len, ETHERNET_CRC_SIZE);
    printf("CRC32:      0x%08X\n", crc);
    
    // Save data to file (for upper layer)
    FILE *fp = fopen(output_file, "wb");
    if (fp == NULL)
    {
        perror("Error opening output file");
        return -1;
    }
    
    size_t written = fwrite(data_start, 1, data_len, fp);
    fclose(fp);
    
    if (written != (size_t)data_len)
    {
        fprintf(stderr, "Error: Only wrote %zu of %d bytes to output\n", written, data_len);
        return -1;
    }
    
    printf("Data extracted: %d bytes written to %s\n", data_len, output_file);
    
    return data_len;
}

/**
 * Packet handler callback for pcap_loop
 */
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    (void)user_data;  // Unused parameter
    
    printf("\n========================================\n");
    printf("Captured packet #%d\n", ++g_packet_count);
    printf("Capture time: %ld.%06ld\n", (long)pkthdr->ts.tv_sec, (long)pkthdr->ts.tv_usec);
    printf("Packet length: %d bytes\n", pkthdr->len);
    
    // Verify frame
    if (!verify_frame((uint8_t *)packet, pkthdr->len, g_my_mac))
    {
        printf("========================================\n");
        return;  // Frame discarded
    }
    
    printf("Frame accepted!\n");
    
    // Display header
    display_ethernet_header((uint8_t *)packet);
    
    // Extract data
    int data_len = pkthdr->len - ETHERNET_HEADER_SIZE - ETHERNET_CRC_SIZE;
    uint8_t *data_start = (uint8_t *)packet + ETHERNET_HEADER_SIZE;
    
    // If callback is set, use it instead of writing to file
    if (g_upper_layer_callback != NULL)
    {
        printf("Delivering %d bytes to upper layer via callback\n", data_len);
        g_upper_layer_callback(data_start, data_len, g_user_data);
    }
    else if (g_output_file != NULL)
    {
        // Legacy file-based delivery
        if (extract_frame_data((uint8_t *)packet, pkthdr->len, g_output_file) < 0)
        {
            printf("Error extracting frame data\n");
        }
    }
    
    printf("========================================\n");
}

/**
 * Receive and process Ethernet frame using libpcap
 */
int ethernet_receive(const char *output_file)
{
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fcode;
    bpf_u_int32 netmask;
    int inum, i = 0;
    uint8_t local_mac[6];
    
    // Set global variables for callback
    g_output_file = output_file;
    g_packet_count = 0;
    
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
    scanf("%d", &inum);
    
    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Jump to the selected adapter
    for (device = alldevs, i = 0; i < inum - 1; device = device->next, i++);
    
    printf("\nSelected interface: %s\n", device->name);
    
    // Get local MAC address from selected interface
    if (get_interface_mac(device->name, local_mac) < 0)
    {
        fprintf(stderr, "\nFailed to get MAC address for %s\n", device->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("Local MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
           local_mac[0], local_mac[1], local_mac[2], 
           local_mac[3], local_mac[4], local_mac[5]);
    
    // Cache the MAC address and set global pointer
    memcpy(g_cached_local_mac, local_mac, 6);
    g_my_mac = g_cached_local_mac;
    
    // Notify ethernet_send module about the selected interface
    ethernet_send_set_interface(device->name, local_mac);
    
    // Open the device
    handle = pcap_open_live(device->name,      // name of the device
                            65536,              // portion to capture (entire packet)
                            1,                  // promiscuous mode
                            1000,               // read timeout
                            errbuf);            // error buffer
    
    if (handle == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter %s.\nError: %s\n", device->name, errbuf);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Check the link layer
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Get the netmask
    netmask = 0xffffff;
    
    // Compile the filter
    // Filter: ether dst <my_mac> or ether broadcast
    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp),
             "ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether broadcast",
             local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
    
    printf("\nSetting filter: %s\n", filter_exp);
    
    if (pcap_compile(handle, &fcode, filter_exp, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Set the filter
    if (pcap_setfilter(handle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nListening on %s...\n", device->name);
    printf("Waiting for Ethernet frames (Press Ctrl+C to stop)...\n");
    
    // Start the capture (capture 10 packets or until Ctrl+C)
    pcap_loop(handle, 10, packet_handler, NULL);
    
    printf("\nCapture finished. Total packets received: %d\n", g_packet_count);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    
    return 1;
}

/**
 * Receive and process Ethernet frames with callback
 */
int ethernet_receive_callback(ethernet_recv_callback_t callback, void *user_data, int packet_count)
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
    
    // Set global variables for callback
    g_upper_layer_callback = callback;
    g_user_data = user_data;
    g_output_file = NULL;
    g_packet_count = 0;
    
    // Check if interface is already pre-selected
    if (ethernet_send_is_interface_selected())
    {
        interface_to_use = ethernet_send_get_interface();
        ethernet_send_get_src_mac(local_mac);
        
        // Cache the MAC address and set global pointer
        memcpy(g_cached_local_mac, local_mac, 6);
        g_my_mac = g_cached_local_mac;
        
        printf("\nUsing pre-selected interface: %s\n", interface_to_use);
        printf("Local MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               local_mac[0], local_mac[1], local_mac[2],
               local_mac[3], local_mac[4], local_mac[5]);
    }
    else
    {
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
        
        interface_to_use = device->name;
        printf("\nSelected interface: %s\n", device->name);
        
        // Get local MAC address from selected interface
        if (get_interface_mac(device->name, local_mac) < 0)
        {
            fprintf(stderr, "\nFailed to get MAC address for %s\n", device->name);
            pcap_freealldevs(alldevs);
            return -1;
        }
        
        printf("Local MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
               local_mac[0], local_mac[1], local_mac[2], 
               local_mac[3], local_mac[4], local_mac[5]);
        
        // Cache the MAC address and set global pointer
        memcpy(g_cached_local_mac, local_mac, 6);
        g_my_mac = g_cached_local_mac;
        
        // Notify ethernet_send module about the selected interface
        ethernet_send_set_interface(device->name, local_mac);
    }
    
    // Open the device
    handle = pcap_open_live(interface_to_use,   // name of the device
                            65536,              // portion to capture (entire packet)
                            1,                  // promiscuous mode
                            1000,               // read timeout
                            errbuf);            // error buffer
    
    if (handle == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter %s.\nError: %s\n", interface_to_use, errbuf);
        if (alldevs) pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Check the link layer
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
        pcap_close(handle);
        if (alldevs) pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Get the netmask
    netmask = 0xffffff;
    
    // Compile the filter
    char filter_exp[256];
    snprintf(filter_exp, sizeof(filter_exp),
             "ether dst %02x:%02x:%02x:%02x:%02x:%02x or ether broadcast",
             local_mac[0], local_mac[1], local_mac[2], local_mac[3], local_mac[4], local_mac[5]);
    
    printf("\nSetting filter: %s\n", filter_exp);
    
    if (pcap_compile(handle, &fcode, filter_exp, 1, netmask) < 0)
    {
        fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
        pcap_close(handle);
        if (alldevs) pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Set the filter
    if (pcap_setfilter(handle, &fcode) < 0)
    {
        fprintf(stderr, "\nError setting the filter.\n");
        pcap_close(handle);
        if (alldevs) pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nListening on %s...\n", interface_to_use);
    printf("Waiting for Ethernet frames (Press Ctrl+C to stop)...\n");
    
    // Free alldevs now if it was allocated
    if (alldevs) pcap_freealldevs(alldevs);
    
    // Start the capture
    int captured = pcap_loop(handle, packet_count, packet_handler, NULL);
    
    printf("\nCapture finished. Total packets received: %d\n", g_packet_count);
    
    pcap_close(handle);
    
    // Reset callback
    g_upper_layer_callback = NULL;
    g_user_data = NULL;
    
    return captured;
}
