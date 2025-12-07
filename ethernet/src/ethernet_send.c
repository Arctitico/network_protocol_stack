#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <unistd.h>
#include "../include/ethernet_send.h"
#include "../include/ethernet.h"
#include "../include/crc32.h"
#include "../../common/include/logger.h"

/* Global logger instance for ethernet module */
logger_t g_ethernet_logger;
static int g_logger_initialized = 0;

// Global variables to cache interface selection
static char g_selected_interface[IFNAMSIZ] = {0};
static uint8_t g_cached_src_mac[6] = {0};
static int g_interface_selected = 0;

// Persistent pcap handle for high-performance sending
static pcap_t *g_send_handle = NULL;

/**
 * Initialize ethernet logger
 */
void ethernet_logger_init(void)
{
    if (g_logger_initialized) return;
    
    // Check LOG_QUIET environment variable (0 = enable console output)
    int console_enabled = (getenv("LOG_QUIET") != NULL && atoi(getenv("LOG_QUIET")) == 0) ? 1 : 0;
    
    int ret = logger_init(&g_ethernet_logger, "ETHERNET", "output/ethernet.log", 
                          LOG_LEVEL_DEBUG, console_enabled);
    if (ret == 0)
    {
        g_logger_initialized = 1;
        LOG_INFO(&g_ethernet_logger, "Ethernet logger initialized");
    }
}

/**
 * Close ethernet logger
 */
void ethernet_logger_close(void)
{
    // Close persistent pcap handle
    if (g_send_handle != NULL)
    {
        pcap_close(g_send_handle);
        g_send_handle = NULL;
    }
    
    if (g_logger_initialized)
    {
        LOG_INFO(&g_ethernet_logger, "Ethernet logger closing");
        logger_close(&g_ethernet_logger);
        g_logger_initialized = 0;
    }
}

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
 * Set the cached interface for sending
 */
void ethernet_send_set_interface(const char *ifname, const uint8_t *src_mac)
{
    if (ifname != NULL)
    {
        strncpy(g_selected_interface, ifname, IFNAMSIZ - 1);
        g_selected_interface[IFNAMSIZ - 1] = '\0';
    }
    if (src_mac != NULL)
    {
        memcpy(g_cached_src_mac, src_mac, 6);
    }
    g_interface_selected = 1;
    
    // Pre-open pcap handle for persistent sending
    if (g_send_handle == NULL && ifname != NULL)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        g_send_handle = pcap_open_live(ifname, 65536, 1, 10, errbuf);
        if (g_send_handle == NULL)
        {
            LOG_WARN(&g_ethernet_logger, "Failed to pre-open pcap handle: %s", errbuf);
        }
    }
}

/**
 * Get the cached interface name
 */
const char* ethernet_send_get_interface(void)
{
    if (g_interface_selected)
    {
        return g_selected_interface;
    }
    return NULL;
}

/**
 * Get the cached source MAC address
 */
int ethernet_send_get_src_mac(uint8_t *mac)
{
    if (g_interface_selected && mac != NULL)
    {
        memcpy(mac, g_cached_src_mac, 6);
        return 1;
    }
    return 0;
}

/**
 * Check if interface is already selected
 */
int ethernet_send_is_interface_selected(void)
{
    return g_interface_selected;
}

/**
 * Load Ethernet header into frame buffer
 */
void load_ethernet_header(uint8_t *buffer, uint8_t *dest_mac, uint8_t *src_mac, uint16_t ethernet_type)
{
    ethernet_header_t *header = (ethernet_header_t *)buffer;
    
    // Copy destination MAC address
    memcpy(header->dest_mac, dest_mac, 6);
    
    // Copy source MAC address
    memcpy(header->src_mac, src_mac, 6);
    
    // Set Ethernet type (convert to network byte order)
    header->ethernet_type = htons(ethernet_type);
}

/**
 * Load data into Ethernet frame and calculate CRC
 */
int load_ethernet_data(uint8_t *buffer, uint8_t *data, int data_len)
{
    // Check data length constraints
    if (data_len < ETHERNET_MIN_DATA_SIZE || data_len > ETHERNET_MAX_DATA_SIZE)
    {
        LOG_ERROR(&g_ethernet_logger, "Data size %d is out of range [%d, %d]", 
                  data_len, ETHERNET_MIN_DATA_SIZE, ETHERNET_MAX_DATA_SIZE);
        return -1;
    }
    
    // Copy data to buffer
    memcpy(buffer, data, data_len);
    
    // Calculate CRC32 for the data
    uint32_t crc = calculate_crc32(buffer, data_len);
    
    // Append CRC to the end of data (in little endian as per standard)
    memcpy(buffer + data_len, &crc, ETHERNET_CRC_SIZE);
    
    return data_len + ETHERNET_CRC_SIZE;
}

/**
 * Send Ethernet frame using libpcap
 */
int send_ethernet_frame(uint8_t *buffer, int frame_size)
{
    pcap_if_t *alldevs;
    pcap_if_t *device;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum, i = 0;
    
    // If interface is already selected, use persistent handle for speed
    if (g_interface_selected)
    {
        // Update source MAC in the frame buffer
        memcpy(buffer + 6, g_cached_src_mac, 6);
        
        // Use persistent handle if available, otherwise open new one
        if (g_send_handle != NULL)
        {
            // Fast path: use persistent handle
            if (pcap_sendpacket(g_send_handle, buffer, frame_size) != 0)
            {
                LOG_ERROR(&g_ethernet_logger, "Error sending packet: %s", pcap_geterr(g_send_handle));
                return -1;
            }
            LOG_DEBUG(&g_ethernet_logger, "Sent %d bytes via %s (persistent)", frame_size, g_selected_interface);
            return 1;
        }
        
        // Fallback: open new handle (slower)
        handle = pcap_open_live(g_selected_interface, 65536, 1, 10, errbuf);
        
        if (handle == NULL)
        {
            LOG_ERROR(&g_ethernet_logger, "Unable to open adapter %s", g_selected_interface);
            return -1;
        }
        
        // Send the packet
        if (pcap_sendpacket(handle, buffer, frame_size) != 0)
        {
            LOG_ERROR(&g_ethernet_logger, "Error sending packet: %s", pcap_geterr(handle));
            pcap_close(handle);
            return -1;
        }
        
        LOG_INFO(&g_ethernet_logger, "Sent %d bytes via %s", frame_size, g_selected_interface);
        
        // Cache this handle for future use
        g_send_handle = handle;
        return 1;
    }

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
    
    printf("\nSelected interface: %s\n", device->name);
    
    // Cache the selected interface name
    strncpy(g_selected_interface, device->name, IFNAMSIZ - 1);
    g_selected_interface[IFNAMSIZ - 1] = '\0';
    
    // Get source MAC address from selected interface
    uint8_t src_mac[6];
    if (get_interface_mac(device->name, src_mac) < 0)
    {
        LOG_ERROR(&g_ethernet_logger, "Failed to get MAC address for %s", device->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    LOG_INFO(&g_ethernet_logger, "Source MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
             src_mac[0], src_mac[1], src_mac[2], 
             src_mac[3], src_mac[4], src_mac[5]);
           
    // Cache the source MAC and set flag
    memcpy(g_cached_src_mac, src_mac, 6);
    g_interface_selected = 1;
    
    // Update source MAC in the frame buffer
    memcpy(buffer + 6, src_mac, 6);
    
    // Open the device
    handle = pcap_open_live(device->name,      // name of the device
                            65536,              // portion to capture (entire packet)
                            1,                  // promiscuous mode
                            1000,               // read timeout
                            errbuf);            // error buffer
    
    if (handle == NULL)
    {
        LOG_ERROR(&g_ethernet_logger, "Unable to open adapter %s", device->name);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    // Send the packet
    if (pcap_sendpacket(handle, buffer, frame_size) != 0)
    {
        LOG_ERROR(&g_ethernet_logger, "Error sending packet: %s", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    LOG_INFO(&g_ethernet_logger, "Sent %d bytes via %s", frame_size, device->name);
    
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    
    return 1;
}

/**
 * High-level function to encapsulate and send Ethernet frame
 */
int ethernet_send(uint8_t *data, int data_len, 
                  uint8_t *dest_mac, uint8_t *src_mac, uint16_t ethernet_type)
{
    uint8_t frame_buffer[MAX_FRAME_BUFFER_SIZE];
    int frame_size = 0;
    
    // Validate input data length
    if (data_len < ETHERNET_MIN_DATA_SIZE)
    {
        LOG_WARN(&g_ethernet_logger, "Data size %d < minimum %d, padding with zeros", 
                 data_len, ETHERNET_MIN_DATA_SIZE);
        
        // Pad with zeros
        uint8_t padded_data[ETHERNET_MIN_DATA_SIZE];
        memcpy(padded_data, data, data_len);
        memset(padded_data + data_len, 0, ETHERNET_MIN_DATA_SIZE - data_len);
        data = padded_data;
        data_len = ETHERNET_MIN_DATA_SIZE;
    }
    else if (data_len > ETHERNET_MAX_DATA_SIZE)
    {
        LOG_ERROR(&g_ethernet_logger, "Data size %d exceeds maximum %d", 
                  data_len, ETHERNET_MAX_DATA_SIZE);
        return -1;
    }
    
    // Load Ethernet header
    load_ethernet_header(frame_buffer, dest_mac, src_mac, ethernet_type);
    frame_size += ETHERNET_HEADER_SIZE;
    
    // Load data and CRC
    int data_crc_size = load_ethernet_data(frame_buffer + ETHERNET_HEADER_SIZE, data, data_len);
    if (data_crc_size < 0)
    {
        return -1;
    }
    frame_size += data_crc_size;
    
    // Send the frame
    return send_ethernet_frame(frame_buffer, frame_size);
}
