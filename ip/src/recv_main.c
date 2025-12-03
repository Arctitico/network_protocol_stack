#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include "../include/ip.h"
#include "../include/ip_recv.h"
#include "../include/ip_send.h"
#include "../../arp/include/arp.h"
#include "../../arp/include/arp_recv.h"
#include "../../arp/include/arp_send.h"
#include "../../ethernet/include/ethernet_send.h"
#include "../../common/include/logger.h"

/* Use the global loggers from each layer */
extern logger_t g_ip_logger;
extern logger_t g_arp_logger;
extern logger_t g_ethernet_logger;

#define DEFAULT_OUTPUT_FILE "output/received_data.txt"

// Get IP address of interface
static int get_interface_ip(const char *ifname, char *ip_str, size_t len)
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sock < 0) return -1;
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0)
    {
        close(sock);
        return -1;
    }
    
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_str, len);
    close(sock);
    return 0;
}

// Get netmask of interface  
static int get_interface_netmask(const char *ifname, char *mask_str, size_t len)
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (sock < 0) return -1;
    
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0)
    {
        close(sock);
        return -1;
    }
    
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &addr->sin_addr, mask_str, len);
    close(sock);
    return 0;
}

// Select network interface and return its name
static int select_interface(char *ifname, size_t len)
{
    pcap_if_t *alldevs, *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0, inum;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        LOG_ERROR(&g_ip_logger, "Error finding devices: %s", errbuf);
        return -1;
    }
    
    // User interaction - keep printf
    printf("\n=== Available Network Interfaces ===\n");
    for (device = alldevs; device != NULL; device = device->next)
    {
        char ip[INET_ADDRSTRLEN] = "N/A";
        get_interface_ip(device->name, ip, sizeof(ip));
        printf("%d. %s (IP: %s)\n", ++i, device->name, ip);
    }
    
    if (i == 0)
    {
        LOG_ERROR(&g_ip_logger, "No interfaces found!");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nEnter the interface number (1-%d): ", i);
    if (scanf("%d", &inum) != 1 || inum < 1 || inum > i)
    {
        LOG_ERROR(&g_ip_logger, "Invalid selection");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    for (device = alldevs, i = 0; i < inum - 1; device = device->next, i++);
    strncpy(ifname, device->name, len - 1);
    ifname[len - 1] = '\0';
    
    pcap_freealldevs(alldevs);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *output_file = DEFAULT_OUTPUT_FILE;
    
    char selected_if[IFNAMSIZ] = {0};
    char local_ip[INET_ADDRSTRLEN] = {0};
    char subnet_mask[INET_ADDRSTRLEN] = {0};
    char gateway_ip[INET_ADDRSTRLEN] = {0};
    
    // Network configuration for ARP
    network_config_t net_config;
    arp_cache_t arp_cache;
    
    // Parse command line arguments
    if (argc > 1) output_file = argv[1];
    
    // Initialize loggers for all layers
    ethernet_logger_init();
    arp_logger_init();
    ip_logger_init();
    
    // Set role for all loggers
    logger_set_role(&g_ethernet_logger, LOG_ROLE_RECV);
    logger_set_role(&g_arp_logger, LOG_ROLE_RECV);
    logger_set_role(&g_ip_logger, LOG_ROLE_RECV);
    
    LOG_INFO(&g_ip_logger, "========================================");
    LOG_INFO(&g_ip_logger, "     IP Network Layer - RECEIVER");
    LOG_INFO(&g_ip_logger, "       (with ARP Integration)");
    LOG_INFO(&g_ip_logger, "========================================");
    
    // Step 1: Select network interface
    LOG_INFO(&g_ip_logger, "Step 1: Select network interface");
    if (select_interface(selected_if, sizeof(selected_if)) < 0)
    {
        ip_logger_close();
        arp_logger_close();
        return 1;
    }
    LOG_INFO(&g_ip_logger, "Selected: %s", selected_if);
    
    // Step 2: Get interface IP automatically
    if (get_interface_ip(selected_if, local_ip, sizeof(local_ip)) < 0)
    {
        LOG_WARN(&g_ip_logger, "Could not get IP for %s, using 0.0.0.0", selected_if);
        strcpy(local_ip, "0.0.0.0");
    }
    LOG_INFO(&g_ip_logger, "Local IP: %s", local_ip);
    
    // Step 3: Get netmask
    if (get_interface_netmask(selected_if, subnet_mask, sizeof(subnet_mask)) < 0)
    {
        strcpy(subnet_mask, "255.255.255.0");
    }
    LOG_INFO(&g_ip_logger, "Subnet Mask: %s", subnet_mask);
    
    // Step 4: Calculate default gateway (assume x.x.x.1)
    {
        uint8_t ip_bytes[4], mask_bytes[4];
        ip_str_to_bytes(local_ip, ip_bytes);
        ip_str_to_bytes(subnet_mask, mask_bytes);
        uint8_t gw_bytes[4];
        gw_bytes[0] = ip_bytes[0] & mask_bytes[0];
        gw_bytes[1] = ip_bytes[1] & mask_bytes[1];
        gw_bytes[2] = ip_bytes[2] & mask_bytes[2];
        gw_bytes[3] = 1;
        snprintf(gateway_ip, sizeof(gateway_ip), "%d.%d.%d.%d",
                 gw_bytes[0], gw_bytes[1], gw_bytes[2], gw_bytes[3]);
    }
    LOG_INFO(&g_ip_logger, "Gateway IP: %s", gateway_ip);
    
    LOG_INFO(&g_ip_logger, "========================================");
    LOG_INFO(&g_ip_logger, "Configuration Summary:");
    LOG_INFO(&g_ip_logger, "  Interface:    %s", selected_if);
    LOG_INFO(&g_ip_logger, "  Output file:  %s", output_file);
    LOG_INFO(&g_ip_logger, "  Local IP:     %s", local_ip);
    LOG_INFO(&g_ip_logger, "  Subnet Mask:  %s", subnet_mask);
    LOG_INFO(&g_ip_logger, "  Gateway IP:   %s", gateway_ip);
    LOG_INFO(&g_ip_logger, "========================================");
    
    // Initialize ARP with real interface info
    memset(&net_config, 0, sizeof(net_config));
    ip_str_to_bytes(local_ip, net_config.local_ip);
    ip_str_to_bytes(subnet_mask, net_config.subnet_mask);
    ip_str_to_bytes(gateway_ip, net_config.gateway_ip);
    net_config.dhcp_flag = 0;
    
    // Pre-set the interface for ethernet_send (for ARP replies)
    uint8_t local_mac[6];
    {
        struct ifreq ifr;
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        strncpy(ifr.ifr_name, selected_if, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
        {
            memcpy(local_mac, ifr.ifr_hwaddr.sa_data, 6);
            memcpy(net_config.local_mac, local_mac, 6);
            ethernet_send_set_interface(selected_if, local_mac);
            LOG_INFO(&g_ip_logger, "Local MAC: %02X:%02X:%02X:%02X:%02X:%02X",
                     local_mac[0], local_mac[1], local_mac[2],
                     local_mac[3], local_mac[4], local_mac[5]);
        }
        close(sock);
    }
    
    arp_cache_init(&arp_cache);
    
    LOG_INFO(&g_ip_logger, "Waiting for IP packets on %s (IP: %s)...", selected_if, local_ip);
    LOG_INFO(&g_ip_logger, "Press Ctrl+C to stop");
    
    printf("\nWaiting for IP packets...\n");
    
    // Start integrated network stack (Ethernet + IP + ARP)
    int result = network_stack_receive(local_ip, output_file, &net_config, &arp_cache, 0);
    
    if (result < 0)
    {
        LOG_ERROR(&g_ip_logger, "Error occurred while receiving packets");
        ip_logger_close();
        arp_logger_close();
        return 1;
    }
    
    LOG_INFO(&g_ip_logger, "========================================");
    LOG_INFO(&g_ip_logger, "Network stack receiver stopped");
    LOG_INFO(&g_ip_logger, "========================================");
    
    // Display final ARP cache
    arp_cache_display(&arp_cache);
    
    ip_logger_close();
    arp_logger_close();
    ethernet_logger_close();
    return 0;
}
