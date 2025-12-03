#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>
#include "ip.h"
#include "ip_recv.h"
#include "../../arp/include/arp.h"
#include "../../arp/include/arp_recv.h"
#include "../../arp/include/arp_send.h"
#include "../../ethernet/include/ethernet_send.h"

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
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    printf("\n=== Available Network Interfaces ===\n");
    for (device = alldevs; device != NULL; device = device->next)
    {
        char ip[INET_ADDRSTRLEN] = "N/A";
        get_interface_ip(device->name, ip, sizeof(ip));
        printf("%d. %s (IP: %s)\n", ++i, device->name, ip);
    }
    
    if (i == 0)
    {
        printf("No interfaces found!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nEnter the interface number (1-%d): ", i);
    if (scanf("%d", &inum) != 1 || inum < 1 || inum > i)
    {
        printf("Invalid selection\n");
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
    
    printf("========================================\n");
    printf("     IP Network Layer - RECEIVER\n");
    printf("       (with ARP Integration)\n");
    printf("========================================\n");
    
    // Step 1: Select network interface
    printf("\nStep 1: Select network interface\n");
    if (select_interface(selected_if, sizeof(selected_if)) < 0)
    {
        return 1;
    }
    printf("Selected: %s\n", selected_if);
    
    // Step 2: Get interface IP automatically
    if (get_interface_ip(selected_if, local_ip, sizeof(local_ip)) < 0)
    {
        fprintf(stderr, "Warning: Could not get IP for %s, using 0.0.0.0\n", selected_if);
        strcpy(local_ip, "0.0.0.0");
    }
    printf("Local IP: %s\n", local_ip);
    
    // Step 3: Get netmask
    if (get_interface_netmask(selected_if, subnet_mask, sizeof(subnet_mask)) < 0)
    {
        strcpy(subnet_mask, "255.255.255.0");
    }
    printf("Subnet Mask: %s\n", subnet_mask);
    
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
    printf("Gateway IP: %s\n", gateway_ip);
    
    printf("\n========================================\n");
    printf("Configuration Summary:\n");
    printf("  Interface:    %s\n", selected_if);
    printf("  Output file:  %s\n", output_file);
    printf("  Local IP:     %s\n", local_ip);
    printf("  Subnet Mask:  %s\n", subnet_mask);
    printf("  Gateway IP:   %s\n", gateway_ip);
    printf("========================================\n");
    
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
            printf("Local MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   local_mac[0], local_mac[1], local_mac[2],
                   local_mac[3], local_mac[4], local_mac[5]);
        }
        close(sock);
    }
    
    arp_cache_init(&arp_cache);
    
    // Set ARP context for IP receiver
    ip_recv_set_arp_context(&net_config, &arp_cache);
    
    printf("\nWaiting for IP packets on %s (IP: %s)...\n", selected_if, local_ip);
    printf("Press Ctrl+C to stop\n\n");
    
    // Receive and process IP packet via Ethernet layer
    int result = ip_receive(local_ip, output_file);
    
    if (result < 0)
    {
        fprintf(stderr, "\nError occurred while receiving IP packet\n");
        return 1;
    }
    
    printf("\n========================================\n");
    printf("IP receiver stopped\n");
    printf("========================================\n");
    
    // Display final ARP cache
    arp_cache_display(&arp_cache);
    
    return 0;
}
