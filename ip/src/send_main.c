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
#include "ip_send.h"
#include "../../arp/include/arp.h"
#include "../../arp/include/arp_send.h"
#include "../../ethernet/include/ethernet_send.h"

#define DEFAULT_INPUT_FILE "data/input.txt"
#define DEFAULT_DEST_IP "auto"  // Will be prompted
#define DEFAULT_SUBNET_MASK "255.255.255.0"
#define DEFAULT_GATEWAY_IP "auto"  // Will use x.x.x.1
#define DEFAULT_PROTOCOL IP_PROTO_TCP

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
    const char *input_file = DEFAULT_INPUT_FILE;
    uint8_t protocol = DEFAULT_PROTOCOL;
    uint8_t dest_mac[6];
    
    char selected_if[IFNAMSIZ] = {0};
    char src_ip[INET_ADDRSTRLEN] = {0};
    char dest_ip[INET_ADDRSTRLEN] = {0};
    char subnet_mask[INET_ADDRSTRLEN] = {0};
    char gateway_ip[INET_ADDRSTRLEN] = {0};
    
    // Network configuration for ARP
    network_config_t net_config;
    arp_cache_t arp_cache;
    
    // Parse command line arguments
    if (argc > 1) input_file = argv[1];
    if (argc > 2) protocol = (uint8_t)atoi(argv[2]);
    
    printf("========================================\n");
    printf("      IP Network Layer - SENDER\n");
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
    if (get_interface_ip(selected_if, src_ip, sizeof(src_ip)) < 0)
    {
        fprintf(stderr, "Warning: Could not get IP for %s, using 0.0.0.0\n", selected_if);
        strcpy(src_ip, "0.0.0.0");
    }
    printf("Source IP: %s\n", src_ip);
    
    // Step 3: Get netmask
    if (get_interface_netmask(selected_if, subnet_mask, sizeof(subnet_mask)) < 0)
    {
        strcpy(subnet_mask, "255.255.255.0");
    }
    printf("Subnet Mask: %s\n", subnet_mask);
    
    // Step 4: Calculate default gateway (assume x.x.x.1)
    {
        uint8_t ip_bytes[4], mask_bytes[4];
        ip_str_to_bytes(src_ip, ip_bytes);
        ip_str_to_bytes(subnet_mask, mask_bytes);
        uint8_t gw_bytes[4];
        gw_bytes[0] = ip_bytes[0] & mask_bytes[0];
        gw_bytes[1] = ip_bytes[1] & mask_bytes[1];
        gw_bytes[2] = ip_bytes[2] & mask_bytes[2];
        gw_bytes[3] = 1;  // Gateway is usually .1
        snprintf(gateway_ip, sizeof(gateway_ip), "%d.%d.%d.%d",
                 gw_bytes[0], gw_bytes[1], gw_bytes[2], gw_bytes[3]);
    }
    printf("Gateway IP: %s\n", gateway_ip);
    
    // Step 5: Ask for destination IP
    printf("\nStep 2: Enter destination IP address: ");
    if (scanf("%s", dest_ip) != 1)
    {
        fprintf(stderr, "Invalid input\n");
        return 1;
    }
    
    printf("\n========================================\n");
    printf("Configuration Summary:\n");
    printf("  Interface:    %s\n", selected_if);
    printf("  Input file:   %s\n", input_file);
    printf("  Source IP:    %s\n", src_ip);
    printf("  Dest IP:      %s\n", dest_ip);
    printf("  Subnet Mask:  %s\n", subnet_mask);
    printf("  Gateway IP:   %s\n", gateway_ip);
    printf("  Protocol:     %d\n", protocol);
    printf("========================================\n");
    
    // Initialize ARP with real interface info
    memset(&net_config, 0, sizeof(net_config));
    ip_str_to_bytes(src_ip, net_config.local_ip);
    ip_str_to_bytes(subnet_mask, net_config.subnet_mask);
    ip_str_to_bytes(gateway_ip, net_config.gateway_ip);
    net_config.dhcp_flag = 0;
    
    // Pre-set the interface for ethernet_send
    uint8_t src_mac[6];
    {
        struct ifreq ifr;
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        strncpy(ifr.ifr_name, selected_if, IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
        {
            memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6);
            memcpy(net_config.local_mac, src_mac, 6);
            ethernet_send_set_interface(selected_if, src_mac);
        }
        close(sock);
    }
    
    arp_cache_init(&arp_cache);
    
    // Resolve destination MAC address using ARP
    printf("\nResolving MAC address for %s using ARP...\n", dest_ip);
    
    uint8_t dest_ip_bytes[4];
    ip_str_to_bytes(dest_ip, dest_ip_bytes);
    
    if (!arp_get_mac(&net_config, &arp_cache, dest_ip_bytes, dest_mac))
    {
        fprintf(stderr, "\nFailed to resolve MAC address for %s\n", dest_ip);
        fprintf(stderr, "Make sure the destination host is running ip_recv\n");
        return 1;
    }
    
    char mac_str[18];
    mac_bytes_to_str(dest_mac, mac_str);
    printf("Resolved: %s -> %s\n", dest_ip, mac_str);
    
    // Read data from input file (simulating transport layer)
    FILE *fp = fopen(input_file, "rb");
    if (fp == NULL)
    {
        perror("Error opening input file");
        fprintf(stderr, "\nUsage: %s [input] [src_ip] [dest_ip] [protocol] [subnet_mask] [gateway_ip]\n", argv[0]);
        fprintf(stderr, "Example: %s data/input.txt 192.168.1.100 192.168.1.200 6\n", argv[0]);
        fprintf(stderr, "         %s data/input.txt 192.168.1.100 8.8.8.8 6 255.255.255.0 192.168.1.1\n\n", argv[0]);
        return 1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (file_size == 0)
    {
        fprintf(stderr, "Error: Input file is empty\n");
        fclose(fp);
        return 1;
    }
    
    if (file_size > IP_MAX_PACKET_SIZE)
    {
        fprintf(stderr, "Error: File too large (%ld bytes > %d bytes max)\n",
                file_size, IP_MAX_PACKET_SIZE);
        fclose(fp);
        return 1;
    }
    
    // Read data
    uint8_t *data = (uint8_t *)malloc(file_size);
    if (data == NULL)
    {
        perror("Memory allocation failed");
        fclose(fp);
        return 1;
    }
    
    size_t read_len = fread(data, 1, file_size, fp);
    fclose(fp);
    
    if (read_len != (size_t)file_size)
    {
        fprintf(stderr, "Error: Failed to read complete file\n");
        free(data);
        return 1;
    }
    
    printf("Read %ld bytes from input file\n", file_size);
    
    // Send IP packet via Ethernet layer
    int result = ip_send(data, (int)file_size, protocol, src_ip, dest_ip, dest_mac);
    
    free(data);
    
    if (result < 0)
    {
        fprintf(stderr, "\nFailed to send IP packet\n");
        return 1;
    }
    
    printf("\n========================================\n");
    printf("IP packet(s) sent successfully!\n");
    printf("========================================\n");
    
    return 0;
}
