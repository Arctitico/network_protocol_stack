/**
 * UDP Client - Network Protocol Stack Test
 * 
 * This program demonstrates the UDP protocol implementation
 * as a client that sends UDP datagrams.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pcap.h>

#include "../include/udp.h"
#include "../include/udp_send.h"
#include "../include/udp_recv.h"
#include "../../ip/include/ip.h"
#include "../../ip/include/ip_send.h"
#include "../../arp/include/arp.h"
#include "../../arp/include/arp_send.h"
#include "../../ethernet/include/ethernet.h"
#include "../../ethernet/include/ethernet_send.h"
#include "../../common/include/logger.h"

/* External loggers */
extern logger_t g_udp_logger;
extern logger_t g_ip_logger;
extern logger_t g_arp_logger;
extern logger_t g_ethernet_logger;

#define DEFAULT_PORT 5050
#define DEFAULT_DATA_FILE "data/input.txt"

/* Get IP address of interface */
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

/* Get netmask of interface */
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

/* Select network interface */
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
        fprintf(stderr, "No interfaces found!\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    printf("\nEnter the interface number (1-%d): ", i);
    if (scanf("%d", &inum) != 1 || inum < 1 || inum > i)
    {
        fprintf(stderr, "Invalid selection\n");
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
    int dest_port = DEFAULT_PORT;
    const char *data_file = DEFAULT_DATA_FILE;
    char dest_ip[INET_ADDRSTRLEN] = {0};
    
    char selected_if[IFNAMSIZ] = {0};
    char local_ip[INET_ADDRSTRLEN] = {0};
    char subnet_mask[INET_ADDRSTRLEN] = {0};
    char gateway_ip[INET_ADDRSTRLEN] = {0};
    
    network_config_t net_config;
    arp_cache_t arp_cache;
    uint8_t dest_mac[6];
    
    /* Parse command line arguments */
    if (argc > 1) data_file = argv[1];
    if (argc > 2) dest_port = atoi(argv[2]);
    
    /* Initialize all loggers */
    ethernet_logger_init();
    arp_logger_init();
    ip_logger_init();
    udp_logger_init();
    
    /* Set role for all loggers */
    logger_set_role(&g_ethernet_logger, LOG_ROLE_SEND);
    logger_set_role(&g_arp_logger, LOG_ROLE_SEND);
    logger_set_role(&g_ip_logger, LOG_ROLE_SEND);
    logger_set_role(&g_udp_logger, LOG_ROLE_SEND);
    
    printf("========================================\n");
    printf("       UDP Client - Protocol Stack\n");
    printf("========================================\n");
    
    /* Step 1: Select network interface */
    printf("\nStep 1: Select network interface\n");
    if (select_interface(selected_if, sizeof(selected_if)) < 0)
    {
        goto cleanup;
    }
    printf("Selected: %s\n", selected_if);
    
    /* Step 2: Get interface IP automatically */
    if (get_interface_ip(selected_if, local_ip, sizeof(local_ip)) < 0)
    {
        fprintf(stderr, "Could not get IP for %s\n", selected_if);
        goto cleanup;
    }
    printf("Local IP: %s\n", local_ip);
    
    /* Step 3: Get netmask */
    if (get_interface_netmask(selected_if, subnet_mask, sizeof(subnet_mask)) < 0)
    {
        strcpy(subnet_mask, "255.255.255.0");
    }
    
    /* Step 4: Calculate default gateway */
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
    
    /* Step 5: Get destination IP from user */
    printf("\nStep 2: Enter destination IP address: ");
    if (scanf("%s", dest_ip) != 1)
    {
        fprintf(stderr, "Invalid input\n");
        goto cleanup;
    }
    
    printf("\n========================================\n");
    printf("Client Configuration:\n");
    printf("  Interface:   %s\n", selected_if);
    printf("  Local IP:    %s\n", local_ip);
    printf("  Dest IP:     %s\n", dest_ip);
    printf("  Dest Port:   %d\n", dest_port);
    printf("  Data File:   %s\n", data_file);
    printf("  Subnet Mask: %s\n", subnet_mask);
    printf("  Gateway:     %s\n", gateway_ip);
    printf("========================================\n");
    
    /* Initialize network configuration */
    memset(&net_config, 0, sizeof(net_config));
    ip_str_to_bytes(local_ip, net_config.local_ip);
    ip_str_to_bytes(subnet_mask, net_config.subnet_mask);
    ip_str_to_bytes(gateway_ip, net_config.gateway_ip);
    net_config.dhcp_flag = 0;
    
    /* Get and set MAC address */
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
    
    /* Initialize ARP cache */
    arp_cache_init(&arp_cache);
    
    /* Resolve destination MAC using ARP */
    printf("\nResolving MAC address for %s using ARP...\n", dest_ip);
    
    uint8_t dest_ip_bytes[4];
    ip_str_to_bytes(dest_ip, dest_ip_bytes);
    
    if (!arp_get_mac(&net_config, &arp_cache, dest_ip_bytes, dest_mac))
    {
        fprintf(stderr, "Failed to resolve MAC address for %s\n", dest_ip);
        fprintf(stderr, "Make sure the server is running!\n");
        goto cleanup;
    }
    
    printf("Resolved MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           dest_mac[0], dest_mac[1], dest_mac[2],
           dest_mac[3], dest_mac[4], dest_mac[5]);
    
    /* Create UDP socket */
    int sockid = udp_socket(AF_INET, SOCK_DGRAM, 0);
    if (sockid == INVALID_SOCKET_CUSTOM)
    {
        fprintf(stderr, "Failed to create socket\n");
        goto cleanup;
    }
    
    /* Bind socket to local address (optional for client, but we do it for proper five-tuple) */
    sockaddr_in_custom_t local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(0);  // Let system choose port
    inet_pton(AF_INET, local_ip, &local_addr.sin_addr);
    
    /* Note: We don't bind client socket, it will use ephemeral port */
    
    /* Open file to get total size */
    FILE *fp = fopen(data_file, "rb");
    if (fp == NULL)
    {
        fprintf(stderr, "Failed to open data file: %s\n", data_file);
        /* Use default message */
        const char *default_msg = "Hello from UDP client! This is a test message.";
        
        sockaddr_in_custom_t dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(dest_port);
        inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);
        
        udp_socket_t *sock = get_udp_socket(sockid);
        if (sock != NULL)
        {
            strncpy(sock->local_address, local_ip, sizeof(sock->local_address) - 1);
        }
        
        printf("Using default message (%lu bytes)\n", strlen(default_msg));
        udp_sendto(sockid, (uint8_t *)default_msg, strlen(default_msg), 0,
                   &dest_addr, sizeof(dest_addr), dest_mac);
        goto cleanup;
    }
    
    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    printf("\nFile: %s (Total: %ld bytes)\n", data_file, file_size);
    
    /* Prepare destination address */
    sockaddr_in_custom_t dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr);
    
    /* Update socket local address for sending */
    udp_socket_t *sock = get_udp_socket(sockid);
    if (sock != NULL)
    {
        strncpy(sock->local_address, local_ip, sizeof(sock->local_address) - 1);
    }
    
    /* Calculate chunk size (IP_MAX_DATA_SIZE - UDP_HEADER_SIZE) */
    #define CHUNK_SIZE 1392  // Safe size: 1400 - 8 (UDP header)
    uint8_t send_buffer[CHUNK_SIZE];
    int total_sent = 0;
    int chunk_num = 0;
    
    printf("\n========================================\n");
    printf("Sending file in chunks...\n");
    printf("  To:         %s:%d\n", dest_ip, dest_port);
    printf("  Total size: %ld bytes\n", file_size);
    printf("  Chunk size: %d bytes\n", CHUNK_SIZE);
    printf("========================================\n\n");
    
    /* Send file in chunks */
    while (!feof(fp))
    {
        int data_len = fread(send_buffer, 1, CHUNK_SIZE, fp);
        if (data_len <= 0) break;
        
        chunk_num++;
        
        /* Send this chunk */
        int sent = udp_sendto(sockid, send_buffer, data_len, 0,
                              &dest_addr, sizeof(dest_addr), dest_mac);
        
        if (sent < 0)
        {
            fprintf(stderr, "Failed to send chunk #%d\n", chunk_num);
            break;
        }
        
        total_sent += sent;
        
        // Print progress (compact for large files)
        if (chunk_num == 1 || chunk_num % 20 == 0 || total_sent == file_size)
        {
            printf("  Chunk #%-3d: %4d bytes sent (Total: %d/%ld)\n", 
                   chunk_num, sent, total_sent, file_size);
        }
        
        // Minimal delay only for very large transfers to avoid buffer overflow
        // Reduced from 1000us to 100us for better performance
        if (chunk_num % 50 == 0)
        {
            usleep(100);
        }
    }
    
    fclose(fp);
    
    if (total_sent == file_size)
    {
        printf("\n========================================\n");
        printf("Successfully sent entire file!\n");
        printf("  Total: %d bytes in %d chunks\n", total_sent, chunk_num);
        printf("========================================\n");
    }
    else
    {
        printf("\n========================================\n");
        printf("Warning: Sent %d/%ld bytes\n", total_sent, file_size);
        printf("========================================\n");
    }
    
    /* Close socket */
    udp_closesocket(sockid);
    
cleanup:
    /* Display ARP cache */
    arp_cache_display(&arp_cache);
    
    /* Close all loggers */
    udp_logger_close();
    ip_logger_close();
    arp_logger_close();
    ethernet_logger_close();
    
    printf("\nClient shutdown complete.\n");
    return 0;
}
