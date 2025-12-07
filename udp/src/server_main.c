/**
 * UDP Server - Network Protocol Stack Test
 * 
 * This program demonstrates the UDP protocol implementation
 * as a server that receives UDP datagrams.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
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
#include "../../ip/include/ip_recv.h"
#include "../../ip/include/ip_send.h"
#include "../../arp/include/arp.h"
#include "../../arp/include/arp_recv.h"
#include "../../arp/include/arp_send.h"
#include "../../ethernet/include/ethernet.h"
#include "../../ethernet/include/ethernet_send.h"
#include "../../ethernet/include/ethernet_recv.h"
#include "../../icmp/include/icmp_recv.h"
#include "../../common/include/logger.h"

/* External loggers */
extern logger_t g_udp_logger;
extern logger_t g_ip_logger;
extern logger_t g_arp_logger;
extern logger_t g_ethernet_logger;

#define DEFAULT_PORT 5050

/* Signal handler - stop pcap loop */
static void signal_handler(int sig)
{
    (void)sig;
    printf("\n\nReceived Ctrl+C, stopping capture...\n");
    ethernet_stop_capture();
}

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
    int server_port = DEFAULT_PORT;
    char selected_if[IFNAMSIZ] = {0};
    char local_ip[INET_ADDRSTRLEN] = {0};
    char subnet_mask[INET_ADDRSTRLEN] = {0};
    char gateway_ip[INET_ADDRSTRLEN] = {0};
    
    network_config_t net_config;
    arp_cache_t arp_cache;
    
    /* Parse command line arguments */
    if (argc > 1) server_port = atoi(argv[1]);
    
    /* Set up signal handler for Ctrl+C */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Initialize all loggers */
    ethernet_logger_init();
    arp_logger_init();
    ip_logger_init();
    udp_logger_init();
    
    /* Set role for all loggers */
    logger_set_role(&g_ethernet_logger, LOG_ROLE_RECV);
    logger_set_role(&g_arp_logger, LOG_ROLE_RECV);
    logger_set_role(&g_ip_logger, LOG_ROLE_RECV);
    logger_set_role(&g_udp_logger, LOG_ROLE_RECV);
    
    printf("\n========================================\n");
    printf("  UDP Server - Protocol Stack\n");
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
    
    printf("\n========================================\n");
    printf("  Server Configuration\n");
    printf("========================================\n");
    printf("    Interface:   %s\n", selected_if);
    printf("    Local IP:    %s\n", local_ip);
    printf("    Port:        %d\n", server_port);
    printf("    Subnet Mask: %s\n", subnet_mask);
    printf("    Gateway:     %s\n", gateway_ip);
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
    
    /* Initialize UDP receive subsystem */
    udp_recv_init();
    
    /* Create UDP socket */
    int sockid = udp_socket(AF_INET, SOCK_DGRAM, 0);
    if (sockid == INVALID_SOCKET_CUSTOM)
    {
        fprintf(stderr, "Failed to create socket\n");
        goto cleanup;
    }
    
    /* Bind to local address and port */
    sockaddr_in_custom_t server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    inet_pton(AF_INET, local_ip, &server_addr.sin_addr);
    
    if (udp_bind(sockid, &server_addr, sizeof(server_addr)) == SOCKET_ERROR_CUSTOM)
    {
        fprintf(stderr, "Failed to bind socket\n");
        udp_closesocket(sockid);
        goto cleanup;
    }
    
    printf("\n========================================\n");
    printf("  UDP Server listening on %s:%d\n", local_ip, server_port);
    printf("  Press Ctrl+C to stop\n");
    printf("  Received data will be saved to output/ directory\n");
    printf("========================================\n\n");
    
    printf("Waiting for UDP packets...\n\n");
    
    /* Start network stack receiver - this blocks until Ctrl+C */
    int result = network_stack_receive(local_ip, "output/udp_data.bin",
                                       &net_config, &arp_cache, 0);
    
    if (result < 0)
    {
        fprintf(stderr, "Network stack error\n");
    }
    
    /* Close socket */
    udp_closesocket(sockid);
    
cleanup:
    printf("\n\n");  // End the progress dots line
    
    /* Print file transfer summary */
    udp_recv_print_summary();
    
    printf("========================================\n");
    printf("  Server Shutdown\n");
    printf("========================================\n\n");
    
    /* Display ARP cache */
    arp_cache_display(&arp_cache);
    
    /* Close all loggers */
    udp_logger_close();
    ip_logger_close();
    arp_logger_close();
    ethernet_logger_close();
    icmp_logger_close();
    
    printf("\nServer shutdown complete.\n");
    printf("Check output/ directory for received data files.\n");
    return 0;
}
