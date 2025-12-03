#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "../include/arp.h"
#include "../include/arp_send.h"
#include "../../common/include/logger.h"

#define DEFAULT_LOCAL_IP    "192.168.1.100"
#define DEFAULT_SUBNET_MASK "255.255.255.0"
#define DEFAULT_GATEWAY_IP  "192.168.1.1"

static volatile int g_running = 1;

/* Use the global ARP logger from arp_send.c */
extern logger_t g_arp_logger;

void signal_handler(int sig)
{
    (void)sig;
    LOG_INFO(&g_arp_logger, "Received signal, exiting...");
    g_running = 0;
}

void print_usage(const char *program)
{
    printf("\nUsage: %s [options]\n", program);
    printf("\nOptions:\n");
    printf("  -l <ip>    Local IP address (default: %s)\n", DEFAULT_LOCAL_IP);
    printf("  -m <mask>  Subnet mask (default: %s)\n", DEFAULT_SUBNET_MASK);
    printf("  -g <ip>    Gateway IP address (default: %s)\n", DEFAULT_GATEWAY_IP);
    printf("  -t <ip>    Target IP to resolve\n");
    printf("  -h         Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -t 192.168.1.200\n", program);
    printf("  %s -l 192.168.1.100 -m 255.255.255.0 -g 192.168.1.1 -t 192.168.1.200\n", program);
    printf("\n");
}

int main(int argc, char *argv[])
{
    network_config_t config;
    arp_cache_t cache;
    const char *local_ip = DEFAULT_LOCAL_IP;
    const char *subnet_mask = DEFAULT_SUBNET_MASK;
    const char *gateway_ip = DEFAULT_GATEWAY_IP;
    const char *target_ip = NULL;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-l") == 0 && i + 1 < argc)
        {
            local_ip = argv[++i];
        }
        else if (strcmp(argv[i], "-m") == 0 && i + 1 < argc)
        {
            subnet_mask = argv[++i];
        }
        else if (strcmp(argv[i], "-g") == 0 && i + 1 < argc)
        {
            gateway_ip = argv[++i];
        }
        else if (strcmp(argv[i], "-t") == 0 && i + 1 < argc)
        {
            target_ip = argv[++i];
        }
        else if (strcmp(argv[i], "-h") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    // Check if target IP is provided
    if (target_ip == NULL)
    {
        printf("Error: Target IP address is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize ARP logger
    arp_logger_init();
    logger_set_role(&g_arp_logger, LOG_ROLE_SEND);
    
    LOG_INFO(&g_arp_logger, "========================================");
    LOG_INFO(&g_arp_logger, "       ARP Protocol - SENDER");
    LOG_INFO(&g_arp_logger, "========================================");
    
    // Initialize configuration
    memset(&config, 0, sizeof(config));
    ip_str_to_bytes(local_ip, config.local_ip);
    ip_str_to_bytes(subnet_mask, config.subnet_mask);
    ip_str_to_bytes(gateway_ip, config.gateway_ip);
    config.dhcp_flag = 0;
    
    LOG_INFO(&g_arp_logger, "Configuration:");
    LOG_INFO(&g_arp_logger, "  Local IP:     %s (will be updated from interface)", local_ip);
    LOG_INFO(&g_arp_logger, "  Subnet Mask:  %s", subnet_mask);
    LOG_INFO(&g_arp_logger, "  Gateway IP:   %s", gateway_ip);
    LOG_INFO(&g_arp_logger, "  Target IP:    %s", target_ip);
    
    // Initialize ARP cache
    arp_cache_init(&cache);
    
    // Resolve target IP to MAC
    uint8_t target_ip_bytes[4];
    uint8_t result_mac[6];
    
    ip_str_to_bytes(target_ip, target_ip_bytes);
    
    LOG_INFO(&g_arp_logger, "========================================");
    LOG_INFO(&g_arp_logger, "Starting ARP resolution for %s", target_ip);
    LOG_INFO(&g_arp_logger, "========================================");
    
    if (arp_get_mac(&config, &cache, target_ip_bytes, result_mac))
    {
        char mac_str[18];
        mac_bytes_to_str(result_mac, mac_str);
        
        LOG_INFO(&g_arp_logger, "========================================");
        LOG_INFO(&g_arp_logger, "        ARP Resolution SUCCESS");
        LOG_INFO(&g_arp_logger, "========================================");
        LOG_INFO(&g_arp_logger, "  IP Address:  %s", target_ip);
        LOG_INFO(&g_arp_logger, "  MAC Address: %s", mac_str);
        LOG_INFO(&g_arp_logger, "========================================");
        
        // Display final cache state
        arp_cache_display(&cache);
        
        arp_logger_close();
        return 0;
    }
    else
    {
        LOG_ERROR(&g_arp_logger, "========================================");
        LOG_ERROR(&g_arp_logger, "        ARP Resolution FAILED");
        LOG_ERROR(&g_arp_logger, "========================================");
        LOG_ERROR(&g_arp_logger, "  Could not resolve %s", target_ip);
        LOG_ERROR(&g_arp_logger, "  Possible reasons:");
        LOG_ERROR(&g_arp_logger, "    - Host is offline or unreachable");
        LOG_ERROR(&g_arp_logger, "    - Network interface misconfigured");
        LOG_ERROR(&g_arp_logger, "    - Firewall blocking ARP packets");
        LOG_ERROR(&g_arp_logger, "========================================");
        
        arp_logger_close();
        return 1;
    }
}
