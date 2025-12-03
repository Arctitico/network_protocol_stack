#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "../include/arp.h"
#include "../include/arp_recv.h"
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
    printf("  -l <ip>    Local IP address (default: auto-detect from interface)\n");
    printf("  -m <mask>  Subnet mask (default: %s)\n", DEFAULT_SUBNET_MASK);
    printf("  -g <ip>    Gateway IP address (default: %s)\n", DEFAULT_GATEWAY_IP);
    printf("  -h         Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s\n", program);
    printf("  %s -l 192.168.1.100 -m 255.255.255.0 -g 192.168.1.1\n", program);
    printf("\nNote: Run with root/sudo privileges for raw packet access.\n");
    printf("\n");
}

int main(int argc, char *argv[])
{
    network_config_t config;
    arp_cache_t cache;
    const char *local_ip = DEFAULT_LOCAL_IP;
    const char *subnet_mask = DEFAULT_SUBNET_MASK;
    const char *gateway_ip = DEFAULT_GATEWAY_IP;
    
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
        else if (strcmp(argv[i], "-h") == 0)
        {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    // Setup signal handler
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize ARP logger
    arp_logger_init();
    logger_set_role(&g_arp_logger, LOG_ROLE_RECV);
    
    LOG_INFO(&g_arp_logger, "========================================");
    LOG_INFO(&g_arp_logger, "      ARP Protocol - RECEIVER");
    LOG_INFO(&g_arp_logger, "========================================");
    
    // Initialize configuration
    memset(&config, 0, sizeof(config));
    ip_str_to_bytes(local_ip, config.local_ip);
    ip_str_to_bytes(subnet_mask, config.subnet_mask);
    ip_str_to_bytes(gateway_ip, config.gateway_ip);
    config.dhcp_flag = 0;
    
    LOG_INFO(&g_arp_logger, "Initial Configuration:");
    LOG_INFO(&g_arp_logger, "  Local IP:     %s (may be updated from interface)", local_ip);
    LOG_INFO(&g_arp_logger, "  Subnet Mask:  %s", subnet_mask);
    LOG_INFO(&g_arp_logger, "  Gateway IP:   %s", gateway_ip);
    
    // Initialize ARP cache
    arp_cache_init(&cache);
    
    // Start ARP receiver
    LOG_INFO(&g_arp_logger, "Starting ARP receiver...");
    
    if (arp_receive(&config, &cache) < 0)
    {
        LOG_ERROR(&g_arp_logger, "Failed to start ARP receiver");
        arp_logger_close();
        return 1;
    }
    
    // Display final cache state
    LOG_INFO(&g_arp_logger, "========================================");
    LOG_INFO(&g_arp_logger, "Final ARP Cache State:");
    arp_cache_display(&cache);
    
    LOG_INFO(&g_arp_logger, "ARP receiver stopped.");
    arp_logger_close();
    return 0;
}
