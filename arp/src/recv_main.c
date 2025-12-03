#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "arp.h"
#include "arp_recv.h"
#include "arp_send.h"

#define DEFAULT_LOCAL_IP    "192.168.1.100"
#define DEFAULT_SUBNET_MASK "255.255.255.0"
#define DEFAULT_GATEWAY_IP  "192.168.1.1"

static volatile int g_running = 1;

void signal_handler(int sig)
{
    (void)sig;
    printf("\nReceived signal, exiting...\n");
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
    
    printf("========================================\n");
    printf("      ARP Protocol - RECEIVER\n");
    printf("========================================\n\n");
    
    // Initialize configuration
    memset(&config, 0, sizeof(config));
    ip_str_to_bytes(local_ip, config.local_ip);
    ip_str_to_bytes(subnet_mask, config.subnet_mask);
    ip_str_to_bytes(gateway_ip, config.gateway_ip);
    config.dhcp_flag = 0;
    
    printf("Initial Configuration:\n");
    printf("  Local IP:     %s (may be updated from interface)\n", local_ip);
    printf("  Subnet Mask:  %s\n", subnet_mask);
    printf("  Gateway IP:   %s\n", gateway_ip);
    
    // Initialize ARP cache
    arp_cache_init(&cache);
    
    // Start ARP receiver
    printf("\nStarting ARP receiver...\n");
    
    if (arp_receive(&config, &cache) < 0)
    {
        fprintf(stderr, "Failed to start ARP receiver\n");
        return 1;
    }
    
    // Display final cache state
    printf("\n========================================\n");
    printf("Final ARP Cache State:\n");
    arp_cache_display(&cache);
    
    printf("\nARP receiver stopped.\n");
    return 0;
}
