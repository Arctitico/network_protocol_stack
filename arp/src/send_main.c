#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "arp.h"
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
    
    printf("========================================\n");
    printf("       ARP Protocol - SENDER\n");
    printf("========================================\n\n");
    
    // Initialize configuration
    memset(&config, 0, sizeof(config));
    ip_str_to_bytes(local_ip, config.local_ip);
    ip_str_to_bytes(subnet_mask, config.subnet_mask);
    ip_str_to_bytes(gateway_ip, config.gateway_ip);
    config.dhcp_flag = 0;
    
    printf("Configuration:\n");
    printf("  Local IP:     %s (will be updated from interface)\n", local_ip);
    printf("  Subnet Mask:  %s\n", subnet_mask);
    printf("  Gateway IP:   %s\n", gateway_ip);
    printf("  Target IP:    %s\n", target_ip);
    
    // Initialize ARP cache
    arp_cache_init(&cache);
    
    // Resolve target IP to MAC
    uint8_t target_ip_bytes[4];
    uint8_t result_mac[6];
    
    ip_str_to_bytes(target_ip, target_ip_bytes);
    
    printf("\n========================================\n");
    printf("Starting ARP resolution for %s\n", target_ip);
    printf("========================================\n");
    
    if (arp_get_mac(&config, &cache, target_ip_bytes, result_mac))
    {
        char mac_str[18];
        mac_bytes_to_str(result_mac, mac_str);
        
        printf("\n========================================\n");
        printf("        ARP Resolution SUCCESS\n");
        printf("========================================\n");
        printf("  IP Address:  %s\n", target_ip);
        printf("  MAC Address: %s\n", mac_str);
        printf("========================================\n");
        
        // Display final cache state
        arp_cache_display(&cache);
    }
    else
    {
        printf("\n========================================\n");
        printf("        ARP Resolution FAILED\n");
        printf("========================================\n");
        printf("  Could not resolve %s\n", target_ip);
        printf("  Possible reasons:\n");
        printf("    - Host is offline or unreachable\n");
        printf("    - Network interface misconfigured\n");
        printf("    - Firewall blocking ARP packets\n");
        printf("========================================\n");
        return 1;
    }
    
    return 0;
}
