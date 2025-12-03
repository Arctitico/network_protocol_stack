#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include "arp.h"

/**
 * Convert IP string to byte array
 */
void ip_str_to_bytes(const char *ip_str, uint8_t *ip_bytes)
{
    struct in_addr addr;
    inet_pton(AF_INET, ip_str, &addr);
    memcpy(ip_bytes, &addr.s_addr, 4);
}

/**
 * Convert byte array to IP string
 */
void ip_bytes_to_str(const uint8_t *ip_bytes, char *ip_str)
{
    sprintf(ip_str, "%d.%d.%d.%d", 
            ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
}

/**
 * Convert MAC string to byte array
 * Format: "AA:BB:CC:DD:EE:FF" or "AA-BB-CC-DD-EE-FF"
 */
int mac_str_to_bytes(const char *mac_str, uint8_t *mac_bytes)
{
    int values[6];
    int count;
    
    // Try colon-separated format
    count = sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                   &values[0], &values[1], &values[2],
                   &values[3], &values[4], &values[5]);
    
    if (count != 6)
    {
        // Try dash-separated format
        count = sscanf(mac_str, "%02x-%02x-%02x-%02x-%02x-%02x",
                       &values[0], &values[1], &values[2],
                       &values[3], &values[4], &values[5]);
    }
    
    if (count != 6)
    {
        return -1;
    }
    
    for (int i = 0; i < 6; i++)
    {
        mac_bytes[i] = (uint8_t)values[i];
    }
    
    return 0;
}

/**
 * Convert byte array to MAC string
 */
void mac_bytes_to_str(const uint8_t *mac_bytes, char *mac_str)
{
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5]);
}

/**
 * Check if two IPs are in the same subnet
 */
int is_same_subnet(const uint8_t *ip1, const uint8_t *ip2, const uint8_t *mask)
{
    for (int i = 0; i < 4; i++)
    {
        if ((ip1[i] & mask[i]) != (ip2[i] & mask[i]))
        {
            return 0;
        }
    }
    return 1;
}

/**
 * Display ARP header information
 */
void display_arp_header(arp_header_t *header)
{
    char sender_ip_str[16], target_ip_str[16];
    char sender_mac_str[18], target_mac_str[18];
    
    ip_bytes_to_str(header->sender_ip, sender_ip_str);
    ip_bytes_to_str(header->target_ip, target_ip_str);
    mac_bytes_to_str(header->sender_mac, sender_mac_str);
    mac_bytes_to_str(header->target_mac, target_mac_str);
    
    printf("\n========== ARP Header ==========\n");
    printf("Hardware Type:   0x%04X ", ntohs(header->hardware_type));
    if (ntohs(header->hardware_type) == ARP_HARDWARE_ETHERNET)
        printf("(Ethernet)\n");
    else
        printf("(Unknown)\n");
    
    printf("Protocol Type:   0x%04X ", ntohs(header->protocol_type));
    if (ntohs(header->protocol_type) == ARP_PROTOCOL_IPV4)
        printf("(IPv4)\n");
    else
        printf("(Unknown)\n");
    
    printf("Hardware Len:    %d\n", header->hardware_len);
    printf("Protocol Len:    %d\n", header->protocol_len);
    
    uint16_t op = ntohs(header->operation);
    printf("Operation:       %d ", op);
    switch (op)
    {
        case ARP_OP_REQUEST:
            printf("(ARP Request)\n");
            break;
        case ARP_OP_REPLY:
            printf("(ARP Reply)\n");
            break;
        case ARP_OP_RARP_REQUEST:
            printf("(RARP Request)\n");
            break;
        case ARP_OP_RARP_REPLY:
            printf("(RARP Reply)\n");
            break;
        default:
            printf("(Unknown)\n");
            break;
    }
    
    printf("Sender MAC:      %s\n", sender_mac_str);
    printf("Sender IP:       %s\n", sender_ip_str);
    printf("Target MAC:      %s\n", target_mac_str);
    printf("Target IP:       %s\n", target_ip_str);
    printf("================================\n\n");
}
