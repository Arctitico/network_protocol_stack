#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ip.h"
#include "ip_send.h"

#define DEFAULT_INPUT_FILE "data/input.txt"
#define DEFAULT_SRC_IP "192.168.1.100"
#define DEFAULT_DEST_IP "192.168.1.200"
#define DEFAULT_PROTOCOL IP_PROTO_TCP

int main(int argc, char *argv[])
{
    const char *input_file = DEFAULT_INPUT_FILE;
    const char *src_ip = DEFAULT_SRC_IP;
    const char *dest_ip = DEFAULT_DEST_IP;
    uint8_t protocol = DEFAULT_PROTOCOL;
    uint8_t dest_mac[6];
    
    // Parse command line arguments
    if (argc > 1) input_file = argv[1];
    if (argc > 2) src_ip = argv[2];
    if (argc > 3) dest_ip = argv[3];
    if (argc > 4) protocol = (uint8_t)atoi(argv[4]);
    
    printf("========================================\n");
    printf("      IP Network Layer - SENDER\n");
    printf("========================================\n\n");
    
    printf("Configuration:\n");
    printf("  Input file:   %s (from Transport Layer)\n", input_file);
    printf("  Source IP:    %s\n", src_ip);
    printf("  Dest IP:      %s\n", dest_ip);
    printf("  Protocol:     %d\n", protocol);
    
    // Get destination MAC address from user
    printf("\nEnter destination MAC address (format: AA:BB:CC:DD:EE:FF): ");
    int mac_values[6];
    if (scanf("%02x:%02x:%02x:%02x:%02x:%02x",
              &mac_values[0], &mac_values[1], &mac_values[2],
              &mac_values[3], &mac_values[4], &mac_values[5]) != 6)
    {
        fprintf(stderr, "Invalid MAC address format\n");
        return 1;
    }
    
    for (int i = 0; i < 6; i++)
    {
        dest_mac[i] = (uint8_t)mac_values[i];
    }
    
    printf("\n");
    
    // Read data from input file (simulating transport layer)
    FILE *fp = fopen(input_file, "rb");
    if (fp == NULL)
    {
        perror("Error opening input file");
        fprintf(stderr, "\nUsage: %s [input] [output] [src_ip] [dest_ip] [protocol]\n", argv[0]);
        fprintf(stderr, "Example: %s data/input.txt data/ip_packet.bin 192.168.1.100 192.168.1.200 6\n\n", argv[0]);
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
