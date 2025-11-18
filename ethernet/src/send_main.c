#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crc32.h"
#include "ethernet.h"
#include "ethernet_send.h"

#define DEFAULT_INPUT_FILE "data/input.txt"

int main(int argc, char *argv[])
{
    const char *input_file = DEFAULT_INPUT_FILE;
    
    // Parse command line arguments
    if (argc > 1)
    {
        input_file = argv[1];
    }
    
    printf("========================================\n");
    printf("   Ethernet Data Link Layer - SENDER\n");
    printf("========================================\n\n");
    
    printf("Input file:  %s\n\n", input_file);
    
    // Initialize CRC32 table
    generate_crc32_table();
    
    // Read data from input file
    FILE *fp = fopen(input_file, "rb");
    if (fp == NULL)
    {
        perror("Error opening input file");
        fprintf(stderr, "Usage: %s [input_file] [frame_file]\n", argv[0]);
        return 1;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    printf("Input data size: %ld bytes\n", file_size);
    
    // Read data
    uint8_t data[ETHERNET_MAX_DATA_SIZE];
    size_t data_len = fread(data, 1, ETHERNET_MAX_DATA_SIZE, fp);
    fclose(fp);
    
    if (data_len == 0)
    {
        fprintf(stderr, "Error: No data read from input file\n");
        return 1;
    }
    
    printf("Data read: %zu bytes\n\n", data_len);
    
    // Get destination MAC address from user
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type = ETHERNET_TYPE_IPV4;
    
    printf("Enter destination MAC address (format: AA:BB:CC:DD:EE:FF): ");
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
    
    // Get source MAC from network interface (will be obtained after interface selection)
    // For now, we'll pass zeros and update it in ethernet_send
    memset(src_mac, 0, 6);
    
    printf("\nFrame Configuration:\n");
    printf("  Destination MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           dest_mac[0], dest_mac[1], dest_mac[2], dest_mac[3], dest_mac[4], dest_mac[5]);
    printf("  Ethernet Type:   0x%04X (IPv4)\n", eth_type);
    printf("\nNote: Source MAC will be automatically obtained from selected interface\n\n");
    
    // Send Ethernet frame
    printf("Encapsulating and sending frame...\n");
    int result = ethernet_send(data, data_len, dest_mac, src_mac, eth_type);
    
    if (result < 0)
    {
        fprintf(stderr, "Failed to send Ethernet frame\n");
        return 1;
    }
    
    printf("\n========================================\n");
    printf("Frame sent successfully!\n");
    printf("========================================\n");
    
    return 0;
}
