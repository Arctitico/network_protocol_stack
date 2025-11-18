#include <stdio.h>
#include <stdlib.h>
#include "crc32.h"
#include "ethernet.h"
#include "ethernet_recv.h"

#define DEFAULT_OUTPUT_FILE "output/received_data.txt"

int main(int argc, char *argv[])
{
    const char *output_file = DEFAULT_OUTPUT_FILE;
    
    // Parse command line arguments
    if (argc > 1)
    {
        output_file = argv[1];
    }
    
    printf("========================================\n");
    printf("  Ethernet Data Link Layer - RECEIVER\n");
    printf("========================================\n\n");
    
    printf("Output file:  %s\n\n", output_file);
    
    // Initialize CRC32 table
    generate_crc32_table();
    
    // Note: Local MAC address will be automatically obtained from selected interface
    
    // Receive and process Ethernet frame
    printf("Receiving and processing frame...\n\n");
    int result = ethernet_receive(output_file);
    
    if (result < 0)
    {
        fprintf(stderr, "\nError occurred while receiving frame\n");
        return 1;
    }
    else if (result == 0)
    {
        printf("\nFrame was discarded (verification failed)\n");
        return 0;
    }
    
    printf("\n========================================\n");
    printf("Frame received and processed successfully!\n");
    printf("Data delivered to upper layer (Network Layer)\n");
    printf("========================================\n");
    
    return 0;
}
