#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ip.h"
#include "ip_recv.h"

#define DEFAULT_OUTPUT_FILE "output/received_data.txt"
#define DEFAULT_LOCAL_IP "192.168.1.200"

int main(int argc, char *argv[])
{
    const char *output_file = DEFAULT_OUTPUT_FILE;
    const char *local_ip = DEFAULT_LOCAL_IP;
    
    // Parse command line arguments
    if (argc > 1) output_file = argv[1];
    if (argc > 2) local_ip = argv[2];
    
    printf("========================================\n");
    printf("     IP Network Layer - RECEIVER\n");
    printf("========================================\n\n");
    
    printf("Configuration:\n");
    printf("  Output file:  %s (to Transport Layer)\n", output_file);
    printf("  Local IP:     %s\n", local_ip);
    printf("\n");
    
    // Receive and process IP packet via Ethernet layer
    int result = ip_receive(local_ip, output_file);
    
    if (result < 0)
    {
        fprintf(stderr, "\nError occurred while receiving IP packet\n");
        return 1;
    }
    
    printf("\n========================================\n");
    printf("IP receiver stopped\n");
    printf("========================================\n");
    
    return 0;
}
