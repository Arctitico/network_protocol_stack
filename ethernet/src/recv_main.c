#include <stdio.h>
#include <stdlib.h>
#include "../include/crc32.h"
#include "../include/ethernet.h"
#include "../include/ethernet_recv.h"
#include "../include/ethernet_send.h"
#include "../../common/include/logger.h"

#define DEFAULT_OUTPUT_FILE "output/received_data.txt"
#define DEFAULT_LOG_FILE "output/ethernet.log"

int main(int argc, char *argv[])
{
    const char *output_file = DEFAULT_OUTPUT_FILE;
    
    // Parse command line arguments
    if (argc > 1)
    {
        output_file = argv[1];
    }
    
    // Initialize logger
    ethernet_logger_init();
    logger_set_role(&g_ethernet_logger, LOG_ROLE_RECV);
    
    printf("========================================\n");
    printf("  Ethernet Data Link Layer - RECEIVER\n");
    printf("========================================\n\n");
    
    LOG_INFO(&g_ethernet_logger, "Ethernet receiver started");
    printf("Output file:  %s\n\n", output_file);
    
    // Initialize CRC32 table
    generate_crc32_table();
    
    // Note: Local MAC address will be automatically obtained from selected interface
    
    // Receive and process Ethernet frame
    printf("Receiving and processing frame...\n\n");
    int result = ethernet_receive(output_file);
    
    if (result < 0)
    {
        LOG_ERROR(&g_ethernet_logger, "Error occurred while receiving frame");
        ethernet_logger_close();
        return 1;
    }
    else if (result == 0)
    {
        LOG_WARN(&g_ethernet_logger, "Frame was discarded (verification failed)");
        ethernet_logger_close();
        return 0;
    }
    
    LOG_INFO(&g_ethernet_logger, "Receiver finished successfully");
    printf("\n========================================\n");
    printf("Frame received and processed successfully!\n");
    printf("Data delivered to upper layer (Network Layer)\n");
    printf("========================================\n");
    
    ethernet_logger_close();
    return 0;
}
