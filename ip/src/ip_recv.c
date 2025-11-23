#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include "ip_recv.h"
#include "../../ethernet/include/ethernet_recv.h"
#include "../../ethernet/include/ethernet.h"

#define MAX_FRAGMENTS 10
#define FRAGMENT_TIMEOUT 30  // 30 seconds

// Global fragment buffer
static fragment_info_t g_fragments[MAX_FRAGMENTS];
static int g_fragment_count = 0;

// Global variables for callback
static const char *g_local_ip = NULL;
static const char *g_output_file = NULL;
static int g_packet_processed = 0;

/**
 * Verify IP header checksum
 */
int verify_ip_checksum(ip_header_t *header, int header_len)
{
    uint32_t sum = 0;
    uint8_t *ptr = (uint8_t *)header;
    int len = header_len;
    
    // Sum all 16-bit words (including checksum field)
    while (len > 1)
    {
        uint16_t word;
        memcpy(&word, ptr, sizeof(uint16_t));
        sum += word;
        ptr += 2;
        len -= 2;
    }
    
    // Add odd byte if present
    if (len > 0)
    {
        sum += *ptr;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Checksum is valid if result is 0xFFFF or 0x0000
    return (sum == 0xFFFF || sum == 0x0000);
}

/**
 * Check if destination IP matches local IP or broadcast
 */
int check_destination_ip(struct in_addr dest_ip, const char *local_ip)
{
    char dest_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest_ip, dest_ip_str, INET_ADDRSTRLEN);
    
    // Check if broadcast
    if (strcmp(dest_ip_str, "255.255.255.255") == 0)
    {
        printf("  -> Broadcast address\n");
        return 1;
    }
    
    // Check if matches local IP
    if (strcmp(dest_ip_str, local_ip) == 0)
    {
        printf("  -> Matches local IP\n");
        return 1;
    }
    
    printf("  -> Does NOT match local IP (%s)\n", local_ip);
    return 0;
}

/**
 * Display IP header information
 */
void display_ip_header(ip_header_t *header)
{
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &header->src_ip, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &header->dest_ip, dest_ip, INET_ADDRSTRLEN);
    
    uint8_t version = (header->version_ihl >> 4) & 0x0F;
    uint8_t ihl = header->version_ihl & 0x0F;
    uint16_t total_len = ntohs(header->total_length);
    uint16_t id = ntohs(header->identification);
    uint16_t flags_offset = ntohs(header->flags_offset);
    uint16_t offset = (flags_offset & IP_OFFSET_MASK) * 8;
    int mf = (flags_offset & IP_FLAG_MF) ? 1 : 0;
    int df = (flags_offset & IP_FLAG_DF) ? 1 : 0;
    
    printf("\n========== IP Header ==========\n");
    printf("Version:        %d\n", version);
    printf("IHL:            %d (%d bytes)\n", ihl, ihl * 4);
    printf("TOS:            0x%02X\n", header->tos);
    printf("Total Length:   %d bytes\n", total_len);
    printf("Identification: %d\n", id);
    printf("Flags:          DF=%d, MF=%d\n", df, mf);
    printf("Fragment Offset: %d bytes\n", offset);
    printf("TTL:            %d\n", header->ttl);
    printf("Protocol:       %d ", header->protocol);
    
    switch (header->protocol)
    {
        case IP_PROTO_TCP:
            printf("(TCP)\n");
            break;
        case IP_PROTO_UDP:
            printf("(UDP)\n");
            break;
        case IP_PROTO_ICMP:
            printf("(ICMP)\n");
            break;
        default:
            printf("(Unknown)\n");
            break;
    }
    
    printf("Checksum:       0x%04X\n", ntohs(header->checksum));
    printf("Source IP:      %s\n", src_ip);
    printf("Destination IP: %s\n", dest_ip);
    printf("===============================\n\n");
}

/**
 * Find or create fragment entry
 */
static fragment_info_t* find_fragment_entry(uint16_t identification, uint8_t protocol,
                                            struct in_addr src_ip, struct in_addr dest_ip)
{
    time_t current_time = time(NULL);
    
    // Search for existing entry
    for (int i = 0; i < g_fragment_count; i++)
    {
        // Check for timeout
        if (current_time - g_fragments[i].first_fragment_time > FRAGMENT_TIMEOUT)
        {
            printf("Fragment timeout: ID=%d, clearing entry\n", 
                   ntohs(g_fragments[i].identification));
            // Reuse this entry
            memset(&g_fragments[i], 0, sizeof(fragment_info_t));
            g_fragments[i].identification = identification;
            g_fragments[i].protocol = protocol;
            g_fragments[i].src_ip = src_ip;
            g_fragments[i].dest_ip = dest_ip;
            g_fragments[i].total_size = -1;
            g_fragments[i].first_fragment_time = current_time;
            return &g_fragments[i];
        }
        
        // Check if matches
        if (g_fragments[i].identification == identification &&
            g_fragments[i].protocol == protocol &&
            g_fragments[i].src_ip.s_addr == src_ip.s_addr &&
            g_fragments[i].dest_ip.s_addr == dest_ip.s_addr)
        {
            return &g_fragments[i];
        }
    }
    
    // Create new entry if space available
    if (g_fragment_count < MAX_FRAGMENTS)
    {
        fragment_info_t *entry = &g_fragments[g_fragment_count++];
        memset(entry, 0, sizeof(fragment_info_t));
        entry->identification = identification;
        entry->protocol = protocol;
        entry->src_ip = src_ip;
        entry->dest_ip = dest_ip;
        entry->total_size = -1;
        entry->first_fragment_time = current_time;
        return entry;
    }
    
    return NULL;
}

/**
 * Reassemble IP fragments
 */
int reassemble_fragments(ip_header_t *header, uint8_t *packet_data, int packet_len,
                         uint8_t *reassembled_data, int *reassembled_len)
{
    (void)packet_len;  // Unused parameter
    uint16_t flags_offset = ntohs(header->flags_offset);
    uint16_t offset = (flags_offset & IP_OFFSET_MASK) * 8;
    int mf = (flags_offset & IP_FLAG_MF) ? 1 : 0;
    uint16_t identification = header->identification;
    int data_len = ntohs(header->total_length) - IP_HEADER_MAX_SIZE;
    
    // Check if this is not a fragment (MF=0 and offset=0)
    if (mf == 0 && offset == 0)
    {
        printf("Not a fragment, processing as complete packet\n");
        memcpy(reassembled_data, packet_data + IP_HEADER_MAX_SIZE, data_len);
        *reassembled_len = data_len;
        return 1;  // Complete
    }
    
    printf("Fragment detected: Offset=%d, MF=%d, Data=%d bytes\n", offset, mf, data_len);
    
    // Find or create fragment entry
    fragment_info_t *frag = find_fragment_entry(identification, header->protocol,
                                                header->src_ip, header->dest_ip);
    
    if (frag == NULL)
    {
        fprintf(stderr, "Error: Fragment buffer full\n");
        return -1;
    }
    
    // Copy fragment data to buffer
    memcpy(frag->buffer + offset, packet_data + IP_HEADER_MAX_SIZE, data_len);
    frag->received_size += data_len;
    
    // If this is the last fragment (MF=0), record total size
    if (mf == 0)
    {
        frag->total_size = offset + data_len;
        printf("Last fragment received, total size: %d bytes\n", frag->total_size);
    }
    
    // Check if reassembly is complete
    if (frag->total_size > 0 && frag->received_size >= frag->total_size)
    {
        printf("Reassembly complete!\n");
        memcpy(reassembled_data, frag->buffer, frag->total_size);
        *reassembled_len = frag->total_size;
        
        // Clear fragment entry
        memset(frag, 0, sizeof(fragment_info_t));
        
        return 1;  // Complete
    }
    
    printf("Waiting for more fragments... (received %d bytes)\n", frag->received_size);
    return 0;  // Waiting for more fragments
}

/**
 * Process received IP packet from Ethernet layer
 */
int process_ip_packet(uint8_t *ip_packet, int packet_len, 
                      const char *local_ip, const char *output_file)
{
    static uint8_t reassembled_data[IP_MAX_PACKET_SIZE];
    static int reassembled_len;
    
    if (packet_len < IP_HEADER_MAX_SIZE)
    {
        fprintf(stderr, "Error: Packet too small\n");
        return 0;
    }
    
    ip_header_t *header = (ip_header_t *)ip_packet;
    
    printf("\n--- IP Packet Processing ---\n");
    
    // Check destination IP
    if (!check_destination_ip(header->dest_ip, local_ip))
    {
        printf("Packet discarded: Destination IP mismatch\n");
        return 0;
    }
    
    // Verify checksum
    if (!verify_ip_checksum(header, IP_HEADER_MAX_SIZE))
    {
        printf("Packet discarded: Checksum error\n");
        return 0;
    }
    printf("Checksum verified: OK\n");
    
    // Check TTL
    if (header->ttl == 0)
    {
        printf("Packet discarded: TTL expired\n");
        return 0;
    }
    
    // Display header
    display_ip_header(header);
    
    // Reassemble fragments
    int result = reassemble_fragments(header, ip_packet, packet_len,
                                      reassembled_data, &reassembled_len);
    
    if (result == 1)
    {
        // Reassembly complete, deliver to upper layer
        printf("Delivering %d bytes to Transport Layer\n", reassembled_len);
        
        FILE *fp_out = fopen(output_file, "wb");
        if (fp_out == NULL)
        {
            perror("Error opening output file");
            return -1;
        }
        
        fwrite(reassembled_data, 1, reassembled_len, fp_out);
        fclose(fp_out);
        
        printf("Data written to: %s\n", output_file);
        return 1;
    }
    else if (result < 0)
    {
        printf("Error during reassembly\n");
        return -1;
    }
    
    return 0;  // Waiting for more fragments
}

/**
 * Callback function for Ethernet layer
 */
static int ethernet_callback_handler(uint8_t *data, int data_len, void *user_data)
{
    (void)user_data;  // Unused
    
    printf("\n========== Received from Ethernet Layer ==========\n");
    printf("IP packet length: %d bytes\n", data_len);
    
    int result = process_ip_packet(data, data_len, g_local_ip, g_output_file);
    
    if (result > 0)
    {
        g_packet_processed++;
    }
    
    return result;
}

/**
 * Start IP receiver via Ethernet layer
 */
int ip_receive(const char *local_ip, const char *output_file)
{
    printf("\n========== IP Layer - Receiving ==========\n");
    printf("Output file: %s\n", output_file);
    printf("Local IP:    %s\n", local_ip);
    printf("==========================================\n\n");
    
    // Set global variables
    g_local_ip = local_ip;
    g_output_file = output_file;
    g_packet_processed = 0;
    
    printf("Starting Ethernet layer reception...\n");
    printf("Waiting for IP packets (Press Ctrl+C to stop)...\n\n");
    
    // Start receiving via Ethernet layer with callback
    int result = ethernet_receive_callback(ethernet_callback_handler, NULL, 0);
    
    printf("\n==========================================\n");
    printf("Total IP packets processed: %d\n", g_packet_processed);
    printf("==========================================\n");
    
    return result;
}
