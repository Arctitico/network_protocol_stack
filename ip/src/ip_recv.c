#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include "ip_recv.h"
#include "ip_send.h"
#include "../../ethernet/include/ethernet_recv.h"
#include "../../ethernet/include/ethernet.h"
#include "../../arp/include/arp.h"
#include "../../arp/include/arp_recv.h"
#include "../../arp/include/arp_send.h"
#include "../../icmp/include/icmp.h"
#include "../../icmp/include/icmp_recv.h"
#include "../../common/include/logger.h"

/* Use the global IP logger from ip_send.c */
extern logger_t g_ip_logger;

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
    uint16_t *ptr = (uint16_t *)header;
    int len = header_len;
    
    // Special case: checksum = 0 means checksum offload (e.g., loopback interface)
    // Accept these packets as valid
    if (header->checksum == 0)
    {
        LOG_DEBUG(&g_ip_logger, "Checksum is 0 (offload), accepting packet");
        return 1;
    }
    
    // Sum all 16-bit words (including checksum field)
    // Note: data is already in network byte order, process as-is
    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }
    
    // Add odd byte if present
    if (len > 0)
    {
        sum += *(uint8_t *)ptr;
    }
    
    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    // Checksum is valid if result is 0xFFFF
    uint16_t final_sum = (uint16_t)sum;
    LOG_DEBUG(&g_ip_logger, "Checksum verification: header=0x%04X, calculated sum=0x%04X", 
              ntohs(header->checksum), final_sum);
    
    // For valid packet, sum should be 0xFFFF (all 16-bit words including checksum)
    return (final_sum == 0xFFFF);
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
        LOG_DEBUG(&g_ip_logger, "  -> Broadcast address");
        return 1;
    }
    
    // Check if matches local IP
    if (strcmp(dest_ip_str, local_ip) == 0)
    {
        LOG_DEBUG(&g_ip_logger, "  -> Matches local IP");
        return 1;
    }
    
    LOG_DEBUG(&g_ip_logger, "  -> Does NOT match local IP (%s)", local_ip);
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
    
    const char *proto_str;
    switch (header->protocol)
    {
        case IP_PROTO_TCP:
            proto_str = "(TCP)";
            break;
        case IP_PROTO_UDP:
            proto_str = "(UDP)";
            break;
        case IP_PROTO_ICMP:
            proto_str = "(ICMP)";
            break;
        default:
            proto_str = "(Unknown)";
            break;
    }
    
    LOG_INFO(&g_ip_logger, "========== IP Header ==========");
    LOG_INFO(&g_ip_logger, "Version:        %d", version);
    LOG_INFO(&g_ip_logger, "IHL:            %d (%d bytes)", ihl, ihl * 4);
    LOG_DEBUG(&g_ip_logger, "TOS:            0x%02X", header->tos);
    LOG_INFO(&g_ip_logger, "Total Length:   %d bytes", total_len);
    LOG_INFO(&g_ip_logger, "Identification: %d", id);
    LOG_INFO(&g_ip_logger, "Flags:          DF=%d, MF=%d", df, mf);
    LOG_INFO(&g_ip_logger, "Fragment Offset: %d bytes", offset);
    LOG_DEBUG(&g_ip_logger, "TTL:            %d", header->ttl);
    LOG_INFO(&g_ip_logger, "Protocol:       %d %s", header->protocol, proto_str);
    LOG_DEBUG(&g_ip_logger, "Checksum:       0x%04X", ntohs(header->checksum));
    LOG_INFO(&g_ip_logger, "Source IP:      %s", src_ip);
    LOG_INFO(&g_ip_logger, "Destination IP: %s", dest_ip);
    LOG_INFO(&g_ip_logger, "===============================");
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
            LOG_WARN(&g_ip_logger, "Fragment timeout: ID=%d, clearing entry", 
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
    
    // Get actual IP header length from IHL field
    int ip_header_len = (header->version_ihl & 0x0F) * 4;
    
    uint16_t flags_offset = ntohs(header->flags_offset);
    uint16_t offset = (flags_offset & IP_OFFSET_MASK) * 8;
    int mf = (flags_offset & IP_FLAG_MF) ? 1 : 0;
    uint16_t identification = header->identification;
    int data_len = ntohs(header->total_length) - ip_header_len;
    
    // Check if this is not a fragment (MF=0 and offset=0)
    if (mf == 0 && offset == 0)
    {
        LOG_DEBUG(&g_ip_logger, "Not a fragment, processing as complete packet");
        memcpy(reassembled_data, packet_data + ip_header_len, data_len);
        *reassembled_len = data_len;
        return 1;  // Complete
    }
    
    LOG_INFO(&g_ip_logger, "Fragment detected: Offset=%d, MF=%d, Data=%d bytes", offset, mf, data_len);
    
    // Find or create fragment entry
    fragment_info_t *frag = find_fragment_entry(identification, header->protocol,
                                                header->src_ip, header->dest_ip);
    
    if (frag == NULL)
    {
        LOG_ERROR(&g_ip_logger, "Fragment buffer full");
        return -1;
    }
    
    // Copy fragment data to buffer
    memcpy(frag->buffer + offset, packet_data + ip_header_len, data_len);
    frag->received_size += data_len;
    
    // If this is the last fragment (MF=0), record total size
    if (mf == 0)
    {
        frag->total_size = offset + data_len;
        LOG_INFO(&g_ip_logger, "Last fragment received, total size: %d bytes", frag->total_size);
    }
    
    // Check if reassembly is complete
    if (frag->total_size > 0 && frag->received_size >= frag->total_size)
    {
        LOG_INFO(&g_ip_logger, "Reassembly complete!");
        memcpy(reassembled_data, frag->buffer, frag->total_size);
        *reassembled_len = frag->total_size;
        
        // Clear fragment entry
        memset(frag, 0, sizeof(fragment_info_t));
        
        return 1;  // Complete
    }
    
    LOG_DEBUG(&g_ip_logger, "Waiting for more fragments... (received %d bytes)", frag->received_size);
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
    
    if (packet_len < IP_HEADER_MIN_SIZE)
    {
        LOG_ERROR(&g_ip_logger, "Packet too small");
        return 0;
    }
    
    ip_header_t *header = (ip_header_t *)ip_packet;
    
    // Get actual IP header length from IHL field (in 4-byte units)
    int ip_header_len = (header->version_ihl & 0x0F) * 4;
    
    if (ip_header_len < IP_HEADER_MIN_SIZE || ip_header_len > IP_HEADER_MAX_SIZE)
    {
        LOG_ERROR(&g_ip_logger, "Invalid IP header length: %d", ip_header_len);
        return 0;
    }
    
    if (packet_len < ip_header_len)
    {
        LOG_ERROR(&g_ip_logger, "Packet smaller than header length");
        return 0;
    }
    
    LOG_DEBUG(&g_ip_logger, "--- IP Packet Processing ---");
    LOG_DEBUG(&g_ip_logger, "IP header length: %d bytes", ip_header_len);
    
    // Check destination IP
    if (!check_destination_ip(header->dest_ip, local_ip))
    {
        LOG_DEBUG(&g_ip_logger, "Packet discarded: Destination IP mismatch");
        return 0;
    }
    
    // Verify checksum using actual header length
    if (!verify_ip_checksum(header, ip_header_len))
    {
        LOG_WARN(&g_ip_logger, "Packet discarded: Checksum error");
        return 0;
    }
    LOG_DEBUG(&g_ip_logger, "Checksum verified: OK");
    
    // Check TTL
    if (header->ttl == 0)
    {
        LOG_WARN(&g_ip_logger, "Packet discarded: TTL expired");
        return 0;
    }
    
    // Display header
    display_ip_header(header);;
    
    // Reassemble fragments
    int result = reassemble_fragments(header, ip_packet, packet_len,
                                      reassembled_data, &reassembled_len);
    
    if (result == 1)
    {
        // Reassembly complete, deliver to upper layer based on protocol
        LOG_INFO(&g_ip_logger, "Delivering %d bytes to upper layer (protocol=%d)", 
                 reassembled_len, header->protocol);
        
        // Check protocol type
        if (header->protocol == IP_PROTO_ICMP)
        {
            // Handle ICMP protocol
            LOG_INFO(&g_ip_logger, "Protocol is ICMP, calling ICMP handler");
            
            // Get source IP address string for ICMP reply
            char src_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &header->src_ip, src_ip_str, INET_ADDRSTRLEN);
            
            // Get source MAC from Ethernet layer for reply
            uint8_t src_mac[6];
            ethernet_get_last_src_mac(src_mac);
            
            // Call ICMP receiver
            int icmp_result = icmp_recv(reassembled_data, reassembled_len, 
                                        src_ip_str, src_mac);
            
            if (icmp_result > 0)
            {
                LOG_INFO(&g_ip_logger, "ICMP packet processed and reply sent");
            }
            else if (icmp_result == 0)
            {
                LOG_INFO(&g_ip_logger, "ICMP packet processed, no reply needed");
            }
            else
            {
                LOG_ERROR(&g_ip_logger, "ICMP packet processing failed");
            }
            
            return icmp_result;
        }
        else
        {
            // For other protocols (TCP, UDP, etc.), write to file as before
            LOG_INFO(&g_ip_logger, "Delivering %d bytes to Transport Layer", reassembled_len);
            
            FILE *fp_out = fopen(output_file, "wb");
            if (fp_out == NULL)
            {
                LOG_ERROR(&g_ip_logger, "Error opening output file: %s", output_file);
                return -1;
            }
            
            fwrite(reassembled_data, 1, reassembled_len, fp_out);
            fclose(fp_out);
            
            LOG_INFO(&g_ip_logger, "Data written to: %s", output_file);
        }
        
        return 1;
    }
    else if (result < 0)
    {
        LOG_ERROR(&g_ip_logger, "Error during reassembly");
        return -1;
    }
    
    return 0;  // Waiting for more fragments
}

/**
 * Ethernet callback for IP processing (internal)
 */
static int ip_ethernet_callback(uint8_t *data, int data_len, void *user_data)
{
    (void)user_data;
    
    LOG_INFO(&g_ip_logger, "========== IP Packet from Ethernet Layer ==========");
    LOG_DEBUG(&g_ip_logger, "Data length: %d bytes", data_len);
    
    int result = process_ip_packet(data, data_len, g_local_ip, g_output_file);
    
    if (result > 0)
    {
        g_packet_processed++;
        printf("[RECV] IP packet #%d received (%d bytes)\n", g_packet_processed, data_len);
    }
    
    return result;
}

/**
 * Initialize IP receiver context (internal)
 */
static void ip_recv_init(const char *local_ip, const char *output_file)
{
    g_local_ip = local_ip;
    g_output_file = output_file;
    g_packet_processed = 0;
    LOG_INFO(&g_ip_logger, "IP receiver context initialized");
    LOG_INFO(&g_ip_logger, "  Local IP: %s", local_ip);
    LOG_INFO(&g_ip_logger, "  Output:   %s", output_file);
}

/**
 * Start integrated network stack receiver
 */
int network_stack_receive(const char *local_ip, const char *output_file,
                          network_config_t *net_config, 
                          arp_cache_t *arp_cache,
                          int packet_count)
{
    LOG_INFO(&g_ip_logger, "========================================");
    LOG_INFO(&g_ip_logger, "  Network Stack - Integrated Receiver");
    LOG_INFO(&g_ip_logger, "========================================");
    LOG_INFO(&g_ip_logger, "Local IP:    %s", local_ip);
    LOG_INFO(&g_ip_logger, "Output file: %s", output_file);
    LOG_INFO(&g_ip_logger, "========================================");
    
    // Initialize IP context
    ip_recv_init(local_ip, output_file);
    
    // Initialize ARP context
    arp_init_context(net_config, arp_cache);
    
    // Initialize ICMP context (set local IP and MAC for replies)
    icmp_logger_init();
    icmp_set_context(local_ip, net_config->local_mac);
    LOG_INFO(&g_ip_logger, "ICMP context initialized");
    
    // Register protocol handlers with Ethernet layer
    ethernet_clear_protocols();
    
    // Register IPv4 handler (EtherType 0x0800)
    if (ethernet_register_protocol(ETHERNET_TYPE_IPV4, ip_ethernet_callback, NULL) < 0)
    {
        LOG_ERROR(&g_ip_logger, "Failed to register IPv4 protocol handler");
        return -1;
    }
    
    // Register ARP handler (EtherType 0x0806)
    if (ethernet_register_protocol(ETHERNET_TYPE_ARP, 
                                   (ethernet_recv_callback_t)arp_ethernet_callback, NULL) < 0)
    {
        LOG_ERROR(&g_ip_logger, "Failed to register ARP protocol handler");
        return -1;
    }
    
    LOG_INFO(&g_ip_logger, "Protocol handlers registered:");
    LOG_INFO(&g_ip_logger, "  - IPv4 (0x0800)");
    LOG_INFO(&g_ip_logger, "  - ARP  (0x0806)");
    LOG_INFO(&g_ip_logger, "Starting Ethernet dispatch...");
    
    // Start Ethernet layer in dispatch mode
    int result = ethernet_receive_dispatch(packet_count);
    
    LOG_INFO(&g_ip_logger, "========================================");
    LOG_INFO(&g_ip_logger, "Total IP packets processed: %d", g_packet_processed);
    LOG_INFO(&g_ip_logger, "========================================");
    
    // Clean up protocol handlers
    ethernet_clear_protocols();
    
    return result;
}
