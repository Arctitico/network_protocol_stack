#ifndef ICMP_RECV_H
#define ICMP_RECV_H

#include "icmp.h"
#include "../../common/include/logger.h"

/* Global logger for ICMP module */
extern logger_t g_icmp_logger;

/**
 * @brief Initialize ICMP logger
 */
void icmp_logger_init(void);

/**
 * @brief Close ICMP logger
 */
void icmp_logger_close(void);

/**
 * @brief Context structure for ICMP processing
 * 
 * This structure holds the necessary context information for
 * processing ICMP packets and sending replies.
 */
typedef struct icmp_context {
    const char *local_ip;       // Local IP address (string)
    uint8_t local_mac[6];       // Local MAC address
    uint8_t *dest_mac;          // Destination MAC for reply (source MAC of request)
    const char *src_ip;         // Source IP of request (destination for reply)
} icmp_context_t;

/**
 * @brief Set ICMP processing context
 * 
 * Must be called before icmp_recv to set up the context needed
 * for sending ICMP replies.
 * 
 * @param local_ip Local IP address string
 * @param local_mac Local MAC address (6 bytes)
 */
void icmp_set_context(const char *local_ip, const uint8_t *local_mac);

/**
 * @brief Process received ICMP packet
 * 
 * Main function for handling received ICMP packets. According to the
 * requirements:
 * - If the packet is an ICMP ECHO Request, construct an ICMP ECHO Reply
 *   and send it back through IP layer -> Ethernet layer.
 * - For other ICMP types, no processing is performed.
 * 
 * @param icmp_buffer Pointer to ICMP packet data (header + data)
 * @param icmp_len Length of ICMP packet
 * @param src_ip Source IP address of the request (string, will be dest for reply)
 * @param dest_mac Destination MAC address for reply (6 bytes)
 * @return int 1 if reply sent, 0 if no reply needed, -1 on error
 */
int icmp_recv(uint8_t *icmp_buffer, int icmp_len, const char *src_ip, uint8_t *dest_mac);

/**
 * @brief Verify ICMP packet integrity
 * 
 * @param buffer ICMP packet buffer
 * @param len Length of buffer
 * @return int 1 if valid, 0 if invalid
 */
int verify_icmp_packet(const uint8_t *buffer, int len);

/**
 * @brief Parse ICMP header from buffer
 * 
 * @param buffer Input buffer containing ICMP packet
 * @param header Output ICMP header structure
 * @return int 0 on success, -1 on error
 */
int parse_icmp_header(const uint8_t *buffer, icmp_header_t *header);

/**
 * @brief Build ICMP ECHO Reply packet
 * 
 * Constructs an ICMP ECHO Reply based on a received ECHO Request.
 * The reply preserves the identifier, sequence number, and data
 * from the request.
 * 
 * @param request_header Pointer to the request ICMP header
 * @param request_data Pointer to the request data
 * @param request_data_len Length of request data
 * @param reply_buffer Output buffer for the complete reply packet
 * @param reply_len Output parameter for reply packet length
 * @return int 0 on success, -1 on error
 */
int build_icmp_echo_reply(icmp_header_t *request_header, uint8_t *request_data,
                          int request_data_len, uint8_t *reply_buffer, int *reply_len);

/**
 * @brief Send ICMP reply through IP layer
 * 
 * @param icmp_packet ICMP packet data (header + data)
 * @param icmp_len Length of ICMP packet
 * @param src_ip Source IP for IP header (local IP)
 * @param dest_ip Destination IP for IP header
 * @param dest_mac Destination MAC address
 * @return int 1 on success, -1 on error
 */
int icmp_send_reply(uint8_t *icmp_packet, int icmp_len,
                    const char *src_ip, const char *dest_ip, uint8_t *dest_mac);

#endif /* ICMP_RECV_H */
