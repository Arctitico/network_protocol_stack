#ifndef CRC32_H
#define CRC32_H

#include <stdint.h>

/**
 * @brief Generate CRC32 lookup table
 * 
 * This function initializes the CRC32 lookup table using the polynomial:
 * CRC-32 = X^32+X^26+X^23+X^22+X^16+X^12+X^11+X^10+X^8+X^7+X^5+X^4+X^2+X+1
 * Which is represented as 0xEDB88320 in reversed bit order
 */
void generate_crc32_table(void);

/**
 * @brief Calculate CRC32 checksum for a buffer
 * 
 * @param buffer Pointer to the data buffer
 * @param len Length of the buffer in bytes
 * @return uint32_t CRC32 checksum value
 */
uint32_t calculate_crc32(uint8_t *buffer, int len);

#endif /* CRC32_H */
