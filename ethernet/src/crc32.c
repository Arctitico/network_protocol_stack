#include "../include/crc32.h"

static uint32_t crc32_table[256];

/**
 * Generate CRC32 lookup table
 * Uses the standard Ethernet polynomial: 0xEDB88320 (reversed)
 */
void generate_crc32_table(void)
{
    int i, j;
    uint32_t crc;
    
    for (i = 0; i < 256; i++)
    {
        crc = i;
        for (j = 0; j < 8; j++)
        {
            if (crc & 1)
                crc = (crc >> 1) ^ 0xEDB88320;
            else
                crc >>= 1;
        }
        crc32_table[i] = crc;
    }
}

/**
 * Calculate CRC32 checksum using table lookup method
 */
uint32_t calculate_crc32(uint8_t *buffer, int len)
{
    int i;
    uint32_t crc;
    
    crc = 0xffffffff;
    for (i = 0; i < len; i++)
    {
        crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
    }
    crc ^= 0xffffffff;
    
    return crc;
}
