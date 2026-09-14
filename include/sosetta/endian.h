#ifndef SOSETTA_ENDIAN_H
#define SOSETTA_ENDIAN_H

#include <stdint.h>
#include <stddef.h>

static inline uint32_t be32(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static inline uint64_t be64(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] << 8) | (uint64_t)b[7];
}

static inline uint16_t be16(const void *p)
{
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(((uint16_t)b[0] << 8) | (uint16_t)b[1]);
}

static inline void put_be16(void *p, uint16_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 8);
    b[1] = (uint8_t)v;
}

static inline void put_be32(void *p, uint32_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

static inline void put_be64(void *p, uint64_t v)
{
    uint8_t *b = (uint8_t *)p;
    b[0] = (uint8_t)(v >> 56);
    b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40);
    b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24);
    b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >> 8);
    b[7] = (uint8_t)v;
}

#endif