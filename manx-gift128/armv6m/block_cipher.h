#ifndef GIFT128_H_
#define GIFT128_H_

#include <stdint.h>

#define BLOCKBYTES 16

// In our paper, Manx-GIFT128 benchmarks assume precomputed roundkeys
typedef struct { } roundkeys_t;

extern void giftb128_encrypt_block(uint8_t* out_block, const uint8_t* in_block, const uint32_t* rkey);

#endif  // GIFT128_H_