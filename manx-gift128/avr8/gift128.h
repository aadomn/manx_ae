#ifndef GIFT128_H_
#define GIFT128_H_

#define KEY_SIZE    16
#define BLOCK_SIZE  16

#include <stdint.h>

extern void giftb128_enc(uint8_t* out_block, const uint8_t* in_block, const uint32_t* rkey);

#endif  // GIFT128_H_
