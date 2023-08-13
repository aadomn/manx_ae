#ifndef GIFT128_H_
#define GIFT128_H_

#include <stdint.h>

#define KEY_SIZE            16

extern void giftb128_encrypt_block(uint8_t* out_block, const uint8_t* in_block, const uint32_t* rkey);

#endif  // GIFT128_H_