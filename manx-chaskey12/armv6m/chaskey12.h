#ifndef CHASKEYEM12_H_
#define CHASKEYEM12_H_

#include <stdint.h>

#define KEY_SIZE            16

extern void chaskey12_enc(uint8_t* ctext, const uint8_t* ptext, const uint8_t* key);

#endif  // GIFT128_H_