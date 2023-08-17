#ifndef CHASKEYEM12_H_
#define CHASKEYEM12_H_

#include <stdint.h>

#define BLOCKBYTES 16

// Chaskey-EM-12 does not require any key expansion (Even-Mansour scheme)
typedef struct { } roundkeys_t;

extern void chaskey12_enc(uint8_t* ctext, const uint8_t* ptext, const uint8_t* key);

#endif  // CHASKEYEM12_H_