#ifndef BLOCK_CIPHER_H_
#define BLOCK_CIPHER_H_

#include <wmmintrin.h>
#include <stdint.h>

#define KEYBYTES    16
#define BLOCKBYTES  16

typedef struct { __m128i rk[11]; } roundkeys_t;

void aes128_kexp(roundkeys_t* roundkeys, const unsigned char k[KEYBYTES]);
void aes128_enc(unsigned char out[BLOCKBYTES], const unsigned char in[BLOCKBYTES], const roundkeys_t* roundkeys);
void aes128_dec(unsigned char out[BLOCKBYTES], const unsigned char in[BLOCKBYTES], const roundkeys_t* roundkeys);

#endif
