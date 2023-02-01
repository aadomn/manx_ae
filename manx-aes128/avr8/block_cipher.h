#ifndef _BLOCK_CIPHER_H_
#define _BLOCK_CIPHER_H_

#define BLOCKBYTES 16

typedef struct {unsigned char rk[176];} roundkeys_t;

extern void aes128_kexp(roundkeys_t *roundkeys, const unsigned char* key);
extern void aes128_enc(unsigned char * out, const unsigned char *in, const roundkeys_t *roundkeys);
extern void aes128_dec(unsigned char * out, const unsigned char *in, const roundkeys_t *roundkeys);

#endif