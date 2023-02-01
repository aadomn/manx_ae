#include <stdio.h>
#include <string.h>
#include "../manx.h"

int main(void) {
    uint8_t ad[16]        = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t nonce[16]     = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t key[16]       = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t ptext[16]     = {0x7f, 0x43, 0xf6, 0xaf, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t ctext[32]     = {0x00};
    uint8_t ptext_bis[16] = {0x00};
    size_t outlen;

    int ret = manx1_enc(ctext, &outlen, key, nonce, 96, ptext, 30, ad, 64, aes128_enc, aes128_kexp);
    printf("manx1_enc (96, 30, 64) returned ret = %d and outlen = %ld\n", ret, outlen);
    for(int i = 0; i < 16; i++)
      printf("%02x", ctext[i]);
    printf("\n");
    ret = manx1_dec(ptext_bis, &outlen, key, nonce, 96, ctext, outlen, ad, 64, aes128_enc, aes128_dec, aes128_kexp);
    printf("manx1_dec (96, 30, 64) returned %d and outlen = %ld\n", ret, outlen);
    for(int i = 0; i < 16; i++)
      printf("%02x", ptext_bis[i]);
    printf("\n");

    ret = manx1_enc(ctext, &outlen, key, nonce, 128, ptext, 63, ad, 0, aes128_enc, aes128_kexp);
    printf("manx1_enc (128, 63, 0) returned ret = %d and outlen = %ld\n", ret, outlen);
    for(int i = 0; i < 16; i++)
      printf("%02x", ctext[i]);
    printf("\n");
    ret = manx1_dec(ptext_bis, &outlen, key, nonce, outlen, ctext, outlen, ad, 0, aes128_enc, aes128_dec, aes128_kexp);
    printf("manx1_dec (128, 63, 0) returned %d and outlen = %ld\n", ret, outlen);
    for(int i = 0; i < 16; i++)
      printf("%02x", ptext_bis[i]);
    printf("\n");

    ret = manx2_enc(ctext, &outlen, key, nonce, 64, ptext, 96, ad, 0, aes128_enc, aes128_kexp);
    printf("manx2_enc (64, 96, 0) returned ret = %d and outlen = %ld\n", ret, outlen);
    for(int i = 0; i < 16; i++)
      printf("%02x", ctext[i]);
    printf("\n");
    ret = manx2_dec(ptext_bis, &outlen, key, nonce, 64, ctext, outlen, ad, 0, aes128_dec, aes128_kexp);
    printf("manx2_dec (64, 96, 0) returned %d and outlen = %ld\n", ret, outlen);
    for(int i = 0; i < 16; i++)
      printf("%02x", ptext_bis[i]);
    printf("\n");

}
