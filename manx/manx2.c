/**
 * @file manx2.c
 * 
 * @brief Software implementation of the Manx2 authenticated encryption scheme.
 * See the paper at https://eprint.iacr.org/2023/361.pdf for more details.
 *
 * @author Alexandre Adomnicai <alexandre@adomnicai.me>
 *
 * @date March 2023
 * 
 * ~~~
 *   |\/\
 *  /,  ~\                _
 * X      `-.....-------./ |
 *  ~-. ~  ~               |
 *     \              /    |
 *      \  /_     ____\   /
 *      | /\ ~~~~~    \  |
 *      | | \         || |
 *      | |\ \        || )
 *     (_/ (_/       ((_/
 * ~~~
 */
#include "manx.h"
#include "manx-common.h"

/**
 * @brief Sets the separation domain as described in the Manx2 spec.
 *
 * @param out Byte array to be filled
 * @param oct Byte position within out
 * @param bit Bit position within bytpos
 * @param mlen Message length (in bits)
 * @param r Parameter r = n - (ν + α* + 2) as described in spec
 */
static inline void set_separation_domain(uint8_t *out,
                                        size_t *oct,
                                        size_t *bit,
                                        size_t mlen,
                                        size_t r)
{
    if (mlen < r) {         // domain separator = 10
        SETBIT(out[*oct], 7-*bit); 
        inc_bitpos(oct, bit, 2);
    } else if (mlen == r) { // domain separator = 11
        SETBIT(out[*oct], 7-*bit);
        inc_bitpos(oct, bit, 1);
        SETBIT(out[*oct], 7-*bit); 
        inc_bitpos(oct, bit, 1);
    } else {                // domain separator = 00
        inc_bitpos(oct, bit, 2);   
    }
}

static void init_tiny_msg(uint8_t b[],
                    const uint8_t n[], size_t nlen,
                    const uint8_t a[], size_t alen,
                    const uint8_t m[], size_t mlen)
{
    size_t oct;
    size_t bit;
    size_t r = BLOCKBITS - (nlen + MANX2_ALPHASTAR + 2);

    // build the input block N || xx || \bar{A} || pad_r(M) where xx refers to the domain separator
    for (size_t i = 0; i < BLOCKBYTES; i++)
        b[i] = 0x00;
    oct = 0;
    bit = 0;
    concat_bits(b, &oct, &bit, n, nlen);           // b <- N
    set_separation_domain(b, &oct, &bit, mlen, r); // b <- N || xx
    concat_bits(b, &oct, &bit, a, alen);           // b <- N || xx || A
#if MANX2_VARIABLE_ADLEN
    // one-zero padding to build \bar{A} from A
    SETBIT(b[oct], 7-bit);
    inc_bitpos(&oct, &bit, MANX2_ALPHASTAR - alen);
#endif
    concat_bits(b, &oct, &bit, m, mlen);           // b <- N || xx || \bar{A} || M
    SETBIT(b[oct], 7-bit);                         // b <- N || xx || \bar{A} || pad_r(M)
}

static void init_short_msg(uint8_t b[],
                     const uint8_t n[], size_t nlen,
                     const uint8_t a[], size_t alen,
                     const uint8_t m[], size_t mlen)
{
    size_t  oct;
    size_t  bit;
    uint8_t x[(mlen+7)/8];

    // build input block N || 00 || \bar{A} || M[1]
    for (size_t i = 0; i < BLOCKBYTES; i++)
        b[i] = 0x00;
    oct = 0; // current byte position in b is set to 0
    bit = 0; // current bit position in oct is set to 0
    concat_bits(b, &oct, &bit, n, nlen); // b <- N
    inc_bitpos(&oct, &bit, 2);           // b <- N || 00
    concat_bits(b, &oct, &bit, a, alen); // b <- N || 00 || A
#if MANX2_VARIABLE_ADLEN
    // one-zero pad the additional data
    SETBIT(b[oct], 7-bit);
    inc_bitpos(&oct, &bit, MANX2_ALPHASTAR - alen);
#endif
    concat_bits(b, &oct, &bit, m, mlen); // b <- N || 00 || \bar{A} || M[1]

    // save M[2] into x
    for (size_t i = 0; i < (mlen+7)/8; i++)
        x[i] = b[BLOCKBYTES + i];

    // decrease nlen by |M[1]|
    mlen -= BLOCKBITS - nlen - MANX2_ALPHASTAR - 2;

    // build input block N || 01 || pad(M[2])
    b += BLOCKBYTES;
    for (size_t i = 0; i < BLOCKBYTES; i++)
        b[i] = 0x00;
    oct = 0; // current byte position in b is set to 0
    bit = 0; // current bit position in oct is set to 0
    concat_bits(b, &oct, &bit, n, nlen); // b <- N
    inc_bitpos(&oct, &bit, 1);
    SETBIT(b[oct], 7-bit);
    inc_bitpos(&oct, &bit, 1);           // b <- N || 01
    concat_bits(b, &oct, &bit, x, mlen); // b <- N || 01 || M[2]
    SETBIT(b[oct], 7-bit);               // b <- N || 01 || pad_r(M[2])
}

int manx2_enc(uint8_t c[], size_t *clen,
            const uint8_t k[],
            const uint8_t n[], size_t nlen,
            const uint8_t m[], size_t mlen,
            const uint8_t a[], size_t alen,
            enc_func  encrypt,
            kexp_func kexpand)
{
    size_t r = BLOCKBITS - (nlen + MANX2_ALPHASTAR + 2);
    roundkeys_t roundkeys;

    // nlen has to be >= TAU to ensure BLOCKBITS/2-bit privacy and TAU-bit authenticity
    if (nlen < MANX_TAU) {
        *clen = 0;
        return 1;
    }
    // ensure the message length is consistent w/ other parameters
    if (mlen >= BLOCKBITS - nlen - 2 + r) {
        *clen = 0;
        return 2;
    }
    // ensure the associated data is not too large
    if(alen > MANX2_ALPHAMAX) {
        *clen = 0;
        return 3;
    }

    // precomputes the round keys
    kexpand(&roundkeys, k);

    // in case of tiny message
    if (mlen <= r) {
        uint8_t t[BLOCKBYTES];
        init_tiny_msg(t, n, nlen, a, alen, m, mlen);
        encrypt(c, t, &roundkeys); // C <- E_K(N || xx || \bar{A} || pad_r(M))
        *clen = 128;
    }
    // in case of short message
    else {
        uint8_t t[2*BLOCKBYTES];
        init_short_msg(t, n, nlen, a, alen, m, mlen);
        encrypt(c, t, &roundkeys);                                     // C[1] <- E_K(N || 00 || \bar{A} || M[1])
        encrypt(c + BLOCKBYTES, t + BLOCKBYTES, &roundkeys); // C[2] <- E_K(N || 01 || pad_r(M[2]))
        *clen = 256;
    }

    return 0;
}


int manx2_dec(uint8_t p[], size_t *plen,
            const uint8_t k[],
            const uint8_t n[], size_t nlen,
            const uint8_t c[], size_t clen,
            const uint8_t a[], size_t alen,
            dec_func  decrypt,
            kexp_func kexpand)
{
    size_t r = BLOCKBITS - (nlen + MANX2_ALPHASTAR + 2); // r ← n − (ν + α∗ + 2); 
    uint8_t  t[BLOCKBYTES]; // input block
    uint8_t s1[BLOCKBYTES]; // input block
    uint8_t ds;
    size_t oct;
    size_t bit;

    if (clen != BLOCKBITS && clen != 2*BLOCKBITS) {
            *plen = 0;
            return 1;
    }

    roundkeys_t roundkeys;
    kexpand(&roundkeys, k);

    if (clen == BLOCKBITS) {
        decrypt(s1, c, &roundkeys);
        init_tiny_msg(t, n, nlen, a, alen, c, 0);
        ds = GETBIT(s1[(nlen+1)/8], 7-((nlen+1)%8));
        CHGBIT(t[(nlen+1)/8], 7-((nlen+1)%8), ds);
        
        if (sec_memcmp_bits(s1, t, nlen + 2 + MANX2_ALPHASTAR)) {
            *plen = 0;
            return 2;
        }

        if (ds)
            *plen = clen;
        else
            *plen = depad_10(s1, s1);

        *plen -= nlen + 2 + MANX2_ALPHASTAR;
        lshift(p, s1 + (nlen + 2 + MANX2_ALPHASTAR) / 8, *plen, (nlen + 2 + MANX2_ALPHASTAR) % 8);
    }

    else {
        (void) n; // nonce is not required for decryption in case of short messages
        uint8_t s2[BLOCKBYTES];
        decrypt(s1, c, &roundkeys);
        decrypt(s2, c + BLOCKBYTES, &roundkeys);

        init_tiny_msg(t, s2, nlen, a, alen, c, 0);
        CLRBIT(t[(nlen+1)/8], 7-((nlen+1)%8));
        CLRBIT(t[nlen/8], 7-(nlen%8));

        // ensures \tilde{N}[1] == \tilde{N}[2] && \tilde{b}[1] == 00 && \tilde{A} == \bar{A}
        if (sec_memcmp_bits(s1, t, nlen + 2 + MANX2_ALPHASTAR)) {
            *plen = 0;
            return 3;
        }
        // ensures \tilde{b}[2] == 01
        if (GETBIT(s2[nlen/8], 7-(nlen%8)) != 0 || GETBIT(s2[(nlen+1)/8], 7-((nlen+1)%8)) != 1) {
            *plen = 0;
            return 4;
        }
        // M <- \tilde{M}[1] || depad_{r'}(\tilde{M}[2])
        *plen = r;

        lshift(p, s1 + (nlen + 2 + MANX2_ALPHASTAR) / 8, BLOCKBITS - (nlen + MANX2_ALPHASTAR + 2), (nlen + 2 + MANX2_ALPHASTAR) % 8);
        oct = r / 8;
        bit = r % 8;
        r   = depad_10(s2, s2);
        r  -= nlen + 2;

        lshift(s2, s2 + (nlen + 2) / 8, r, (nlen + 2) % 8);
        concat_bits(p, &oct, &bit, s2, r);
        *plen += r;
    }

    return 0;
}
