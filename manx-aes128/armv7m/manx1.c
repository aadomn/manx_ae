/**
 * @file manx1.c
 * 
 * @brief Software implementation of the Manx1 authenticated encryption scheme
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
 * @brief Translate 4 bytes into a 32-bit word (little-endian encoding).
 *
 * @param a The input array
 * 
 * @return The corresponding 32-bit word
 */
static inline uint32_t GET_LE32(const uint8_t *a)
{
    return ((uint32_t)a[3] << 24) | ((uint32_t)a[2] << 16) | ((uint32_t)a[1] << 8) | (uint32_t)a[0];
}

/**
 * @brief Translate a 32-bit word into 4 bytes (little-endian encoding).
 *
 * @param a The output byte array
 * @param val The input 32-bit word
 */
static inline void PUT_LE32(uint8_t *a, uint32_t val)
{
    a[3] = (val >> 24) & 0xff;
    a[2] = (val >> 16) & 0xff;
    a[1] = (val >>  8) & 0xff;
    a[0] = (val >>  0) & 0xff;
}

/**
 * @brief Multiplication by x over GF(2^128) (i.e. doubling) using the
 * irreducible polynomial x^128 + x^7 + x^2 + x + 1.
 * Shift the 128-bit polynomial by 1 bit to the right, and add
 * 0...010000111 (= 0x87) if its MSB equals 1.
 *
 * @param poly Input/output 128-bit polynomial
 */
static inline void doubling(uint8_t *poly)
{
    uint32_t val;
    uint8_t cond = 0x00 - ((poly[15] & 0x80) >> 7);
    // 1st 32-bit word to shift
    val = GET_LE32(poly + 12);
    val <<= 1;
    val |= (poly[11] & 0x80) >> 7;
    PUT_LE32(poly + 12, val);
    // 2nd 32-bit word to shift
    val = GET_LE32(poly + 8);
    val <<= 1;
    val |= (poly[7] & 0x80) >> 7;
    PUT_LE32(poly + 8, val);
    // 3rd 32-bit word to shift
    val = GET_LE32(poly + 4);
    val <<= 1;
    val |= (poly[3] & 0x80) >> 7;
    PUT_LE32(poly + 4, val);
    // 4th 32-bit word to shift
    val = GET_LE32(poly);
    val <<= 1;
    val |= ((poly[3] & 0x80) >> 7);
    PUT_LE32(poly, val);
    // Add 0x87 if and only if MSB is set to 1
    poly[0] ^= 0x87 & cond;
}

/**
 * @brief Exclusive-OR between two 128-bit blocks.
 *
 * @param dst First operand and output
 * @param src Second operand
 */
static inline void xor_block(uint8_t *dst, const uint8_t *src1, const uint8_t *src2)
{
    uint32_t *d  = (uint32_t *) dst;
    uint32_t *s1 = (uint32_t *) src1;
    uint32_t *s2 = (uint32_t *) src2;
    *d++ = *s1++ ^ *s2++;
    *d++ = *s1++ ^ *s2++;
    *d++ = *s1++ ^ *s2++;
    *d++ = *s1++ ^ *s2++;
}

int manx1_aes128_enc(uint8_t c[], size_t *clen,
            const uint8_t k[],
            const uint8_t n[], size_t nlen,
            const uint8_t m[], size_t mlen,
            const uint8_t a[], size_t alen)
{
    size_t  oct;
    size_t  bit;
    uint8_t v[2*BLOCKBYTES];
    uint8_t *v1 = v;
    uint8_t *v2 = v + BLOCKBYTES;
    size_t  s   = MAX(BLOCKBITS - nlen + MANX_TAU , MANX1_ALPHAMAX);

    roundkeys_t roundkeys;
    aes128_keyschedule_ffs_lut(roundkeys.rk, k);

    // ensure that |M| < n − τ
    if (mlen >= BLOCKBITS - MANX_TAU) {
        *clen = 0;
        return 1;
    }
    // ensure that [AD| < α_max
    if (alen > MANX1_ALPHAMAX) {
        *clen = 0;
        return 2;
    }
    // ensure that |M| < n - |V[2]|
    if (mlen >= BLOCKBITS - (s - (BLOCKBITS - nlen))) {
        *clen = 0;
        return 3;
    }

    // build (V[1],V[2]) <- vencode(N,A)
    for (size_t i = 0; i < 2*BLOCKBYTES; i++)
        v[i] = 0x00;
    oct = 0; // current byte position in b is set to 0
    bit = 0; // current bit position in oct is set to 0
    concat_bits(v, &oct, &bit, n, nlen);
    concat_bits(v, &oct, &bit, a, alen);
#if MANX1_VARIABLE_ADLEN
    // one-zero padding to build \bar{A} from A
    SETBIT(v[oct], 7-bit);
    inc_bitpos(&oct, &bit, s - alen);
#endif

    // append pad_{n-v2}(M) to (V[1],V[2])
    concat_bits(v, &oct, &bit, m, mlen);
    SETBIT(v[oct], 7-bit);

    // V[1] <- E_K(V[1])
    aes128_encrypt_ffs(v1, v1, v1, v1, roundkeys.rk);

    // V[1] <- 2V[1]
    doubling(v1);

    // V[2] <- V[1] ^ (V[2] || pad_{n-v2}(M))
    xor_block(v2, v2, v1);

    // C <- E_K(V[2])
    aes128_encrypt_ffs(c, v2, c, v2, roundkeys.rk);

    // C <- C ^ V[1]
    xor_block(c, c, v1);  

    *clen = BLOCKBITS;
    return 0;
}
