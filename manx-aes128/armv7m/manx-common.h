#ifndef MANX_COMMON_H_
#define MANX_COMMON_H_

/**
 *  Return the largest value of {x,y}.
 */
#define MAX(x, y) (((x) < (y)) ? (y) : (x))
/**
 *  Get i-th bit of x.
 */
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
/**
 *  Set i-th bit of x to 1.
 */
#define SETBIT(x, i) ((x) = (x) | ((1UL) << (i)))
/**
 *  Set i-th bit of x to 0.
 */
#define CLRBIT(x, i) ((x) = (x) & ~(1UL << (i)))
/**
 *  Set i-th bit of x to b.
 */
#define CHGBIT(x, i, b) ((x) = (x) ^ ((-(b) ^ (x)) & (1UL << (i))))

/**
 * @brief Given a bit position within an octet, increases its
 * position by a certain amount.
 *
 * @param oct The octet position within a byte array
 * @param bit The bit position within a byte
 * @param val The value to increase the bit position
 */
static inline void inc_bitpos(size_t *oct, size_t *bit, int val)
{
    *bit += val;
    while(*bit >= 8) {
        *oct += 1;
        *bit -= 8;
    }
}

/**
 * @brief Shift a byte array to the right by a certain amount of bits.
 *
 * @param out The shifted byte array
 * @param in The input byte array
 * @param inlen The number of bits to consider in the input byte array
 * @param b The number of bits to shift
 */
static inline void rshift(uint8_t out[], const uint8_t in[], size_t inlen, size_t b)
{   
    uint8_t tmp;
    uint8_t mask = (1 << b) - 1;
    int     i = 0;

    out[0] = 0x00;

    // while we can manipulate plain bytes
    while (inlen >= 8) {
        tmp      = in[i];
        out[i]  |= tmp >> b;
        out[++i] = (tmp & mask) << (8-b);
        inlen   -= 8;
    }
    // if the input is not byte aligned, ignore the least significant bits
    if (inlen) {
        tmp     = in[i] & (0xff << (8-inlen));
        out[i] |= tmp >> b;
        if (inlen > 8-b)
            out[++i] = tmp << (8-b);
    }
}

/**
 * @brief Shift a byte array to the left by a certain amount of bits.
 *
 * @param out The shifted byte array
 * @param in The input byte array
 * @param inlen The number of bits to consider in the input byte array
 * @param b The number of bits to shift
 */
static inline void lshift(uint8_t out[], const uint8_t in[], size_t inlen, size_t b)
{   
    int     i = 0;
    uint8_t mask = 0xff << (8-b);

    // while we can manipulate plain bytes
    while (inlen >= 8) {
        out[i]  = in[i] << b;
        out[i] |= (in[i+1] & mask) >> (8-b);
        inlen  -= 8;
        i++;
    }
    // if the input is not byte aligned, ignore the least significant bits
    if (inlen) {
        mask   = 0xff << (8-inlen);
        out[i] = (in[i] << b) & mask;
        if (inlen > 8-b)
            out[i] |= (in[i+1] & (mask << (8-b))) >> (8-b);
    }
}

/**
 * @brief Concatenate bits into a byte array which is not-necessarily byte aligned.
 *
 * @param out The byte array to be filled
 * @param oct The byte position after concatenating the bits
 * @param bit The bit position within oct after concatenating the bits
 * @param in The input bits to concatenate
 * @param inlen The number of bits to concatenate
 */
static inline void concat_bits(uint8_t out[], size_t *oct, size_t *bit, const uint8_t in[], size_t inlen)
{
	size_t octlen;
    size_t bitmod = (inlen + *bit) % 8;

	// the output array now points to the current byte
    out += *oct;

    // if the output is not byte aligned
    if (*bit) {
        octlen = (inlen + *bit + 7) / 8; // +7 for ceiling division
        // shift the input to the right in a temporary array
        uint8_t tmp = out[0];
        rshift(out, in, inlen, *bit);
        // append the bits to the output
        out[0] |= tmp;
        // increase the byte position accordingly
        *oct += octlen - (bitmod != 0);
	}
	// if the output is byte aligned
	else {
	    octlen = inlen / 8;
	    // simply copy each plain byte sequentially
	    for (size_t i = 0; i < octlen; i++)
	        out[i] = in[i];
	    // if inlen is not a multiple of 8 bits, append the remaining bits
	    if (bitmod)
	        out[octlen] = in[octlen] & (0xff << (8 - bitmod));
	    // increase the byte position accordingly
	    *oct += octlen;
	}

	// set the new bit position within new byte position
    *bit = bitmod;
}

/**
 * @brief Depad one-zero padded input.
 * 
 * @param out The output unpadded block
 * @param in The input block
 * 
 * @return The number of output bits after depadding
 */
static inline size_t depad_10(uint8_t *out, const uint8_t in[BLOCKBYTES])
{
    size_t bytes  = BLOCKBYTES - 1;
    size_t outlen = BLOCKBITS  - 1;
    size_t bit;
    size_t tmp;

    // decrement outlen while we did not find a bit equals to 1
    while (bytes) {
        tmp = in[bytes--];
        for (bit = 0; bit < 8; bit++, outlen--) {
            if (tmp & (1 << bit)) {
                bytes = 0;
                break;
            }
        }
    }
    // copy outlen bits from input to output
    for(size_t i = 0; i < outlen/8; i++)
        out[i] = in[i];
    out[(outlen+7)/8] = tmp & (0xff << (8-bit));

    return outlen;
}

/**
 * @brief Constant-time comparison between two byte arrays for a given number of bits.
 * 
 * @param arr1 The first byte array
 * @param arr1 The second byte array
 * @param bitlen The number of bits taken into account for the comparison
 * 
 * @return 0 if the two arrays are equal, non-zero value otherwise
 */
static inline int sec_memcmp_bits(const uint8_t *arr1, const uint8_t *arr2, size_t bitlen)
{
    size_t    i = 0;
    uint8_t ret = 0x00; 

    while(bitlen >= 8) {
        ret    |= arr1[i] ^ arr2[i];
        bitlen -= 8;
        i      += 1;
    }
    if (bitlen)
        ret |= (arr1[i] ^ arr2[i]) & (0xff << (8-bitlen));

    return ret;
}

#endif
