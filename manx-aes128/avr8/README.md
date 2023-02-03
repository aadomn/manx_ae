# Manx-AES128 on 8-bit AVR

## General information
This folder contains implementations of Manx1-AES128 and Manx2-AES128 relying on very efficient AES implementations on AVR, taken from [this website](http://point-at-infinity.org/avraes/).
The original code has been slightly reworked to meet the API requirements of our generic/cipher-agnostic Manx implementations.

The benchmarks presented in the Table 1 of [our paper](https://eprint.iacr.org/) rely on the fastest variant, namely RijndaelFast, included in this folder for reproducibility purposes. However, this variant has the disadvantage of a large code-size and requires to adapt the round key material for the decryption function. For theses reasons the decryption function is not included for this variant.
For the sake of completeness, this folder also includes the RijndaelFurious variant, which is slightly slower but more compact and uses the same round key material for both encryption and decryption.

When compiling, make sure to not consider `rijndaelfast.s` and `rijndaelfurious.s` simultaneously as it would result in naming collisions for the AES functions.

## Performance

You can find below performance measurements (in clock cycles, rounded to the nearest 100th) for some parameter sets. These results were obtained using Microchip Studio v7.0.2594 in debugging mode with `avr-gcc 12.1.0`.

| Parameters (ν, α, l) | Algorithm                    | ATMega128     |
|:---------------------|:----------------------------:|:-------------:|
| (64, 0, 120)         | Manx1-AES128<br>Manx2-AES128 | -<br>8400     |
| (96, 0,  56)         | Manx1-AES128<br>Manx2-AES128 | 6500<br>7600  |
| (64, 16, 44)         | Manx1-AES128<br>Manx2-AES128 | 6600<br>4600  |

where (ν, α, l) refer to nonce, associated data and message lengths in bits, respectively. Note that `MANX1_ALPHAMAX` and `MANX2_ALPHAMAX` have been set to α in each case.
Also note that all the results reported in the above table include the key expansion, pre-computing it would save ~800 clock cycles.

## Manx2 optimizations for fixed nonce and AD lengths

As stated in Section 4.2 of our paper, Manx2 spend many cycles to format the input blocks 8-bit AVR platforms. This is because our Manx implementations are written to work with any (supported) parameter set (ν, α, l) and the 8-bit AVR shift instruction can only shift a single bit at a time. However, if ν and α are fixed, then one should take advantage of this to rewrite the `concat_bits` and `rshift` functions in `manx-common.h` in order to efficiently concatenate the message into the input blocks.
For instance, if ν and α both consist of plain bytes (i.e. ν mod 8 = α mod 8 = 0), then we can hard code the last input parameter of `rshift` to 2, resulting in the following function:
```
/**
 * Shift an input byte array two bits to the right.
 */
static inline void rshift_2(uint8_t out[], const uint8_t in[], size_t inlen)
{   
    uint8_t tmp;
    int     i = 0;

    out[0] = 0x00;

    // while we can manipulate plain bytes
    while (inlen >= 8) {
        tmp      = in[i];
        out[i]  |= tmp >> 2;
        out[++i] = (tmp & 0x3) << 6;
        inlen   -= 8;
    }
    // if the input is not byte aligned, ignore the least significant bits
    if (inlen) {
        tmp     = in[i] & (0xff << (8-inlen));
        out[i] |= tmp >> 2;
        if (inlen > 6)
            out[++i] = tmp << 6;
    }
}
```
and rely on it to concatenate the message into our internal input blocks.
This allows the compiler to make further optimizations that are not possible when the amount of bit to shift is not hard coded. 

By following this strategy, the performance are now

| Parameters (ν, α, l) | Algorithm    | ATMega128     |
|:---------------------|:------------:|:-------------:|
| (64, 0, 120)         | Manx2-AES128 | 7500          |
| (96, 0,  56)         | Manx2-AES128 | 7100          |
| (64, 16, 44)         | Manx2-AES128 | 4200          |

One can even go further by implementing a dedicated assembly routine for the shift instructions instead of using the C bitwise operations `<< 2` and `>> 6` as described in [this post](https://aykevl.nl/2021/02/avr-bitshift).
