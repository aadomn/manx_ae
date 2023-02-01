# Manx-AES128 on ARMv7-M

## General information
This folder contains implementations of Manx1-AES128 and Manx2-AES128 relying on a constant-time AES implementation based on an optimized instance of bitslicing named *fixslicing*, taken from [this repository](https://github.com/aadomn/aes).

Because the API of the fixsliced AES on this platform does not match the one required by our cipher-agnostic approach for Manx (due to the fact that two blocks are processed in parallel), we simply discarded hardcoded the function calls instead of passing the functions as input parameters. The fact that Manx2 allows to parallelize the two cipher calls makes it very efficient when instantiated with parallel implementations such as the one used here.
Note that this folder implements the encryption functions only, since the fixsliced AES decryption function has not been written in ARMv7-M assembly language yet.

## Performance

You can find below performance measurements (in clock cycles) for some parameter sets. These results were obtained on an STM32F407VG microcontroller with `arm-none-eabi-gcc 10.3.1`.

| Parameters (ν, α, l) | Algorithm                    | ARM Cortex-M4 |
|:---------------------|:----------------------------:|:-------------:|
| (64, 0, 120)         | Manx1-AES128<br>Manx2-AES128 | -<br>5400     |
| (96, 0,  56)         | Manx1-AES128<br>Manx2-AES128 | 7800<br>5200  |
| (64, 16, 44)         | Manx1-AES128<br>Manx2-AES128 | 7800<br>5000  |

where (ν, α, l) refer to nonce, associated data and message lengths in bits, respectively. Note that `MANX1_ALPHAMAX` and `MANX2_ALPHAMAX` have been set to α in each case.
Also note that all the results reported in the above table include the key expansion, pre-computing it would save ~1500 clock cycles.