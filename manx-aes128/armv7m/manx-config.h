#ifndef MANX_CONFIG_H_
#define MANX_CONFIG_H_

/**
 *  Preprocessor directive to indicate whether variable AD length is supported.
 */
#define MANX1_VARIABLE_ADLEN 1
/**
 *  Maximal AD length (in bits) allowed in the Manx2 AEAD scheme.
 */
#define MANX1_ALPHAMAX 64

/**
 *  Preprocessor directive to indicate whether variable AD length is supported.
 */
#define MANX2_VARIABLE_ADLEN 0
/**
 *  Maximal AD length (in bits) allowed in the Manx2 AEAD scheme.
 */
#define MANX2_ALPHAMAX 16

#endif
