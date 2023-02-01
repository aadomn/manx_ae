#ifndef MANX_H_
#define MANX_H_

#include <stdint.h>
#include <stddef.h>
#include "manx-config.h"
#include "aes.h"

/**
 *  Bit-length of the underlying block cipher
 */
#define BLOCKBITS  BLOCKBYTES*8
/**
 *  τ refers to the authenticity security level (in bits)
 */
#define MANX_TAU BLOCKBITS/2
/**
 *  Length of the padded AD in the Manx2 AEAD scheme.
 */
#define MANX2_ALPHASTAR (MANX2_ALPHAMAX+MANX2_VARIABLE_ADLEN)


/**
 * Function type for the key expansion.
 */
typedef void (kexp_func)(roundkeys_t*, const uint8_t*);
/**
 * Function type for the block encryption.
 */
typedef void (enc_func)(uint8_t*, const uint8_t*, const roundkeys_t*);
/**
 * Function type for the block decryption..
 */
typedef void (dec_func)(uint8_t*, const uint8_t*, const roundkeys_t*);


/**
 * @brief Authenticated encryption using Manx1.
 *
 * @param c The output ciphertext (should be at least 16-byte long)
 * @param clen The length of the ciphertext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bits)
 * @param m The message to secure
 * @param mlen The message length (in bits)
 * @param a The additional data to authenticate
 * @param alen The additional data length (in bits)
 * @param encrypt The block encryption function of the underlying block cipher
 * @param kexpand The block key expansion function of the underlying block cipher
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int manx1_enc(uint8_t c[], size_t *clen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t m[], size_t mlen,
        const uint8_t a[], size_t alen,
        enc_func  encrypt,
        kexp_func kexpand);

/**
 * @brief Authenticated decryption using Manx1.
 *
 * @param p The output plaintext
 * @param plen The length of the plaintext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bits)
 * @param c The ciphertext to decrypt/verify
 * @param clen The ciphertext length (in bits)
 * @param a The additional data
 * @param alen The additional data length (in bits)
 * @param encrypt The block encryption function of the underlying block cipher
 * @param decrypt The block decryption function of the underlying block cipher
 * @param kexpand The key expansion function of the underlying block cipher
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int manx1_dec(uint8_t p[], size_t *plen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t c[], size_t clen,
        const uint8_t a[], size_t alen,
        enc_func  encrypt,
        dec_func  decrypt,
        kexp_func kexpand);

/**
 * @brief Authenticated encryption using Manx2.
 *
 * @param c The output ciphertext
 * @param clen The length of the ciphertext
 * @param k The encryption key
 * @param n The nonce
 * @param nlen The nonce length (in bits)
 * @param m The message to secure
 * @param mlen The message length (in bits)
 * @param a The additional data to authenticate
 * @param alen The additional data length (in bits)
 * @param encrypt The block encryption function of the underlying block cipher
 * @param kexpand The block key expansion function of the underlying block cipher
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int manx2_enc(uint8_t c[], size_t *clen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t m[], size_t mlen,
        const uint8_t a[], size_t alen,
        enc_func  encrypt,
        kexp_func kexpand);

/**
 * @brief Authenticated decryption using Manx2.
 *
 * @param p The output plaintext
 * @param plen The length of the plaintext
 * @param k The encryption key
 * @param n The nonce (optional for short messages)
 * @param nlen The nonce length (in bits)
 * @param c The ciphertext to decrypt/verify
 * @param clen The ciphertext length (in bits)
 * @param a The additional data
 * @param alen The additional data length (in bits)
 * @param encrypt The block encryption function of the underlying block cipher
 * @param kexpand The key expansion function of the underlying block cipher
 * 
 * @return 0 if successfully executed, error code otherwise
 */
int manx2_dec(uint8_t p[], size_t *plen,
        const uint8_t k[],
        const uint8_t n[], size_t nlen,
        const uint8_t c[], size_t clen,
        const uint8_t a[], size_t alen,
        enc_func  decrypt,
        kexp_func kexpand);

#endif