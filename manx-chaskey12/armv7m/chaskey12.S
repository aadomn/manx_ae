/****************************************************************************
* ARMv7-M implementation of Chaskey12 block cipher.
*
* @author   Alexandre Adomnicai
*
* @date     July 2023
****************************************************************************/

.syntax unified
.thumb

.text

.macro chaskey_round
    add.w   r4, r5
    eor.w   r5, r4, r5, ror #32-5
    add.w   r6, r7
    eor.w   r7, r6, r7, ror #32-8
    add.w   r4, r7, r4, ror #16
    eor.w   r7, r4, r7, ror #32-13
    add.w   r6, r5
    eor.w   r5, r6, r5, ror #32-7
    ror.w   r6, r6, #16
.endm

@ void chaskey12_enc(u8 *ctext, const u8* ptext, const 8* key)
.global chaskey12_enc
.type   chaskey12_enc,%function
.align 4
chaskey12_enc:
    push        {r4-r10}
    ldr.w         r4, [r1]
    ldr.w         r5, [r1, #4]
    ldr.w         r6, [r1, #8]
    ldr.w         r7, [r1, #12]
    // key whitening
    ldr.w         r3, [r2]
    ldr.w         r8, [r2, #4]
    ldr.w         r9, [r2, #8]
    ldr.w         r10, [r2, #12]
    eor.w        r4, r3
    eor.w        r5, r8
    eor.w        r6, r9
    eor.w        r7, r10
    // Chaskey-12
    chaskey_round
    chaskey_round
    chaskey_round
    chaskey_round
    chaskey_round
    chaskey_round
    chaskey_round
    chaskey_round
    chaskey_round
    chaskey_round
    chaskey_round
    chaskey_round
    // key whitening
    ldr.w   r3, [r2]
    ldr.w   r8, [r2, #4]
    ldr.w   r9, [r2, #8]
    ldr.w   r10, [r2, #12]
    eor.w   r4, r3
    eor.w   r5, r8
    eor.w   r6, r9
    eor.w   r7, r10
    // store ciphertext
    str.w   r4, [r0]
    str.w   r5, [r0, #4]
    str.w   r6, [r0, #8]
    str.w   r7, [r0, #12]
    pop     {r4-r10}
    bx      lr
