/****************************************************************************
* ARMv6-M implementation of Chaskey-EM-12 block cipher.
*
* @author   Alexandre Adomnicai
*
* @date     August 2023
****************************************************************************/

.syntax unified
.thumb

.text

.macro chaskey_round
    adds    r4, r5
    rors    r5, r0
    eors    r5, r4
    adds    r6, r7
    rors    r7, r1
    eors    r7, r6
    subs    r1, #8
    rors    r4, r1
    adds    r4, r7
    rors    r7, r2
    eors    r7, r4
    adds    r6, r5
    rors    r5, r3
    eors    r5, r6
    rors    r6, r1
    adds    r1, #8
.endm

@ void chaskey12_enc(u8 *ctext, const u8* ptext, const 8* key)
.global chaskey12_enc
.type   chaskey12_enc,%function
chaskey12_enc:
    push   {r0-r7}
    ldr    r4, [r1]
    ldr    r5, [r1, #4]
    ldr    r6, [r1, #8]
    ldr    r7, [r1, #12]
    ldr    r0, [r2]
    ldr    r1, [r2, #4]
    ldr    r3, [r2, #8]
    ldr    r2, [r2, #12]
    eors   r4, r0
    eors   r5, r1
    eors   r6, r3
    eors   r7, r2
    movs   r0, #32-5
    movs   r1, #32-8
    movs   r2, #32-13
    movs   r3, #32-7
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
    ldr    r2, [sp, #8]
    ldr    r0, [r2]
    ldr    r1, [r2, #4]
    ldr    r3, [r2, #8]
    ldr    r2, [r2, #12]
    eors   r4, r0
    eors   r5, r1
    eors   r6, r3
    eors   r7, r2
    ldr    r0, [sp]
    str    r4, [r0]
    str    r5, [r0, #4]
    str    r6, [r0, #8]
    str    r7, [r0, #12]
    pop    {r0-r7}
    bx     lr
