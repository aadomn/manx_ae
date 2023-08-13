/****************************************************************************
* ARMv6-M assembly implementation of the GIFT-128 block cipher.
* See "Fixslicing: A New GIFT Representation" paper available at 
* https://eprint.iacr.org/2020/412.pdf for more details.
*
* @author   Alexandre Adomnicai
*
* @date     August 2023
****************************************************************************/

.syntax unified
.thumb

.text

/******************************************************************************
* Macro to compute the SWAPMOVE technique.
*   - out0-out1     output registers
*   - in0-in1       input registers
*   - m             mask
*   - n             shift value
*   - tmp           temporary register
******************************************************************************/
.macro swpmv   reg, m, n, tmp
	lsrs	\tmp, \reg, \n
    eors     \tmp, \reg
    ands     \tmp, \m
    eors     \reg, \tmp
    lsls	\tmp, \tmp, \n
    eors     \reg, \tmp
.endm

/******************************************************************************
* Same as `swpmv` but where the two operands are distinct registers.
******************************************************************************/
.macro swpmv_bis   reg0, reg1, m, n, tmp
    lsrs    \tmp, \reg0, \n
    eors     \tmp, \reg1
    ands     \tmp, \m
    eors     \reg1, \tmp
    lsls    \tmp, \tmp, \n
    eors     \reg0, \tmp
.endm

/******************************************************************************
* Macro to compute a nibble-wise rotation to the right.
*   - out           output register
*   - in            input register
*   - m0-m1         masks
*   - n0-n1         shift value
*   - tmp           temporary register
******************************************************************************/
.macro nibror  reg, m0, m1, n0, n1, tmp
	lsrs	\tmp, \reg, \n0
    ands     \tmp, \m0
    ands     \reg, \m1
    lsls	\reg, \n1
    orrs     \reg, \tmp
.endm

/******************************************************************************
* Macro to compute the SBox (the NOT operation is included in the round keys).
*   - in0-in3       input/output registers
*   - tmp           temporary register
*   - n             rorsindex value to math fixslicing
******************************************************************************/
.macro sbox     in0, in1, in2, in3, tmp
    mov     \tmp, \in0
    ands    \tmp, \tmp, \in2
    eors    \in1, \in1, \tmp
    mov     \tmp, \in1
    ands    \tmp, \tmp, \in3
    eors    \in0, \tmp, \in0
    mov     \tmp, \in1
    orrs    \tmp, \in0, \tmp
    eors    \in2, \tmp, \in2
    eors    \in3, \in3, \in2
    eors    \in1, \in1, \in3
    mov     \tmp, \in1
    ands    \tmp, \in0, \tmp
    eors    \in2, \in2, \tmp
    mvns    \in3, \in3
.endm

/******************************************************************************
* Macro to compute the first round within a quintuple round routine.
*   - in0-in3       input/output registers
*   - const0-const1 round constants
*   - idx           ror index to be used in the sbox (to match fixslicing)
******************************************************************************/
.macro round_0  in0, in1, in2, in3
    sbox    \in0, \in1, \in2, \in3, r2    // sbox layer
    mov	r2, r9
    mov	r3, r10
    nibror \in3, r3, r2, 1, 3, r0        // linear layer
    nibror \in2, r2, r3, 3, 1, r0        // linear layer
    lsls	r3, r2, #1
    orrs     r3, r3, r2 							// 0x33333333 for 'nibror'
    nibror \in1, r3, r3, 2, 2, r0      	// linear layer
    ldmia   r1!, {r2,r3}
    eors     \in1, \in1, r2                      // add 1st rkey word
    eors     \in2, \in2, r3                      // add 2nd rkey word
    mov     r0, r11
    ldmia   r0!, {r2}
    mov     r11, r0
    eors     \in0, \in0, r2                      // add rconst
.endm

/******************************************************************************
* Macro to compute the second round within a quintuple round routine.
*   - in0-in3       input/output registers
*   - const0-const1 round constants
******************************************************************************/
.macro round_1  in0, in1, in2, in3
    sbox    \in0, \in1, \in2, \in3, r0      // sbox layer
    mov	    r3, r8
    lsls    r2, r3, #12                    		// r0<-0x0fff0fff for HALF_ROR
    mvns    r2, r2                    			// r0<-0x0fff0fff for HALF_ROR
    nibror \in3, r2, r3,  4, 12, r0    	// HALF_ROR(in3, 4)
    nibror \in2, r3, r2, 12,  4, r0 		// HALF_ROR(in2, 12)
    rev16   \in1, \in1                          // HALF_ROR(in1, 8)
    ldmia   r1!, {r2,r3}
    eors     \in1, r2                      // add 1st rkey word
    eors     \in2, r3                      // add 2nd rkey word

    mov     r0, r11
    ldmia   r0!, {r2}
    mov     r11, r0
    eors     \in0, r2                      // add rconst
.endm

/******************************************************************************
* Macro to compute the third round within a quintuple round routine.
*   - in0-in3       input/output registers
*   - const0-const1 round constants
******************************************************************************/
.macro round_2  in0, in1, in2, in3
    sbox    \in0, \in1, \in2, \in3, r0      // sbox layer
    mov	    r2, r9
    lsls	r3, r2, #2
    orrs    r3, r2 							// r3<-0x55555555 for swpmv
    swpmv   \in1, r3, #1, r0
    lsrs	r2, \in3, #1
    eors    r2, \in3
    lsrs	r0, r3, #16
    ands    r2, r0
    eors    \in3, r2
    lsls	r2, r2, #1
    eors    \in3, r2              //SWAPMOVE(r12,r12,0x55550000,1)
    lsrs	r2, \in2, #1
    eors    r2, \in2
    lsls	r0, r3, #16
    ands    r2, r0
    eors    \in2, r2
    lsls	r2, r2, #1
    eors    \in2, r2              		//SWAPMOVE(r11,r11,0x00005555,1)
    movs	r0, #16
    rors	\in2, r0
    ldmia   r1!, {r2,r3}
    eors    \in1, r2                      // add 1st rkey word
    eors    \in2, r3             			// add 2nd rkey word
    mov     r0, r11
    ldmia   r0!, {r2}
    mov     r11, r0
    eors     \in0, r2                      // add rconst
.endm

/******************************************************************************
* Macro to compute the fourth round within a quintuple round routine.
*   - in0-in3       input/output registers
*   - const0-const1 round constants
******************************************************************************/
.macro round_3  in0, in1, in2, in3
    movs    r0, #16
    rors    \in0, r0
    sbox    \in0, \in1, \in2, \in3, r0     // sbox layer
    mov	    r3, r8
    lsls	r2, r3, #8
    eors    r2, r3 							// r2<-0x0f0f0f0f for swpmv
    nibror \in1, r2, r2, #4, #4, r0
    lsls	r0, r2, #2
    orrs    r2, r0 							// r2<-0x3f3f3f3f for nibror
    mvns    r3, r2
    lsrs    r3, #6                          // r3<-0x03030303 for nibror
    nibror \in2, r2, r3, #2, #6, r0
    nibror \in3, r3, r2, #6, #2, r0
    ldmia   r1!, {r2,r3}                    // load round keys
    eors     \in1, r2                      // add 1st rkey word
    eors     \in2, r3                      // add 2nd rkey word
    mov     r0, r11
    ldmia   r0!, {r2}
    mov     r11, r0
    eors     \in0, r2                      // add rconst
.endm

/******************************************************************************
* Macro to compute the fifth round within a quintuple round routine.
*   - in0-in3       input/output registers
*   - const0-const1 round constants
******************************************************************************/
.macro round_4  in0, in1, in2, in3
    sbox    \in0, \in1, \in2, \in3, r0      // sbox layer
    movs	r0, #16             				
    rors	\in1, r0
    movs	r0, #8             					
    rors	\in2, r0
    ldmia   r1!, {r2,r3}
    eors     \in1, r2 						// add 1st keyword
    eors     \in2, r3 						// add 2nd keyword
    mov     r0, r11
    ldmia   r0!, {r2}
    mov     r11, r0
    eors     \in0, r2                      // add rconst
.endm

quintuple_round:
    round_0     r4, r5, r6, r7
    round_1     r7, r5, r6, r4
    round_2     r4, r5, r6, r7
    round_3     r7, r5, r6, r4
    round_4     r4, r5, r6, r7
    movs        r0, #24
    rors        r7, r0
    eors        r4, r4, r7
    eors        r7, r7, r4
    eors        r4, r4, r7
    bx          lr


/*****************************************************************************
* ARMv6-M assembly implementation of the GIFTb-128 block cipher.
* This function simply encrypts a 128-bit block, without any operation mode.
*****************************************************************************/
@ void gift128_encrypt_block(u8 *out, const u32* rkey,
@       const u8 *block) {
.global gift128_encrypt_block
.type   gift128_encrypt_block,%function
gift128_encrypt_block:
    push    {r0-r7}
    sub     sp, #20
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    mov     r0, r14
    str     r7, [sp]
    str     r6, [sp, #4]
    str     r5, [sp, #8]
    str     r4, [sp, #12]
    str     r0, [sp, #16]
    ldr     r4, [r1]
    ldr     r5, [r1, #4]
    ldr     r6, [r1, #8]
    ldr     r7, [r1, #12]
    adr     r3, rconst
    mov     r11, r3     // save rconst pointer to r11
    mov     r1, r2      // mov rkey pointer to r1
    rev     r4, r4      // endianess to match fixsliced representation
    rev     r5, r5      // endianess to match fixsliced representation
    rev     r6, r6      // endianess to match fixsliced representation
    rev     r7, r7      // endianess to match fixsliced representation
    // ------------------ PACKING ------------------ 
    uxth    r2, r5
    uxth    r3, r7
    lsls    r2, #16
    orrs    r3, r3, r2             // r3 <- block[6-7] || block[14-15]
    movs    r0, #16
    rors    r5, r0
    uxth    r2, r5
    rors    r7, r0
    uxth    r7, r7
    lsls    r2, #16
    uxth    r7, r7
    orrs    r7, r7, r2      // r10
    uxth    r2, r4
    uxth    r5, r6
    rors    r6, r0
    rors    r4, r0
    lsls    r2, #16
    orrs    r5, r5, r2      // r11
    uxth    r4, r4
    uxth    r6, r6
    lsls    r4, #16
    orrs    r6, r6, r4      // r12
    mov     r4, r3
    mov     r0, r6
    mov     r6, r5
    mov     r5, r7
    mov     r7, r0
    // r2 <- 0x0a0a0a0a
    movs    r2, #0x0a
    lsls    r0, r2, #8
    orrs    r2, r2, r0
    lsls    r0, r2, #16
    orrs    r2, r2, r0
    swpmv   r4, r2, #3, r0
    swpmv   r5, r2, #3, r0
    swpmv   r6, r2, #3, r0
    swpmv   r7, r2, #3, r0
    // r2 <- 0x00cc00cc
    movs    r2, #0xcc
    lsls    r0, r2, #16
    orrs    r2, r2, r0
    swpmv   r4, r2, #6, r0
    swpmv   r5, r2, #6, r0
    swpmv   r6, r2, #6, r0
    swpmv   r7, r2, #6, r0
    // r2 <- 0x000f000f
    movs    r2, #0x0f
    lsls    r0, r2, #16
    orrs    r2, r2, r0
    swpmv_bis   r4, r5, r2, #4, r0
    swpmv_bis   r4, r6, r2, #8, r0
    swpmv_bis   r4, r7, r2, #12, r0
    // r2 <- 0x00f000f0
    lsls        r2, #4
    swpmv_bis   r5, r6, r2, #4, r0
    swpmv_bis   r5, r7, r2, #8, r0
    // r2 <- 0x0f000f00
    lsls        r2, #4
    swpmv_bis   r6, r7, r2, #4, r0
    // ------------------ GIFTb-CORE ROUTINE ------------------
    movs    r2, #0xf0
    lsls    r0, r2, #16
    orrs    r2, r2, r0
    lsrs    r0, r2, #8
    mov     r8,  r0
    movs    r2, #0x11
    lsls    r0, r2, #8
    eors    r2, r0
    lsls    r0, r2, #16
    eors    r2, r0
    movs    r3, #0x77
    lsls    r0, r3, #8
    eors    r3, r0
    lsls    r0, r3, #16
    eors    r3, r0
    mov     r9,  r2
    mov     r10, r3
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    // r2 <- 0x00f00f00
    movs        r2, #0xf0
    lsls        r2, r2, #4
    lsls        r0, r2, #16
    eors        r2, r0, r2
    swpmv_bis   r6, r7, r2, #4, r0
    // r2 <- 0x00f000f0
    lsrs        r2, #4
    swpmv_bis   r5, r7, r2, #8, r0
    swpmv_bis   r5, r6, r2, #4, r0
    // r2 <- 0x000f000f
    lsrs        r2, #4
    swpmv_bis   r4, r7, r2, #12, r0
    swpmv_bis   r4, r6, r2, #8, r0
    swpmv_bis   r4, r5, r2, #4, r0
    // r2 <- 0x00cc00cc
    movs    r2, #0xcc
    lsls    r0, r2, #16
    orrs    r2, r2, r0
    swpmv   r7, r2, #6, r0
    swpmv   r6, r2, #6, r0
    swpmv   r5, r2, #6, r0
    swpmv   r4, r2, #6, r0
    // r2 <- 0x0a0a0a0a
    movs    r2, #0x0a
    lsls    r0, r2, #8
    orrs    r2, r2, r0
    lsls    r0, r2, #16
    orrs    r2, r2, r0
    swpmv   r7, r2, #3, r0
    swpmv   r6, r2, #3, r0
    swpmv   r5, r2, #3, r0
    swpmv   r4, r2, #3, r0
    rev     r4, r4
    rev     r5, r5
    rev     r6, r6
    rev     r7, r7
    ldr     r0, [sp, #20]
    str     r4, [r0]
    str     r5, [r0, #4]
    str     r6, [r0, #8]
    str     r7, [r0, #12]
    ldr     r7, [sp]
    ldr     r6, [sp, #4]
    ldr     r5, [sp, #8]
    ldr     r4, [sp, #12]
    ldr     r0, [sp, #16]
    mov     r11, r7
    mov     r10, r6
    mov     r9, r5
    mov     r8, r4
    mov     r14, r0
    add     sp, #20
    pop     {r0-r7}
    bx      lr


/*****************************************************************************
* ARMv6-M assembly implementation of the GIFTb-128 block cipher.
* This function simply encrypts a 128-bit block, without any operation mode.
*****************************************************************************/
@ void giftb128_encrypt_block(u8 *out, const u32* rkey,
@       const u8 *block) {
.global giftb128_encrypt_block
.type   giftb128_encrypt_block,%function
giftb128_encrypt_block:
    push    {r0-r7}
    sub     sp, #20
    mov     r4, r8
    mov     r5, r9
    mov     r6, r10
    mov     r7, r11
    mov     r0, r14
    str     r7, [sp]
    str     r6, [sp, #4]
    str     r5, [sp, #8]
    str     r4, [sp, #12]
    str     r0, [sp, #16]
    ldr     r4, [r1]
    ldr     r5, [r1, #4]
    ldr     r6, [r1, #8]
    ldr     r7, [r1, #12]
    adr     r3, rconst
    mov     r11, r3         // save rconst pointer to r11
    mov     r1, r2  // mov rkey pointer to r1
    // ------------------ GIFTb-CORE ROUTINE ------------------
    movs    r2, #0xf0
    lsls    r0, r2, #16
    orrs    r2, r2, r0
    lsrs    r0, r2, #8
    mov     r8,  r0
    movs    r2, #0x11
    lsls    r0, r2, #8
    eors    r2, r0
    lsls    r0, r2, #16
    eors    r2, r0
    movs    r3, #0x77
    lsls    r0, r3, #8
    eors    r3, r0
    lsls    r0, r3, #16
    eors    r3, r0
    mov		r9,  r2
    mov		r10, r3
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    bl quintuple_round
    ldr     r0, [sp, #20]
    str     r4, [r0]
    str     r5, [r0, #4]
    str     r6, [r0, #8]
    str     r7, [r0, #12]
    ldr      r7, [sp]
    ldr      r6, [sp, #4]
    ldr      r5, [sp, #8]
    ldr      r4, [sp, #12]
    ldr      r0, [sp, #16]
    mov      r11, r7
    mov      r10, r6
    mov      r9, r5
    mov      r8, r4
    mov      r14, r0
    add      sp, #20
    pop      {r0-r7}
    bx       lr

/*****************************************************************************
* Round constants look-up table according to the fixsliced representation.
*****************************************************************************/
.align 2
.type rconst,%object
rconst:
.word 0x10000008, 0x80018000, 0x54000002, 0x01010181
.word 0x8000001f, 0x10888880, 0x6001e000, 0x51500002
.word 0x03030180, 0x8000002f, 0x10088880, 0x60016000
.word 0x41500002, 0x03030080, 0x80000027, 0x10008880
.word 0x4001e000, 0x11500002, 0x03020180, 0x8000002b
.word 0x10080880, 0x60014000, 0x01400002, 0x02020080
.word 0x80000021, 0x10000080, 0x0001c000, 0x51000002
.word 0x03010180, 0x8000002e, 0x10088800, 0x60012000
.word 0x40500002, 0x01030080, 0x80000006, 0x10008808
.word 0xc001a000, 0x14500002, 0x01020181, 0x8000001a
