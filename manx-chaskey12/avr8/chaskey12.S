
; Argument registers for function calls
#define ARG1 r24
#define ARG2 r22
#define ARG3 r20

/**
 * push_registers macro:
 *
 * Pushes a given range of registers in ascending order
 * To be called like: push_registers 0,15
 */
.macro push_registers from:req, to:req
  push \from
  .if \to-\from
    push_registers "(\from+1)",\to
  .endif
.endm

/**
 * pop_registers macro:
 *
 * Pops a given range of registers in descending order
 * To be called like: pop_registers 0,15
 */
.macro pop_registers from:req, to:req
  pop \to
  .if \to-\from
    pop_registers \from,"(\to-1)"
  .endif
.endm

.global chaskey12_enc
chaskey12_enc:
	; Save r2-r17,r28-r29
	push_registers 2,17
	push_registers 28,29
	; Save the argument pointers to Z (key) and X (plaintext)
	movw XL, ARG2
	; Load the plaintext given by argument to register 2-17 instead of 0-15 because
	; the mul instruction inconditionally overwrites registers r1:r0.
	.irp param,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15,r16,r17
	ld \param, X+
	.endr
	; Key whitening
	movw YL, ARG3
	ld   r18, Y+
	eor  r2, r18
	ld   r18, Y+
	eor  r3, r18
	ld   r18, Y+
	eor  r4, r18
	ld   r18, Y+
	eor  r5, r18
	ld   r18, Y+
	eor  r6, r18
	ld   r18, Y+
	eor  r7, r18
	ld   r18, Y+
	eor  r8, r18
	ld   r18, Y+
	eor  r9, r18
	ld   r18, Y+
	eor  r10, r18
	ld   r18, Y+
	eor  r11, r18
	ld   r18, Y+
	eor  r12, r18
	ld   r18, Y+
	eor  r13, r18
	ld   r18, Y+
	eor  r14, r18
	ld   r18, Y+
	eor  r15, r18
	ld   r18, Y+
	eor  r16, r18
	ld   r18, Y+
	eor  r17, r18
	; Core function
	ldi r18, 12
	ldi r19, 32
	loop:
		/*
		// v[0] += v[1]
		add  r2, r6
		adc  r3, r7
		adc  r4, r8
		adc  r5, r9
		// v[1] <<<= 5
		mov  r28, r7
		mov  r29, r9
		mul  r6, r19
		movw r6, r0
		mul  r8, r19
		movw r8, r0
		mul  r28, r19
		eor  r7, r0
		eor  r8, r1
		mul  r29, r19
		eor  r9, r0
		eor  r6, r1
		// v[1] ^= v[0]
		eor  r6, r2
		eor  r7, r3
		eor  r8, r4
		eor  r9, r5
		// v[0] <<<= 16
		movw r28, r4
		movw r4, r2
		movw r2, r28
		// v[2] += v[3]
		add  r10,  r14
		adc  r11,  r15
		adc  r12, r16
		adc  r13, r17
		// v[3] ^= v[2] <<< 8
		eor  r17, r10
		eor  r14, r11
		eor  r15, r12
		eor  r16, r13
		// v[1] += v[3] <<< 8
		add  r2, r17
		adc  r3, r14
		adc  r4, r15
		adc  r5, r16
		// v[3] <<<= 16
		movw r28, r14
		movw r14, r16
		movw r16, r28
		// v[3] <<<= 5
		mov  r28, r15
		mov  r29, r17
		mul  r14, r19
		movw r14, r0
		mul  r16, r19
		movw r16, r0
		mul  r28, r19
		eor  r15, r0
		eor  r16, r1
		mul  r29, r19
		eor  r17, r0
		eor  r14, r1
		// v[3] ^= v[0]
		eor r14, r2
		eor r15, r3
		eor r16, r4
		eor r17, r5
		// v[2] += v[1]
		add  r10, r6
		adc  r11, r7
		adc  r12, r8
		adc  r13, r9
		// v[1] <<<= 7
		mov  r28, r9
		mov  r9, r8
		mov  r8, r7
		mov  r7, r6
		mov  r6, r28
		bst  r6, 0
		ror  r9
		ror  r8
		ror  r7
		ror  r6
		bld  r9, 7
		// v[1] ^= v[2]
		eor  r6, r10
		eor  r7, r11
		eor  r8, r12
		eor  r9, r13
		; v[2] <<<= 16
		movw r28, r12
		movw r12, r10
		movw r10, r28
		*/
	
		
		// v[0] += v[1]
		add  r2, r6
		adc  r3, r7
		adc  r4, r8
		adc  r5, r9
		// v[1] <<<= 5
		mov  r28, r7
		mov  r29, r9
		mul  r6, r19
		movw r6, r0
		mul  r8, r19
		movw r8, r0
		mul  r28, r19
		eor  r7, r0
		eor  r8, r1
		mul  r29, r19
		eor  r9, r0
		eor  r6, r1
		// v[1] ^= v[0]
		eor  r6, r2
		eor  r7, r3
		eor  r8, r4
		eor  r9, r5
		// v[2] += v[3]
		add  r10,  r14
		adc  r11,  r15
		adc  r12, r16
		adc  r13, r17
		// v[3] ^= v[2] <<< 8
		eor  r17, r10
		eor  r14, r11
		eor  r15, r12
		eor  r16, r13
		// v[0] += v[3] <<< 8
		add  r4, r17
		adc  r5, r14
		adc  r2, r15
		adc  r3, r16
		/*
		// v[3] <<<= 16
		movw r28, r14
		movw r14, r16
		movw r16, r28
		*/
		// v[3] <<<= 5
		mov  r28, r15
		mov  r29, r17
		mul  r14, r19
		movw r14, r0
		mul  r16, r19
		movw r16, r0
		mul  r28, r19
		eor  r15, r0
		eor  r16, r1
		mul  r29, r19
		eor  r17, r0
		eor  r14, r1
		// v[3] ^= v[0]
		eor r14, r2
		eor r15, r3
		eor r16, r4
		eor r17, r5
		// v[2] += v[1]
		add  r10, r6
		adc  r11, r7
		adc  r12, r8
		adc  r13, r9
		// v[1] <<<= 7
		mov  r28, r9
		mov  r9, r8
		mov  r8, r7
		mov  r7, r6
		mov  r6, r28
		bst  r6, 0
		ror  r9
		ror  r8
		ror  r7
		ror  r6
		bld  r9, 7
		// v[1] ^= v[2]
		eor  r6, r10
		eor  r7, r11
		eor  r8, r12
		eor  r9, r13
		
	
		// v[0] += v[1]
		add  r4, r6
		adc  r5, r7
		adc  r2, r8
		adc  r3, r9
		// v[1] <<<= 5
		mov  r28, r7
		mov  r29, r9
		mul  r6, r19
		movw r6, r0
		mul  r8, r19
		movw r8, r0
		mul  r28, r19
		eor  r7, r0
		eor  r8, r1
		mul  r29, r19
		eor  r9, r0
		eor  r6, r1
		// v[1] ^= v[0]
		eor  r6, r4
		eor  r7, r5
		eor  r8, r2
		eor  r9, r3
		// v[2] += (v[3] <<< 16)
		add  r12, r16
		adc  r13, r17
		adc  r10, r14
		adc  r11, r15
		// v[3] ^= v[2] <<< 8
		eor  r16, r13
		eor  r17, r10
		eor  r14, r11
		eor  r15, r12
		// v[0] += v[3] <<< 8
		add  r2, r15
		adc  r3, r16
		adc  r4, r17
		adc  r5, r14
		// v[3] <<<= 5
		mov  r28, r15
		mov  r29, r17
		mul  r14, r19
		movw r14, r0
		mul  r16, r19
		movw r16, r0
		mul  r28, r19
		eor  r15, r0
		eor  r16, r1
		mul  r29, r19
		eor  r17, r0
		eor  r14, r1
		// v[3] ^= v[0]
		eor r14, r2
		eor r15, r3
		eor r16, r4
		eor r17, r5
		// v[2] += v[1]
		add  r12, r6
		adc  r13, r7
		adc  r10, r8
		adc  r11, r9
		// v[1] <<<= 7
		mov  r28, r9
		mov  r9, r8
		mov  r8, r7
		mov  r7, r6
		mov  r6, r28
		bst  r6, 0
		ror  r9
		ror  r8
		ror  r7
		ror  r6
		bld  r9, 7
		// v[1] ^= v[2]
		eor  r6, r12
		eor  r7, r13
		eor  r8, r10
		eor  r9, r11

		; Decrement loop counter
		subi r18, 2
		cpi  r18, 0
		breq exit
		rjmp loop
	exit:
	; Key whitening
	movw YL, ARG3
	ld   r18, Y+
	eor  r2, r18
	ld   r18, Y+
	eor  r3, r18
	ld   r18, Y+
	eor  r4, r18
	ld   r18, Y+
	eor  r5, r18
	ld   r18, Y+
	eor  r6, r18
	ld   r18, Y+
	eor  r7, r18
	ld   r18, Y+

	eor  r8, r18
	ld   r18, Y+
	eor  r9, r18
	ld   r18, Y+
	eor  r10, r18
	ld   r18, Y+
	eor  r11, r18
	ld   r18, Y+
	eor  r12, r18
	ld   r18, Y+
	eor  r13, r18
	ld   r18, Y+
	eor  r14, r18
	ld   r18, Y+
	eor  r15, r18
	ld   r18, Y+
	eor  r16, r18
	ld   r18, Y+
	eor  r17, r18
	; Store output
	movw YL, ARG1
	st Y+, r2
	st Y+, r3
	st Y+, r4
	st Y+, r5
	st Y+, r6
	st Y+, r7
	st Y+, r8
	st Y+, r9
	st Y+, r10
	st Y+, r11
	st Y+, r12
	st Y+, r13
	st Y+, r14
	st Y+, r15
	st Y+, r16
	st Y+, r17
	; Restore r2-r19,r28-r29
	pop_registers 28,29
	pop_registers 2,17
	ret
