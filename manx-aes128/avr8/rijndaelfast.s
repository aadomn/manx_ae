; Copyright (C) 2003,2006 B. Poettering
; 
; This program is free software; you can redistribute and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation; either version 2 of the License, or
; (at your option) any later version. Whenever you redistribute a copy
; of this document, make sure to include the copyright and license
; agreement without modification.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program; if not, write to the Free Software
; Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
; The license text can be found here: http://www.gnu.org/licenses/gpl.txt

;                http://point-at-infinity.org/avraes/
;
; This AES implementation was written in May 2003 by B. Poettering. It is 
; published under the terms of the GNU General Public License. If you need 
; AES code, but this license is unsuitable for your project, feel free to 
; contact me: avraes AT point-at-infinity.org


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;                                 RijndaelFast
;
; This is a microcontroller implementation of the Rijndael block cipher, better
; known as AES. The target device class is Atmel's AVR, a family of very fast 
; and very powerful flash MCUs, operating at clock rates up to 16 MHz,  
; executing one instruction per clock cycle (16 MIPS). The implementation 
; given here is optimized for speed (versus codesize), and achieves an 
; encryption rate of more than 100 kByte per second (on a 16MHz MCU). 
; The decryption performs about 40% slower than encryption (typical for 
; Rijndael).
; 
; The implemented algorithm is restricted to block and key sizes of 128 bit. 
; Larger key sizes can be obtained by altering the key scheduling code, which
; should be easy. As the cipher's state is completely kept in registers
; (which are limited in number), the block size is not that easy to enlarge.
; 
; This implementation makes extensive use of the AVR's "lpm" instruction,
; which loads data bytes from program memory at given addresses (the s-boxes 
; are realized that way). Some members of the AVR family don't offer that 
; instruction at all (e.g. AT90S1200), others only in a restricted way 
; (forcing the target register to be r0). The code below requires the least 
; restricted lpm instruction (with free choice of the target register).
; The ATmega161 devices meet the above mentioned requirements.
; 
; Statistics:
; 
; 16 MHz MCU | clock cycles | blocks per second | bytes per second
; -----------+--------------+-------------------+------------------
; encryption |    2474      |       6467        |      103476
; decryption |    3411      |       4691        |       75051
; 
; KEY SETUP TIME
; encryption: 756 clock cycles
; decryption: 756 + 4221 = 4977 clock cycles
; 
; CODE SIZE
; instructions: 1306 byte ( 653 words)
; sboxes:       1792 byte ( 896 words) = 7 * 256 byte
; total:        3098 byte (1549 words)
;
; RAM REQUIREMENTS
; 16 * 11 = 176 byte for each expanded key
;
;
; This source code consists of four routines and an example application, 
; which encrypts a certain plaintext and decrypts it afterwards with the
; same key. Comments in the code clarify the interaction between the key 
; expansion and the encryption/decryption routines.
;
; I encourage to read the following Rijndael-related papers/books/sites:
; [1] "The Design of Rijndael", Daemen & Rijmen, Springer, ISBN 3-540-42580-2
; [2] http://www.esat.kuleuven.ac.be/~rijmen/rijndael/
; [3] http://www.esat.kuleuven.ac.be/~rijmen/rijndael/rijndaeldocV2.zip
; [4] http://www.esat.kuleuven.ac.be/~rijmen/rijndael/atmal.zip
; [5] http://csrc.nist.gov/CryptoToolkit/aes/rijndael/
;
; [1] is *the* book about Rijndael, [2] is the official Rijndael homepage,
; [3] contains the complete Rijndael AES specification, [4] is another
; Rijndael-implementation for AVR MCUs (but much slower than this one, 
; taking 3815 clock cycles per encryption), [5] is the official NIST AES 
; site with further links.
;
; AVR and ATmega are registered trademarks by the ATMEL corporation.
; See http://www.atmel.com and http://www.atmel.com/products/avr/ for
; further details.

	
	
;;; ***************************************************************************
;;; The Rijndael cipher acts on a so-called (128 bit) "state matrix", 
;;; represented here by the 4x4 state bytes ST11-ST44. To guarantee maximum
;;; performance on AVR MCUs, these bytes are kept in registers (defaulted to
;;; the 16 low order registers r0-r15, but this may be changed if required).
;;; 
;;; The implementation makes use of six auxiliary registers (H1-H5 and I),
;;; some of which must reside in the upper registers (r16-r31). In addition
;;; ramp-registers YH:YL and ZH:ZL are used.
;;;
;;; If the context *really* requires more registers than the remaining ones, 
;;; it seems promising to move the I-register to a (fixed) ram location. 
;;; In the time crititcal routines the I-value is rarely used, thus the 
;;; speed loss obtained by dropping it from the register file is acceptible. 

#include <avr/io.h>

#define ST11 r0
#define ST21 r1
#define ST31 r2
#define ST41 r3
#define ST12 r4
#define ST22 r5
#define ST32 r6
#define ST42 r7
#define ST13 r8
#define ST23 r9
#define ST33 r10
#define ST43 r11
#define ST14 r12
#define ST24 r13
#define ST34 r14
#define ST44 r15
#define H1 r16
#define H2 r17
#define H3 r18
#define H4 r19
#define H5 r20
#define I r21


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

; saves registers, ensures calling convention is followed
.global aes128_kexp
aes128_kexp:
	; Save r2-r17,r28-r29
	push_registers 2,17
	push_registers 28,29
	; Save the argument pointers to Z (key) and X (plaintext)
	movw XL, ARG2
	movw YL, ARG1
	; Load the plaintext given by argument to register 0-15
	.irp param,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15
	ld \param, X+
	.endr
	; Core function
	ldi H1, 1
	ldi H2, 0x1b
	ldi ZH, hi8(sbox)
	rjmp keyexp1
	keyexp0:
		mov ZL, ST24
		ld H3, Z
		eor ST11, H3
		eor ST11, H1
		mov ZL, ST34
		ld H3, Z
		eor ST21, H3
		mov ZL, ST44
		ld H3, Z
		eor ST31, H3
		mov ZL, ST14
		ld H3, Z
		eor ST41, H3
		eor ST12, ST11
		eor ST22, ST21
		eor ST32, ST31
		eor ST42, ST41
		eor ST13, ST12
		eor ST23, ST22
		eor ST33, ST32
		eor ST43, ST42
		eor ST14, ST13
		eor ST24, ST23
		eor ST34, ST33
		eor ST44, ST43
		lsl H1
		brcc keyexp1
		eor H1, H2
	keyexp1:
		st Y+, ST11
		st Y+, ST21
		st Y+, ST31
		st Y+, ST41
		st Y+, ST12
		st Y+, ST22
		st Y+, ST32
		st Y+, ST42
		st Y+, ST13
		st Y+, ST23
		st Y+, ST33
		st Y+, ST43
		st Y+, ST14
		st Y+, ST24
		st Y+, ST34
		st Y+, ST44
		cpi H1, 0x6c
		brne keyexp0
	; Restore r2-r17,r28-r29
	pop_registers 28,29
	pop_registers 2,17
	clr r1
	ret

.global aes128_enc
aes128_enc:
	;mov SP to X
	in r26, 0x3d
	in r27, 0x3e
	; Save registers r2-17,r28-29
	push_registers 2,17
	push_registers 28,29
	
	; Save the argument pointers to Z (key) and X (plaintext)
	movw XL, ARG2
	movw YL, ARG3
	; Load the plaintext given by argument to register 0-15
	.irp param,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15
	ld \param, X+
	.endr

	rcall encrypt

	; Save the final state from the registers to Y (ARG1)
	movw YL, ARG1
	.irp param,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15
		st Y+, \param
	.endr
	; Restore registers r2-17,r28-29
	pop_registers 28,29
	pop_registers 2,17
	clr r1
	ret

;;; ***************************************************************************
;;; 
;;; ENCRYPT 
;;; This routine encrypts a 128 bit plaintext block (supplied in ST11-ST44), 
;;; using an expanded key given in YH:YL. The resulting 128 bit ciphertext
;;; block is stored in ST11-ST44.
;;;
;;; Parameters:
;;;         YH:YL:	pointer to expanded key
;;;         ST11-ST44:  128 bit plaintext block
;;; Touched registers:
;;;     ST11-ST41,H1-H5,I,ZH,ZL,YH,YL
;;; Clock cycles:	2474
		
encrypt:
	rcall encryp1
	ldi ZH, hi8(sbox)
	ldi I, 8
encryp0:mov ZL, ST11		; 1
	ld H2, Z
	mov H3, H2
	mov H4, H2
	ldi ZH, hi8(sbox02)
	ld H1, Z
	eor H4, H1
	mov ZL, ST22
	ld H5, Z
	eor H1, H5
	eor H2, H5
	ldi ZH, hi8(sbox)
	ld H5, Z
	eor H1, H5
	eor H3, H5
	eor H4, H5
	mov ZL, ST33
	ld H5, Z
	eor H1, H5
	eor H2, H5
	eor H4, H5
	ldi ZH, hi8(sbox02)
	ld H5, Z
	eor H2, H5
	eor H3, H5
	mov ZL, ST44
	ld H5, Z
	eor H3, H5
	eor H4, H5
	ldi ZH, hi8(sbox)
	ld H5, Z
	eor H1, H5
	eor H2, H5
	eor H3, H5
	ldd ST11, Y+0
	eor ST11, H1
	mov ZL, ST41		; 2
	ldd ST41, Y+3
	eor ST41, H4
	ld H1, Z
	mov H4, H1
	mov ST33, H1
	ldi ZH, hi8(sbox02)
	ld ST44, Z
	eor ST33, ST44
	mov ZL, ST12
	ld H5, Z
	eor H1, H5
	eor ST44, H5
	ldi ZH, hi8(sbox)
	ld H5, Z
	eor H4, H5
	eor ST33, H5
	eor ST44, H5
	mov ZL, ST23
	ld H5, Z
	eor H1, H5
	eor ST33, H5
	eor ST44, H5
	ldi ZH, hi8(sbox02)
	ld H5, Z
	eor H1, H5
	eor H4, H5
	mov ZL, ST34
	ld H5, Z
	eor H4, H5
	eor ST33, H5
	ldi ZH, hi8(sbox)
	ld H5, Z
	eor H1, H5
	eor H4, H5
	eor ST44, H5
	ldd ST12, Y+4
	eor ST12, H1
	ldd ST22, Y+5
	eor ST22, H4
	mov ZL, ST31		; 3
	ldd ST31, Y+2
	eor ST31, H3
	ld ST34, Z
	mov H3, ST34
	mov H1, ST34
	ldi ZH, hi8(sbox02)
	ld H4, Z
	eor H3, H4
	mov ZL, ST42
	ldd ST42, Y+7
	eor ST42, ST44
	ld H5, Z
	eor H4, H5
	eor H1, H5
	ldi ZH, hi8(sbox)
	ld H5, Z
	eor ST34, H5
	eor H3, H5
	eor H4, H5
	mov ZL, ST13
	ld H5, Z
	eor H3, H5
	eor H4, H5
	eor H1, H5
	ldi ZH, hi8(sbox02)
	ld H5, Z
	eor ST34, H5
	eor H1, H5
	mov ZL, ST24
	ld H5, Z
	eor ST34, H5
	eor H3, H5
	ldi ZH, hi8(sbox)
	ld H5, Z
	eor ST34, H5
	eor H4, H5
	eor H1, H5
	
	ldd ST13, Y+8
	eor ST13, ST34
	ldd ST23, Y+9
	eor ST23, H3

	mov ZL, ST32		; 4
	
	ldd ST32, Y+6
	eor ST32, ST33
	ldd ST33, Y+10
	eor ST33, H4

	ld ST24, Z
	mov ST34, ST24
	mov H4, ST24
	ldi ZH, hi8(sbox02)
	ld H3, Z
	eor ST34, H3
	mov ZL, ST43
	ldd ST43, Y+11
	eor ST43, H1

	ld H5, Z
	eor H3, H5
	eor H4, H5
	ldi ZH, hi8(sbox)
	ld H5, Z
	eor ST24, H5
	eor ST34, H5
	eor H3, H5
	mov ZL, ST14
	ld H5, Z
	eor ST34, H5
	eor H3, H5
	eor H4, H5
	ldi ZH, hi8(sbox02)
	ld H5, Z
	eor ST24, H5
	eor H4, H5
	mov ZL, ST21
	ld H5, Z
	eor ST24, H5
	eor ST34, H5
	ldi ZH, hi8(sbox)
	ld H5, Z
	eor ST24, H5
	eor H3, H5
	eor H4, H5
	ldd ST21, Y+1
	eor ST21, H2
	ldd ST14, Y+12
	eor ST14, ST24
	ldd ST24, Y+13
	eor ST24, ST34
	ldd ST34, Y+14
	eor ST34, H3
	ldd ST44, Y+15
	eor ST44, H4
	adiw Y, 16
	dec I
	sbrs I,7
	jmp encryp0
	; Omit MixColumns for the last round
	mov ZL, ST11
	ld ST11, Z
	mov ZL, ST12
	ld ST12, Z
	mov ZL, ST13
	ld ST13, Z
	mov ZL, ST14
	ld ST14, Z
	mov H1, ST21
	mov ZL, ST22
	ld ST21, Z
	mov ZL, ST23
	ld ST22, Z
	mov ZL, ST24
	ld ST23, Z
	mov ZL, H1
	ld ST24, Z
	mov H1, ST31
	mov ZL, ST33
	ld ST31, Z
	mov ZL, H1
	ld ST33, Z
	mov H1, ST32
	mov ZL, ST34
	ld ST32, Z
	mov ZL, H1
	ld ST34, Z
	mov H1, ST41
	mov ZL, ST44
	ld ST41, Z
	mov ZL, ST43
	ld ST44, Z
	mov ZL, ST42
	ld ST43, Z
	mov ZL, H1
	ld ST42, Z
	encryp1:
		; AddRoundKey
		ld H1, Y+
		eor ST11, H1
		ld H1, Y+
		eor ST21, H1
		ld H1, Y+
		eor ST31, H1
		ld H1, Y+
		eor ST41, H1
		ld H1, Y+
		eor ST12, H1
		ld H1, Y+
		eor ST22, H1
		ld H1, Y+
		eor ST32, H1
		ld H1, Y+
		eor ST42, H1
		ld H1, Y+
		eor ST13, H1
		ld H1, Y+
		eor ST23, H1
		ld H1, Y+
		eor ST33, H1
		ld H1, Y+
		eor ST43, H1
		ld H1, Y+
		eor ST14, H1
		ld H1, Y+
		eor ST24, H1
		ld H1, Y+
		eor ST34, H1
		ld H1, Y+
		eor ST44, H1
		ret



;;; ***************************************************************************
;;; 
;;; S-BOX
;;; Rijndael consists of a non-linear step in its rounds (called "sbox step"), 
;;; generally implemented with hard-coded lookup tables. The implementation 
;;; given above makes use of seven lookup tables in total: the sbox itself, 
;;; its inverse, and scaled versions of both (e.g. sbox02[] = 2*sbox[]).
;;;
;;; This generous employment of expensive space of flash memory has two
;;; important advantages: excellent performance and protection against 
;;; timing and power measurement attacks.
;;;
;;; The seven tables have to be aligned to a flash position with its lower 
;;; address byte equal to 0x00. In assembler syntax: lo8(sbox<<1) == 0.
;;; To ensure the proper alignment of the sboxes, the assembler directive
;;; .ORG is used (below the sboxes are defined to begin at 0x800). Note, that 
;;; any other address can be used as well, as long as the lower byte is equal 
;;; to 0x00.
;;;
;;; The order of the sboxes is totally arbitrary. They even do not have to be
;;; allocated in adjacent memory areas.

.data
.balign 256

sbox:
.byte 0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76 
.byte 0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0 
.byte 0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15 
.byte 0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75 
.byte 0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84 
.byte 0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf 
.byte 0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8 
.byte 0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2 
.byte 0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73 
.byte 0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb 
.byte 0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79 
.byte 0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08 
.byte 0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a 
.byte 0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e 
.byte 0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf 
.byte 0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16 

sbox02:
.byte 0xc6,0xf8,0xee,0xf6,0xff,0xd6,0xde,0x91,0x60,0x02,0xce,0x56,0xe7,0xb5,0x4d,0xec 
.byte 0x8f,0x1f,0x89,0xfa,0xef,0xb2,0x8e,0xfb,0x41,0xb3,0x5f,0x45,0x23,0x53,0xe4,0x9b 
.byte 0x75,0xe1,0x3d,0x4c,0x6c,0x7e,0xf5,0x83,0x68,0x51,0xd1,0xf9,0xe2,0xab,0x62,0x2a 
.byte 0x08,0x95,0x46,0x9d,0x30,0x37,0x0a,0x2f,0x0e,0x24,0x1b,0xdf,0xcd,0x4e,0x7f,0xea 
.byte 0x12,0x1d,0x58,0x34,0x36,0xdc,0xb4,0x5b,0xa4,0x76,0xb7,0x7d,0x52,0xdd,0x5e,0x13 
.byte 0xa6,0xb9,0x00,0xc1,0x40,0xe3,0x79,0xb6,0xd4,0x8d,0x67,0x72,0x94,0x98,0xb0,0x85 
.byte 0xbb,0xc5,0x4f,0xed,0x86,0x9a,0x66,0x11,0x8a,0xe9,0x04,0xfe,0xa0,0x78,0x25,0x4b 
.byte 0xa2,0x5d,0x80,0x05,0x3f,0x21,0x70,0xf1,0x63,0x77,0xaf,0x42,0x20,0xe5,0xfd,0xbf 
.byte 0x81,0x18,0x26,0xc3,0xbe,0x35,0x88,0x2e,0x93,0x55,0xfc,0x7a,0xc8,0xba,0x32,0xe6 
.byte 0xc0,0x19,0x9e,0xa3,0x44,0x54,0x3b,0x0b,0x8c,0xc7,0x6b,0x28,0xa7,0xbc,0x16,0xad 
.byte 0xdb,0x64,0x74,0x14,0x92,0x0c,0x48,0xb8,0x9f,0xbd,0x43,0xc4,0x39,0x31,0xd3,0xf2 
.byte 0xd5,0x8b,0x6e,0xda,0x01,0xb1,0x9c,0x49,0xd8,0xac,0xf3,0xcf,0xca,0xf4,0x47,0x10 
.byte 0x6f,0xf0,0x4a,0x5c,0x38,0x57,0x73,0x97,0xcb,0xa1,0xe8,0x3e,0x96,0x61,0x0d,0x0f 
.byte 0xe0,0x7c,0x71,0xcc,0x90,0x06,0xf7,0x1c,0xc2,0x6a,0xae,0x69,0x17,0x99,0x3a,0x27 
.byte 0xd9,0xeb,0x2b,0x22,0xd2,0xa9,0x07,0x33,0x2d,0x3c,0x15,0xc9,0x87,0xaa,0x50,0xa5 
.byte 0x03,0x59,0x09,0x1a,0x65,0xd7,0x84,0xd0,0x82,0x29,0x5a,0x1e,0x7b,0xa8,0x6d,0x2c 
