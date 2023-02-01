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
;                            RijndaelFurious
;
; This is a microcontroller implementation of the Rijndael block cipher, better
; known as AES. The target device class is Atmel's AVR, a family of very fast 
; and very powerful flash MCUs, operating at clock rates up to 16 MHz,  
; executing one instruction per clock cycle (16 MIPS). The implementation 
; given here achieves an encryption rate of about 93 kByte per second (on a 
; 16MHz MCU). The decryption performs about 30% slower than encryption (typical 
; for Rijndael).
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
; encryption |    2739      |       5842        |       93465
; decryption |    3579      |       4471        |       71528
; 
; KEY SETUP TIME: 756 clock cycles
; 
; CODE SIZE
; instructions:  802 byte ( 401 words)
; sboxes:        768 byte ( 384 words) = 3 * 256 byte
; total:        1570 byte ( 785 words)
;
; RAM REQUIREMENTS
; 16 * 11 = 176 byte for each expanded key
;
;
; This source code consists of some routines and an example application, 
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
;;; The implementation makes use of four auxiliary registers (H1-H3 and I),
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

;;; ***************************************************************************
;;; 
;;; KEY_EXPAND
;;; The following routine implements the Rijndael key expansion algorithm. The 
;;; caller supplies the 128 bit key in the registers ST11-ST44 and a pointer 
;;; in the YH:YL register pair. The key is expanded to the memory 
;;; positions [Y : Y+16*11-1]. Note: the key expansion is necessary for both
;;; encryption and decryption.
;;; 
;;; Parameters:
;;;     ST11-ST44:	the 128 bit key
;;;         YH:YL:	pointer to ram location
;;; Touched registers:
;;;     ST11-ST44,H1-H3,ZH,ZL,YH,YL
;;; Clock cycles:	756



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
keyexp0:mov ZL, ST24
	lpm H3, Z
	eor ST11, H3
	eor ST11, H1
	mov ZL, ST34
	lpm H3, Z
	eor ST21, H3
	mov ZL, ST44
	lpm H3, Z
	eor ST31, H3
	mov ZL, ST14
	lpm H3, Z
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
keyexp1:st Y+, ST11
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
;;;     ST11-ST44,H1,H2,H3,I,ZH,ZL,YH,YL
;;; Clock cycles:	2739
		
encrypt:
	ldi I, 10
encryp1:
	rcall addroundkey	; AddRoundKey
	ldi ZH, hi8(sbox)	; SubBytes + ShiftRows
	mov ZL, ST11
	lpm ST11, Z
	mov ZL, ST12
	lpm ST12, Z
	mov ZL, ST13
	lpm ST13, Z
	mov ZL, ST14
	lpm ST14, Z
	mov H1, ST21
	mov ZL, ST22
	lpm ST21, Z
	mov ZL, ST23
	lpm ST22, Z
	mov ZL, ST24
	lpm ST23, Z
	mov ZL, H1
	lpm ST24, Z
	mov H1, ST31
	mov ZL, ST33
	lpm ST31, Z
	mov ZL, H1
	lpm ST33, Z
	mov H1, ST32
	mov ZL, ST34
	lpm ST32, Z
	mov ZL, H1
	lpm ST34, Z
	mov H1, ST44
	mov ZL, ST43
	lpm ST44, Z
	mov ZL, ST42
	lpm ST43, Z
	mov ZL, ST41
	lpm ST42, Z
	mov ZL, H1
	lpm ST41, Z
	dec I
	breq last_addroundkey	; AddRoundKey
	rcall mixcolumns	; MixColumns
	rjmp encryp1
last_addroundkey:
	rcall addroundkey
	ret
	


;;; ***************************************************************************
;;; 
;;; ADDROUNDKEY
;;; This routine adds a round key to the state matrix (AddRoundKey). 
;;;
;;; Note: This routine is part of the encryption and decryption routines. You
;;; normally won't be interested in calling this routine directly.
;;;
;;; Parameters:
;;;         ST11-ST44:  128 bit state matrix
;;;         YH:YL:      pointer to ram location
;;; Touched registers:
;;;     ST11-ST41,H1,YH,YL

addroundkey:
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
;;; MIXCOLUMNS
;;; This routine applies the MixColumns diffusion operator to the whole 
;;; state matrix. The code is used for both encryption and decryption.
;;;
;;; Note: This routine is part of the encryption and decryption routines. You
;;; normally wont be interested in calling this routine directly.
;;;
;;; Parameters:
;;;         ST11-ST44:  128 bit state matrix
;;; Touched registers:
;;;     ST11-ST41,H1,H2,H3,ZH,ZL

mixcolumns:
	ldi ZH, hi8(xtime)
	mov H1, ST11
	eor H1, ST21
	eor H1, ST31
	eor H1, ST41
	mov H2, ST11
	mov H3, ST11
	eor H3, ST21
	mov ZL, H3
	lpm H3, Z
	eor ST11, H3
	eor ST11, H1
	mov H3, ST21
	eor H3, ST31
	mov ZL, H3
	lpm H3, Z
	eor ST21, H3
	eor ST21, H1
	mov H3, ST31
	eor H3, ST41
	mov ZL, H3
	lpm H3, Z
	eor ST31, H3
	eor ST31, H1
	mov H3, ST41
	eor H3, H2
	mov ZL, H3
	lpm H3, Z
	eor ST41, H3
	eor ST41, H1
	
	mov H1, ST12
	eor H1, ST22
	eor H1, ST32
	eor H1, ST42
	mov H2, ST12
	mov H3, ST12
	eor H3, ST22
	mov ZL, H3
	lpm H3, Z
	eor ST12, H3
	eor ST12, H1
	mov H3, ST22
	eor H3, ST32
	mov ZL, H3
	lpm H3, Z
	eor ST22, H3
	eor ST22, H1
	mov H3, ST32
	eor H3, ST42
	mov ZL, H3
	lpm H3, Z
	eor ST32, H3
	eor ST32, H1
	mov H3, ST42
	eor H3, H2
	mov ZL, H3
	lpm H3, Z
	eor ST42, H3
	eor ST42, H1
	
	mov H1, ST13
	eor H1, ST23
	eor H1, ST33
	eor H1, ST43
	mov H2, ST13
	mov H3, ST13
	eor H3, ST23
	mov ZL, H3
	lpm H3, Z
	eor ST13, H3
	eor ST13, H1
	mov H3, ST23
	eor H3, ST33
	mov ZL, H3
	lpm H3, Z
	eor ST23, H3
	eor ST23, H1
	mov H3, ST33
	eor H3, ST43
	mov ZL, H3
	lpm H3, Z
	eor ST33, H3
	eor ST33, H1
	mov H3, ST43
	eor H3, H2
	mov ZL, H3
	lpm H3, Z
	eor ST43, H3
	eor ST43, H1
	
	mov H1, ST14
	eor H1, ST24
	eor H1, ST34
	eor H1, ST44
	mov H2, ST14
	mov H3, ST14
	eor H3, ST24
	mov ZL, H3
	lpm H3, Z
	eor ST14, H3
	eor ST14, H1
	mov H3, ST24
	eor H3, ST34
	mov ZL, H3
	lpm H3, Z
	eor ST24, H3
	eor ST24, H1
	mov H3, ST34
	eor H3, ST44
	mov ZL, H3
	lpm H3, Z
	eor ST34, H3
	eor ST34, H1
	mov H3, ST44
	eor H3, H2
	mov ZL, H3
	lpm H3, Z
	eor ST44, H3
	eor ST44, H1
	ret
		
;;; ***************************************************************************
;;; 
;;; DECRYPT
;;; This routine decrypts a 128 bit ciphertext block (given in ST11-ST44), 
;;; using an expanded key supplied in the 16*11 memory locations BEFORE YH:YL
;;; (YH:YL points behind the last byte of the key material!). The resulting 128
;;; bit plaintext block is stored in ST11-ST44. 
;;;
;;; Parameters:
;;;         YH:YL:	pointer behind key
;;;         ST11-ST44:  128 bit ciphertext block
;;; Touched registers:
;;;     ST11-ST41,H1,I,ZH,ZL,YH,YL
;;; Clock cycles:	3579

.global aes128_dec
aes128_dec:
	; Save registers r2-17,r28-29
	push_registers 2,17
	push_registers 28,29
	
	; Save the argument pointers to Y (key) and X (plaintext)
	movw XL, ARG2
	movw YL, ARG3
	; Add 16*11 to Y in order to point *behind* the last byte
	adiw Y, 63
	adiw Y, 63
	adiw Y, 50
	; Load the plaintext given by argument to register 0-15
	.irp param,r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15
	ld \param, X+
	.endr

	ldi I, 10
	sbiw YL,16
	rcall addroundkey	; AddRoundKey
	sbiw YL,32
decryp1:ldi ZH, hi8(isbox)	; SubBytes + ShiftRows
	mov ZL, ST11
	lpm ST11, Z
	mov ZL, ST12
	lpm ST12, Z
	mov ZL, ST13
	lpm ST13, Z
	mov ZL, ST14
	lpm ST14, Z
	mov H1, ST21
	mov ZL, ST24
	lpm ST21, Z
	mov ZL, ST23
	lpm ST24, Z
	mov ZL, ST22
	lpm ST23, Z
	mov ZL, H1
	lpm ST22, Z
	mov H1, ST33
	mov ZL, ST31
	lpm ST33, Z
	mov ZL, H1
	lpm ST31, Z
	mov H1, ST34
	mov ZL, ST32
	lpm ST34, Z
	mov ZL, H1
	lpm ST32, Z
	mov H1, ST41
	mov ZL, ST42
	lpm ST41, Z
	mov ZL, ST43
	lpm ST42, Z
	mov ZL, ST44
	lpm ST43, Z
	mov ZL, H1
	lpm ST44, Z
	rcall addroundkey	; AddRoundKey
	sbiw YL,32
	dec I
	brne loop
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
loop:
	ldi ZH, hi8(xtime)	; preprocessing to use MixColumns
	mov ZL, ST11
	eor ZL, ST31
	lpm H2, Z
	mov ZL, H2
	lpm H1, Z
	mov ZL, ST21
	eor ZL, ST41
	lpm H2, Z
	mov ZL, H2
	lpm H2, Z
	eor ST11, H1
	eor ST21, H2
	eor ST31, H1
	eor ST41, H2
	mov ZL, ST12
	eor ZL, ST32
	lpm H2, Z
	mov ZL, H2
	lpm H1, Z
	mov ZL, ST22
	eor ZL, ST42
	lpm H2, Z
	mov ZL, H2
	lpm H2, Z
	eor ST12, H1
	eor ST22, H2
	eor ST32, H1
	eor ST42, H2
	mov ZL, ST13
	eor ZL, ST33
	lpm H2, Z
	mov ZL, H2
	lpm H1, Z
	mov ZL, ST23
	eor ZL, ST43
	lpm H2, Z
	mov ZL, H2
	lpm H2, Z
	eor ST13, H1
	eor ST23, H2
	eor ST33, H1
	eor ST43, H2
	mov ZL, ST14
	eor ZL, ST34
	lpm H2, Z
	mov ZL, H2
	lpm H1, Z
	mov ZL, ST24
	eor ZL, ST44
	lpm H2, Z
	mov ZL, H2
	lpm H2, Z
	eor ST14, H1
	eor ST24, H2
	eor ST34, H1
	eor ST44, H2
	rcall mixcolumns	; MixColumns
	rjmp decryp1

;;; ***************************************************************************
;;; 
;;; S-BOX and "xtime" tables
;;; Rijndael consists of a non-linear step in its rounds (called "sbox step"), 
;;; here implemented with two hard-coded lookup tables (the sbox itself and its
;;; inverse for decryption). To provide an implementation secure against power 
;;; analysis attacks, the polynomial multiplication in the MixColumns operation 
;;; is done via an auxiliary lookup table called xtime. See [1] for details.
;;;
;;; The three tables have to be aligned to a flash position with its lower 
;;; address byte equal to $00. In assembler syntax: low(sbox<<1) == 0.
;;; To ensure the proper alignment of the sboxes, the assembler directive
;;; .ORG is used (below the sboxes are defined to begin at $800). Note, that 
;;; any other address can be used as well, as long as the lower byte is equal 
;;; to $00.
;;;
;;; The order of the sboxes is totally arbitrary. They even do not have to be
;;; allocated in adjacent memory areas.

.section .text.sbox,"ax",@progbits

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

.section .text.isbox,"ax",@progbits

.balign 256
isbox:
.byte 0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb 
.byte 0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb 
.byte 0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e 
.byte 0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25 
.byte 0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92 
.byte 0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84 
.byte 0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06 
.byte 0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b 
.byte 0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73 
.byte 0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e 
.byte 0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b 
.byte 0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4 
.byte 0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f 
.byte 0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef 
.byte 0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61 
.byte 0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d 

.section .text.xtime,"ax",@progbits

.balign 256
xtime:
.byte 0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e
.byte 0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e
.byte 0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e
.byte 0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e
.byte 0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e
.byte 0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe
.byte 0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde
.byte 0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe
.byte 0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05
.byte 0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25
.byte 0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45
.byte 0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65
.byte 0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85
.byte 0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5
.byte 0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5
.byte 0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5
