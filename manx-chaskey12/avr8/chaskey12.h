/*
 * IncFile1.h
 *
 * Created: 18/07/2023 06:07:28
 *  Author: alexa
 */ 


#ifndef CHASKEY12_H_
#define CHASKEY12_H_

#include <stdint.h>

extern void chaskey12_enc(uint8_t ct[16], const uint8_t pt[16], const uint8_t key[16]);


#endif /* CHASKEY12_H_ */