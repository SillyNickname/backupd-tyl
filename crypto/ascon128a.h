/*****************************************************************************/
/*                                                                           */
/*                                ascon128a.h                                */
/*                                                                           */
/*                       ASCON-128a AEAD (NIST LWC)                          */
/*                                                                           */
/* (C) 2026 Antigravity / Gemini (Google DeepMind)                           */
/* Based on original backupd concept by Ullrich von Bassewitz (1998)         */
/* [Note: original author email uz@musoftware.de is no longer active]        */
/* Requested and Commissioned by: Andre Kajita (kajita@univap.br)            */
/*                                                                           */
/* This software is provided 'as-is', without any express or implied         */
/* warranty. In no event will the authors be held liable for any damages     */
/* arising from the use of this software.                                    */
/*****************************************************************************/

#ifndef TYL_ASCON128A_H
#define TYL_ASCON128A_H

#include <stdint.h>
#include <stddef.h>

#define ASCON128A_KEY_SIZE   16
#define ASCON128A_NONCE_SIZE 16
#define ASCON128A_TAG_SIZE   16

/* ASCON-128a AEAD Encrypt:
 * Output ciphertext length equals plaintext length.
 * Tag is written to tag buffer (16 bytes).
 */
void ascon128a_encrypt(const uint8_t key[ASCON128A_KEY_SIZE],
                       const uint8_t nonce[ASCON128A_NONCE_SIZE],
                       const uint8_t* ad, size_t ad_len,
                       const uint8_t* pt, size_t pt_len,
                       uint8_t* ct,
                       uint8_t tag[ASCON128A_TAG_SIZE]);

/* ASCON-128a AEAD Decrypt:
 * Returns 0 on successful authentication, -1 on tag mismatch.
 */
int ascon128a_decrypt(const uint8_t key[ASCON128A_KEY_SIZE],
                      const uint8_t nonce[ASCON128A_NONCE_SIZE],
                      const uint8_t* ad, size_t ad_len,
                      const uint8_t* ct, size_t ct_len,
                      const uint8_t tag[ASCON128A_TAG_SIZE],
                      uint8_t* pt);

#endif /* TYL_ASCON128A_H */
