/*****************************************************************************/
/*                                                                           */
/*                           chacha20poly1305.h                              */
/*                                                                           */
/*                    ChaCha20-Poly1305 High-Security AEAD                   */
/*                                (RFC 8439)                                 */
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

#ifndef TYL_CHACHA20POLY1305_H
#define TYL_CHACHA20POLY1305_H

#include <stdint.h>
#include <stddef.h>

#define CHACHA20_KEY_SIZE    32
#define CHACHA20_NONCE_SIZE  12
#define CHACHA20_TAG_SIZE    16
#define XCHACHA20_NONCE_SIZE 24

/* HChaCha20 subkey derivation (RFC draft-arciszewski-xchacha) */
void hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t out[32]);

void chacha20_poly1305_encrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                              const uint8_t nonce[CHACHA20_NONCE_SIZE],
                              const uint8_t* ad, size_t ad_len,
                              const uint8_t* pt, size_t pt_len,
                              uint8_t* ct,
                              uint8_t tag[CHACHA20_TAG_SIZE]);

int chacha20_poly1305_decrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                             const uint8_t nonce[CHACHA20_NONCE_SIZE],
                             const uint8_t* ad, size_t ad_len,
                             const uint8_t* ct, size_t ct_len,
                             const uint8_t tag[CHACHA20_TAG_SIZE],
                             uint8_t* pt);

/* XChaCha20-Poly1305 (24-byte extended nonce) */
void xchacha20_poly1305_encrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                               const uint8_t nonce[XCHACHA20_NONCE_SIZE],
                               const uint8_t* ad, size_t ad_len,
                               const uint8_t* pt, size_t pt_len,
                               uint8_t* ct,
                               uint8_t tag[CHACHA20_TAG_SIZE]);

int xchacha20_poly1305_decrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                              const uint8_t nonce[XCHACHA20_NONCE_SIZE],
                              const uint8_t* ad, size_t ad_len,
                              const uint8_t* ct, size_t ct_len,
                              const uint8_t tag[CHACHA20_TAG_SIZE],
                              uint8_t* pt);

#endif /* TYL_CHACHA20POLY1305_H */
