/*****************************************************************************/
/*                                                                           */
/*                                  speck.h                                  */
/*                                                                           */
/*                    Speck-128/128 Lightweight Block Cipher                 */
/*                           and Speck-Poly1305 AEAD                         */
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

#ifndef TYL_SPECK_H
#define TYL_SPECK_H

#include <stdint.h>
#include <stddef.h>

#define SPECK128_KEY_SIZE   16
#define SPECK128_NONCE_SIZE 16
#define SPECK128_TAG_SIZE   16

typedef struct {
    uint64_t round_keys[32];
} speck128_ctx;

/* Initialize Speck-128/128 context with 128-bit key */
void speck128_init(speck128_ctx* ctx, const uint8_t key[SPECK128_KEY_SIZE]);

/* Encrypt single 128-bit block */
void speck128_encrypt_block(const speck128_ctx* ctx, const uint8_t in[16], uint8_t out[16]);

/* Speck-Poly1305 AEAD Encrypt */
void speck_poly1305_encrypt(const uint8_t key[SPECK128_KEY_SIZE],
                            const uint8_t nonce[SPECK128_NONCE_SIZE],
                            const uint8_t* ad, size_t ad_len,
                            const uint8_t* pt, size_t pt_len,
                            uint8_t* ct,
                            uint8_t tag[SPECK128_TAG_SIZE]);

/* Speck-Poly1305 AEAD Decrypt: returns 0 on success, -1 on tag mismatch */
int speck_poly1305_decrypt(const uint8_t key[SPECK128_KEY_SIZE],
                           const uint8_t nonce[SPECK128_NONCE_SIZE],
                           const uint8_t* ad, size_t ad_len,
                           const uint8_t* ct, size_t ct_len,
                           const uint8_t tag[SPECK128_TAG_SIZE],
                           uint8_t* pt);

#endif /* TYL_SPECK_H */
