/*****************************************************************************/
/*                                                                           */
/*                                 aes_gcm.h                                 */
/*                                                                           */
/*               AES-128-GCM and AES-256-GCM AEAD (NIST SP 800-38D)          */
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

#ifndef TYL_AES_GCM_H
#define TYL_AES_GCM_H

#include <stdint.h>
#include <stddef.h>

#define AES_BLOCK_SIZE     16
#define AES_GCM_TAG_SIZE   16
#define AES_GCM_IV_SIZE    12

/* AES-128-GCM Encrypt & Decrypt */
void aes128_gcm_encrypt(const uint8_t key[16],
                        const uint8_t iv[12],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* plaintext, size_t pt_len,
                        uint8_t* ciphertext,
                        uint8_t tag[16]);

int  aes128_gcm_decrypt(const uint8_t key[16],
                        const uint8_t iv[12],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* ciphertext, size_t ct_len,
                        const uint8_t tag[16],
                        uint8_t* plaintext);

/* AES-256-GCM Encrypt & Decrypt */
void aes256_gcm_encrypt(const uint8_t key[32],
                        const uint8_t iv[12],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* plaintext, size_t pt_len,
                        uint8_t* ciphertext,
                        uint8_t tag[16]);

int  aes256_gcm_decrypt(const uint8_t key[32],
                        const uint8_t iv[12],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* ciphertext, size_t ct_len,
                        const uint8_t tag[16],
                        uint8_t* plaintext);

#endif /* TYL_AES_GCM_H */
