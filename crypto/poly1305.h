/*****************************************************************************/
/*                                                                           */
/*                                poly1305.h                                 */
/*                                                                           */
/*                       Poly1305 One-Time Authenticator                     */
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

#ifndef TYL_POLY1305_H
#define TYL_POLY1305_H

#include <stdint.h>
#include <stddef.h>

#define POLY1305_KEY_SIZE 32
#define POLY1305_TAG_SIZE 16

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    size_t leftover;
    uint8_t buffer[16];
    uint8_t final;
} poly1305_ctx;

void poly1305_init(poly1305_ctx* ctx, const uint8_t key[POLY1305_KEY_SIZE]);
void poly1305_update(poly1305_ctx* ctx, const uint8_t* m, size_t bytes);
void poly1305_finish(poly1305_ctx* ctx, uint8_t mac[POLY1305_TAG_SIZE]);
void poly1305_auth(uint8_t mac[POLY1305_TAG_SIZE], const uint8_t* m, size_t bytes, const uint8_t key[POLY1305_KEY_SIZE]);
int poly1305_verify(const uint8_t mac1[POLY1305_TAG_SIZE], const uint8_t mac2[POLY1305_TAG_SIZE]);

#endif /* TYL_POLY1305_H */
