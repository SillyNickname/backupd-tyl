/*****************************************************************************/
/*                                                                           */
/*                                  speck.c                                  */
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

#include "speck.h"
#include "poly1305.h"
#include <string.h>

#define ROTR64(x, r) (((x) >> (r)) | ((x) << (64 - (r))))
#define ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))

#define SPECK_ROUND(x, y, k) do { \
    x = (ROTR64(x, 8) + y) ^ (k); \
    y = ROTL64(y, 3) ^ x;         \
} while (0)

static uint64_t load64_le(const uint8_t* p) {
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static void store64_le(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

void speck128_init(speck128_ctx* ctx, const uint8_t key[SPECK128_KEY_SIZE]) {
    uint64_t k0 = load64_le(key);
    uint64_t l0 = load64_le(key + 8);

    ctx->round_keys[0] = k0;
    for (uint64_t i = 0; i < 31; ++i) {
        SPECK_ROUND(l0, k0, i);
        ctx->round_keys[i + 1] = k0;
    }
}

void speck128_encrypt_block(const speck128_ctx* ctx, const uint8_t in[16], uint8_t out[16]) {
    uint64_t y = load64_le(in);
    uint64_t x = load64_le(in + 8);

    for (int i = 0; i < 32; ++i) {
        SPECK_ROUND(x, y, ctx->round_keys[i]);
    }

    store64_le(out, y);
    store64_le(out + 8, x);
}

void speck_poly1305_encrypt(const uint8_t key[SPECK128_KEY_SIZE],
                            const uint8_t nonce[SPECK128_NONCE_SIZE],
                            const uint8_t* ad, size_t ad_len,
                            const uint8_t* pt, size_t pt_len,
                            uint8_t* ct,
                            uint8_t tag[SPECK128_TAG_SIZE]) {
    speck128_ctx ctx;
    speck128_init(&ctx, key);

    /* Generate 32-byte Poly1305 key using counter 0 and 1 */
    uint8_t poly_key[32];
    uint8_t ctr_blk[16];
    memcpy(ctr_blk, nonce, 16);

    uint64_t ctr = load64_le(ctr_blk + 8);
    speck128_encrypt_block(&ctx, ctr_blk, poly_key);
    store64_le(ctr_blk + 8, ctr + 1);
    speck128_encrypt_block(&ctx, ctr_blk, poly_key + 16);

    /* Encrypt plaintext in CTR mode starting with counter 2 */
    uint64_t counter = ctr + 2;
    size_t offset = 0;
    while (offset < pt_len) {
        store64_le(ctr_blk + 8, counter++);
        uint8_t keystream[16];
        speck128_encrypt_block(&ctx, ctr_blk, keystream);

        size_t chunk = pt_len - offset;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; ++i) {
            ct[offset + i] = pt[offset + i] ^ keystream[i];
        }
        offset += chunk;
    }

    /* Authenticate AD, Ciphertext, and lengths with Poly1305 (RFC 8439 style) */
    poly1305_ctx pctx;
    poly1305_init(&pctx, poly_key);
    if (ad && ad_len > 0) {
        poly1305_update(&pctx, ad, ad_len);
        if (ad_len % 16) {
            uint8_t zeros[16] = { 0 };
            poly1305_update(&pctx, zeros, 16 - (ad_len % 16));
        }
    }
    if (ct && pt_len > 0) {
        poly1305_update(&pctx, ct, pt_len);
        if (pt_len % 16) {
            uint8_t zeros[16] = { 0 };
            poly1305_update(&pctx, zeros, 16 - (pt_len % 16));
        }
    }
    uint8_t lens[16];
    store64_le(lens, (uint64_t)ad_len);
    store64_le(lens + 8, (uint64_t)pt_len);
    poly1305_update(&pctx, lens, 16);
    poly1305_finish(&pctx, tag);
}

int speck_poly1305_decrypt(const uint8_t key[SPECK128_KEY_SIZE],
                           const uint8_t nonce[SPECK128_NONCE_SIZE],
                           const uint8_t* ad, size_t ad_len,
                           const uint8_t* ct, size_t ct_len,
                           const uint8_t tag[SPECK128_TAG_SIZE],
                           uint8_t* pt) {
    speck128_ctx ctx;
    speck128_init(&ctx, key);

    /* Generate Poly1305 key */
    uint8_t poly_key[32];
    uint8_t ctr_blk[16];
    memcpy(ctr_blk, nonce, 16);

    uint64_t ctr = load64_le(ctr_blk + 8);
    speck128_encrypt_block(&ctx, ctr_blk, poly_key);
    store64_le(ctr_blk + 8, ctr + 1);
    speck128_encrypt_block(&ctx, ctr_blk, poly_key + 16);

    /* Verify Poly1305 tag first (encrypt-then-MAC) */
    poly1305_ctx pctx;
    poly1305_init(&pctx, poly_key);
    if (ad && ad_len > 0) {
        poly1305_update(&pctx, ad, ad_len);
        if (ad_len % 16) {
            uint8_t zeros[16] = { 0 };
            poly1305_update(&pctx, zeros, 16 - (ad_len % 16));
        }
    }
    if (ct && ct_len > 0) {
        poly1305_update(&pctx, ct, ct_len);
        if (ct_len % 16) {
            uint8_t zeros[16] = { 0 };
            poly1305_update(&pctx, zeros, 16 - (ct_len % 16));
        }
    }
    uint8_t lens[16];
    store64_le(lens, (uint64_t)ad_len);
    store64_le(lens + 8, (uint64_t)ct_len);
    poly1305_update(&pctx, lens, 16);

    uint8_t calc_tag[16];
    poly1305_finish(&pctx, calc_tag);

    if (poly1305_verify(tag, calc_tag) != 0) {
        memset(pt, 0, ct_len);
        return -1;
    }

    /* Tag matches: decrypt ciphertext in CTR mode */
    uint64_t counter = ctr + 2;
    size_t offset = 0;
    while (offset < ct_len) {
        store64_le(ctr_blk + 8, counter++);
        uint8_t keystream[16];
        speck128_encrypt_block(&ctx, ctr_blk, keystream);

        size_t chunk = ct_len - offset;
        if (chunk > 16) chunk = 16;
        for (size_t i = 0; i < chunk; ++i) {
            pt[offset + i] = ct[offset + i] ^ keystream[i];
        }
        offset += chunk;
    }

    return 0;
}
