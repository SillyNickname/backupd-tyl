/*****************************************************************************/
/*                                                                           */
/*                           chacha20poly1305.c                              */
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

#include "chacha20poly1305.h"
#include "poly1305.h"
#include <string.h>

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define CHACHA_QUARTERROUND(a, b, c, d) do { \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);  \
} while (0)

static uint32_t load32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void store64_le(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        p[i] = (uint8_t)(v >> (i * 8));
    }
}

static void chacha20_block(uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    int i;
    for (i = 0; i < 16; ++i) x[i] = state[i];

    for (i = 0; i < 10; ++i) {
        /* Column rounds */
        CHACHA_QUARTERROUND(x[0], x[4], x[8],  x[12]);
        CHACHA_QUARTERROUND(x[1], x[5], x[9],  x[13]);
        CHACHA_QUARTERROUND(x[2], x[6], x[10], x[14]);
        CHACHA_QUARTERROUND(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        CHACHA_QUARTERROUND(x[0], x[5], x[10], x[15]);
        CHACHA_QUARTERROUND(x[1], x[6], x[11], x[12]);
        CHACHA_QUARTERROUND(x[2], x[7], x[8],  x[13]);
        CHACHA_QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }

    for (i = 0; i < 16; ++i) {
        store32_le(out + i * 4, x[i] + state[i]);
    }
}

static void chacha20_init_state(uint32_t state[16],
                                const uint8_t key[32],
                                uint32_t counter,
                                const uint8_t nonce[12]) {
    /* Constants "expand 32-byte k" */
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    /* Key */
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(key + i * 4);
    }

    /* Counter */
    state[12] = counter;

    /* Nonce (96-bit) */
    state[13] = load32_le(nonce + 0);
    state[14] = load32_le(nonce + 4);
    state[15] = load32_le(nonce + 8);
}

void chacha20_poly1305_encrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                              const uint8_t nonce[CHACHA20_NONCE_SIZE],
                              const uint8_t* ad, size_t ad_len,
                              const uint8_t* pt, size_t pt_len,
                              uint8_t* ct,
                              uint8_t tag[CHACHA20_TAG_SIZE]) {
    uint32_t state[16];
    uint8_t block[64];
    uint8_t poly_key[32];

    /* Block 0 generates the Poly1305 key */
    chacha20_init_state(state, key, 0, nonce);
    chacha20_block(state, block);
    memcpy(poly_key, block, 32);

    /* Encrypt plaintext starting from block 1 */
    uint32_t counter = 1;
    size_t offset = 0;
    while (offset < pt_len) {
        state[12] = counter++;
        chacha20_block(state, block);

        size_t chunk = pt_len - offset;
        if (chunk > 64) chunk = 64;
        for (size_t i = 0; i < chunk; ++i) {
            ct[offset + i] = pt[offset + i] ^ block[i];
        }
        offset += chunk;
    }

    /* Compute Poly1305 MAC over AD and Ciphertext */
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

int chacha20_poly1305_decrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                             const uint8_t nonce[CHACHA20_NONCE_SIZE],
                             const uint8_t* ad, size_t ad_len,
                             const uint8_t* ct, size_t ct_len,
                             const uint8_t tag[CHACHA20_TAG_SIZE],
                             uint8_t* pt) {
    uint32_t state[16];
    uint8_t block[64];
    uint8_t poly_key[32];

    /* Block 0 generates the Poly1305 key */
    chacha20_init_state(state, key, 0, nonce);
    chacha20_block(state, block);
    memcpy(poly_key, block, 32);

    /* Verify Poly1305 MAC first */
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

    /* Decrypt ciphertext */
    uint32_t counter = 1;
    size_t offset = 0;
    while (offset < ct_len) {
        state[12] = counter++;
        chacha20_block(state, block);

        size_t chunk = ct_len - offset;
        if (chunk > 64) chunk = 64;
        for (size_t i = 0; i < chunk; ++i) {
            pt[offset + i] = ct[offset + i] ^ block[i];
        }
        offset += chunk;
    }

    return 0;
}

void hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t out[32]) {
    uint32_t x[16];
    x[0]  = 0x61707865;
    x[1]  = 0x3320646e;
    x[2]  = 0x79622d32;
    x[3]  = 0x6b206574;
    for (int i = 0; i < 8; ++i) {
        x[4 + i] = load32_le(key + i * 4);
    }
    for (int i = 0; i < 4; ++i) {
        x[12 + i] = load32_le(nonce + i * 4);
    }

    for (int i = 0; i < 10; ++i) {
        /* Column rounds */
        CHACHA_QUARTERROUND(x[0], x[4], x[8],  x[12]);
        CHACHA_QUARTERROUND(x[1], x[5], x[9],  x[13]);
        CHACHA_QUARTERROUND(x[2], x[6], x[10], x[14]);
        CHACHA_QUARTERROUND(x[3], x[7], x[11], x[15]);
        /* Diagonal rounds */
        CHACHA_QUARTERROUND(x[0], x[5], x[10], x[15]);
        CHACHA_QUARTERROUND(x[1], x[6], x[11], x[12]);
        CHACHA_QUARTERROUND(x[2], x[7], x[8],  x[13]);
        CHACHA_QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }

    store32_le(out + 0,  x[0]);
    store32_le(out + 4,  x[1]);
    store32_le(out + 8,  x[2]);
    store32_le(out + 12, x[3]);
    store32_le(out + 16, x[12]);
    store32_le(out + 20, x[13]);
    store32_le(out + 24, x[14]);
    store32_le(out + 28, x[15]);
}

void xchacha20_poly1305_encrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                               const uint8_t nonce[XCHACHA20_NONCE_SIZE],
                               const uint8_t* ad, size_t ad_len,
                               const uint8_t* pt, size_t pt_len,
                               uint8_t* ct,
                               uint8_t tag[CHACHA20_TAG_SIZE]) {
    uint8_t subkey[32];
    hchacha20(key, nonce, subkey);

    uint8_t subnonce[12];
    memset(subnonce, 0, 4);
    memcpy(subnonce + 4, nonce + 16, 8);

    chacha20_poly1305_encrypt(subkey, subnonce, ad, ad_len, pt, pt_len, ct, tag);
}

int xchacha20_poly1305_decrypt(const uint8_t key[CHACHA20_KEY_SIZE],
                              const uint8_t nonce[XCHACHA20_NONCE_SIZE],
                              const uint8_t* ad, size_t ad_len,
                              const uint8_t* ct, size_t ct_len,
                              const uint8_t tag[CHACHA20_TAG_SIZE],
                              uint8_t* pt) {
    uint8_t subkey[32];
    hchacha20(key, nonce, subkey);

    uint8_t subnonce[12];
    memset(subnonce, 0, 4);
    memcpy(subnonce + 4, nonce + 16, 8);

    return chacha20_poly1305_decrypt(subkey, subnonce, ad, ad_len, ct, ct_len, tag, pt);
}
