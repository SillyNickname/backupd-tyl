/*****************************************************************************/
/*                                                                           */
/*                                 sha256.c                                  */
/*                                                                           */
/*                  SHA-256, HMAC-SHA256, and HKDF-SHA256                     */
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

#include "sha256.h"
#include <string.h>

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)       (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1(x)       (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0(x)      (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1(x)      (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(sha256_ctx* ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i;

    for (i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)data[i * 4] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(sha256_ctx* ctx) {
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void sha256_update(sha256_ctx* ctx, const uint8_t* data, size_t len) {
    size_t i;
    size_t buffer_idx = (size_t)(ctx->count & 0x3F);
    ctx->count += len;

    for (i = 0; i < len; ++i) {
        ctx->buffer[buffer_idx++] = data[i];
        if (buffer_idx == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, ctx->buffer);
            buffer_idx = 0;
        }
    }
}

void sha256_final(sha256_ctx* ctx, uint8_t digest[SHA256_DIGEST_SIZE]) {
    size_t i = (size_t)(ctx->count & 0x3F);
    uint64_t bit_len = ctx->count * 8;
    int j;

    ctx->buffer[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->buffer[i++] = 0x00;
        sha256_transform(ctx, ctx->buffer);
        memset(ctx->buffer, 0, 56);
    } else {
        while (i < 56) ctx->buffer[i++] = 0x00;
    }

    for (j = 7; j >= 0; --j) {
        ctx->buffer[56 + (7 - j)] = (uint8_t)((bit_len >> (j * 8)) & 0xFF);
    }
    sha256_transform(ctx, ctx->buffer);

    for (j = 0; j < 8; ++j) {
        digest[j * 4]     = (uint8_t)((ctx->state[j] >> 24) & 0xFF);
        digest[j * 4 + 1] = (uint8_t)((ctx->state[j] >> 16) & 0xFF);
        digest[j * 4 + 2] = (uint8_t)((ctx->state[j] >> 8) & 0xFF);
        digest[j * 4 + 3] = (uint8_t)(ctx->state[j] & 0xFF);
    }
}

void sha256_hash(const uint8_t* data, size_t len, uint8_t digest[SHA256_DIGEST_SIZE]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, digest);
}

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t mac[SHA256_DIGEST_SIZE]) {
    sha256_ctx ctx;
    uint8_t k_pad[SHA256_BLOCK_SIZE];
    uint8_t k[SHA256_DIGEST_SIZE];
    size_t i;

    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_hash(key, key_len, k);
        key = k;
        key_len = SHA256_DIGEST_SIZE;
    }

    /* Inner pad: key XOR 0x36 */
    memset(k_pad, 0x36, SHA256_BLOCK_SIZE);
    for (i = 0; i < key_len; ++i) {
        k_pad[i] ^= key[i];
    }
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, mac);

    /* Outer pad: key XOR 0x5c */
    memset(k_pad, 0x5c, SHA256_BLOCK_SIZE);
    for (i = 0; i < key_len; ++i) {
        k_pad[i] ^= key[i];
    }
    sha256_init(&ctx);
    sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, mac, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, mac);
}

int hkdf_sha256(const uint8_t* salt, size_t salt_len,
                const uint8_t* ikm, size_t ikm_len,
                const uint8_t* info, size_t info_len,
                uint8_t* okm, size_t okm_len) {
    uint8_t prk[SHA256_DIGEST_SIZE];
    uint8_t default_salt[SHA256_DIGEST_SIZE];
    uint8_t t[SHA256_DIGEST_SIZE];
    size_t t_len = 0;
    size_t generated = 0;
    uint8_t counter = 1;
    sha256_ctx ctx;
    uint8_t k_pad[SHA256_BLOCK_SIZE];
    size_t i;

    if (okm_len > 255 * SHA256_DIGEST_SIZE) {
        return -1;
    }

    /* Step 1: HKDF-Extract */
    if (salt == NULL || salt_len == 0) {
        memset(default_salt, 0, SHA256_DIGEST_SIZE);
        salt = default_salt;
        salt_len = SHA256_DIGEST_SIZE;
    }
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);

    /* Step 2: HKDF-Expand */
    while (generated < okm_len) {
        /* Compute T(counter) = HMAC(PRK, T(counter-1) || info || counter) */
        memset(k_pad, 0x36, SHA256_BLOCK_SIZE);
        for (i = 0; i < SHA256_DIGEST_SIZE; ++i) k_pad[i] ^= prk[i];
        sha256_init(&ctx);
        sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
        if (t_len > 0) {
            sha256_update(&ctx, t, t_len);
        }
        if (info && info_len > 0) {
            sha256_update(&ctx, info, info_len);
        }
        sha256_update(&ctx, &counter, 1);
        sha256_final(&ctx, t);

        memset(k_pad, 0x5c, SHA256_BLOCK_SIZE);
        for (i = 0; i < SHA256_DIGEST_SIZE; ++i) k_pad[i] ^= prk[i];
        sha256_init(&ctx);
        sha256_update(&ctx, k_pad, SHA256_BLOCK_SIZE);
        sha256_update(&ctx, t, SHA256_DIGEST_SIZE);
        sha256_final(&ctx, t);
        t_len = SHA256_DIGEST_SIZE;

        size_t to_copy = okm_len - generated;
        if (to_copy > SHA256_DIGEST_SIZE) {
            to_copy = SHA256_DIGEST_SIZE;
        }
        memcpy(okm + generated, t, to_copy);
        generated += to_copy;
        counter++;
    }

    return 0;
}
