/*****************************************************************************/
/*                                                                           */
/*                                 aes_gcm.c                                 */
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

#include "aes_gcm.h"
#include <string.h>

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static inline uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

typedef struct {
    uint32_t rk[60];
    int rounds;
} aes_ctx_t;

static void aes_key_init(aes_ctx_t* ctx, const uint8_t* key, int key_bits) {
    int nk = key_bits / 32;
    ctx->rounds = nk + 6;
    for (int i = 0; i < nk; ++i) {
        ctx->rk[i] = ((uint32_t)key[4 * i] << 24) |
                     ((uint32_t)key[4 * i + 1] << 16) |
                     ((uint32_t)key[4 * i + 2] << 8) |
                     ((uint32_t)key[4 * i + 3]);
    }
    for (int i = nk; i < 4 * (ctx->rounds + 1); ++i) {
        uint32_t temp = ctx->rk[i - 1];
        if (i % nk == 0) {
            temp = ((uint32_t)sbox[(temp >> 16) & 0xff] << 24) |
                   ((uint32_t)sbox[(temp >> 8) & 0xff] << 16) |
                   ((uint32_t)sbox[temp & 0xff] << 8) |
                   ((uint32_t)sbox[(temp >> 24) & 0xff]);
            temp ^= ((uint32_t)rcon[i / nk] << 24);
        } else if (nk > 6 && (i % nk == 4)) {
            temp = ((uint32_t)sbox[(temp >> 24) & 0xff] << 24) |
                   ((uint32_t)sbox[(temp >> 16) & 0xff] << 16) |
                   ((uint32_t)sbox[(temp >> 8) & 0xff] << 8) |
                   ((uint32_t)sbox[temp & 0xff]);
        }
        ctx->rk[i] = ctx->rk[i - nk] ^ temp;
    }
}

static void aes_encrypt_block(const aes_ctx_t* ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[4][4];
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[j][i] = in[i * 4 + j];
        }
    }

    /* AddRoundKey 0 */
    for (int i = 0; i < 4; ++i) {
        uint32_t k = ctx->rk[i];
        state[0][i] ^= (uint8_t)(k >> 24);
        state[1][i] ^= (uint8_t)(k >> 16);
        state[2][i] ^= (uint8_t)(k >> 8);
        state[3][i] ^= (uint8_t)(k);
    }

    for (int r = 1; r <= ctx->rounds; ++r) {
        /* SubBytes */
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                state[i][j] = sbox[state[i][j]];
            }
        }

        /* ShiftRows */
        uint8_t t;
        t = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t;
        t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
        t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
        t = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t;

        /* MixColumns (rounds 1 to Nr-1) */
        if (r < ctx->rounds) {
            for (int i = 0; i < 4; ++i) {
                uint8_t a = state[0][i];
                uint8_t b = state[1][i];
                uint8_t c = state[2][i];
                uint8_t d = state[3][i];
                state[0][i] = xtime(a ^ b) ^ b ^ c ^ d;
                state[1][i] = xtime(b ^ c) ^ c ^ d ^ a;
                state[2][i] = xtime(c ^ d) ^ d ^ a ^ b;
                state[3][i] = xtime(d ^ a) ^ a ^ b ^ c;
            }
        }

        /* AddRoundKey */
        for (int i = 0; i < 4; ++i) {
            uint32_t k = ctx->rk[r * 4 + i];
            state[0][i] ^= (uint8_t)(k >> 24);
            state[1][i] ^= (uint8_t)(k >> 16);
            state[2][i] ^= (uint8_t)(k >> 8);
            state[3][i] ^= (uint8_t)(k);
        }
    }

    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            out[i * 4 + j] = state[j][i];
        }
    }
}

static void ghash_mult(uint8_t Z[16], const uint8_t X[16], const uint8_t H[16]) {
    uint8_t V[16];
    memcpy(V, H, 16);
    memset(Z, 0, 16);
    for (int i = 0; i < 128; ++i) {
        if ((X[i / 8] >> (7 - (i % 8))) & 1) {
            for (int j = 0; j < 16; ++j) Z[j] ^= V[j];
        }
        int lsb = V[15] & 1;
        for (int j = 15; j > 0; --j) {
            V[j] = (uint8_t)((V[j] >> 1) | ((V[j - 1] & 1) << 7));
        }
        V[0] >>= 1;
        if (lsb) {
            V[0] ^= 0xe1;
        }
    }
}

static void ghash_update(uint8_t Y[16], const uint8_t* data, size_t len, const uint8_t H[16]) {
    while (len >= 16) {
        for (int i = 0; i < 16; ++i) Y[i] ^= data[i];
        uint8_t next[16];
        ghash_mult(next, Y, H);
        memcpy(Y, next, 16);
        data += 16;
        len -= 16;
    }
    if (len > 0) {
        uint8_t block[16] = {0};
        memcpy(block, data, len);
        for (int i = 0; i < 16; ++i) Y[i] ^= block[i];
        uint8_t next[16];
        ghash_mult(next, Y, H);
        memcpy(Y, next, 16);
    }
}

static void inc32(uint8_t block[16]) {
    for (int i = 15; i >= 12; --i) {
        if (++block[i] != 0) break;
    }
}

static void aes_gcm_encrypt_generic(const uint8_t* key, int key_bits,
                                   const uint8_t iv[12],
                                   const uint8_t* aad, size_t aad_len,
                                   const uint8_t* pt, size_t pt_len,
                                   uint8_t* ct, uint8_t tag[16]) {
    aes_ctx_t ctx;
    aes_key_init(&ctx, key, key_bits);

    uint8_t zero[16] = {0};
    uint8_t H[16];
    aes_encrypt_block(&ctx, zero, H);

    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 1;

    uint8_t tag_mask[16];
    aes_encrypt_block(&ctx, J0, tag_mask);

    uint8_t Ctr[16];
    memcpy(Ctr, J0, 16);

    size_t remaining = pt_len;
    const uint8_t* p = pt;
    uint8_t* c = ct;
    while (remaining >= 16) {
        inc32(Ctr);
        uint8_t mask[16];
        aes_encrypt_block(&ctx, Ctr, mask);
        for (int i = 0; i < 16; ++i) c[i] = p[i] ^ mask[i];
        p += 16;
        c += 16;
        remaining -= 16;
    }
    if (remaining > 0) {
        inc32(Ctr);
        uint8_t mask[16];
        aes_encrypt_block(&ctx, Ctr, mask);
        for (size_t i = 0; i < remaining; ++i) c[i] = p[i] ^ mask[i];
    }

    uint8_t Y[16] = {0};
    if (aad_len > 0) {
        ghash_update(Y, aad, aad_len, H);
    }
    if (pt_len > 0) {
        ghash_update(Y, ct, pt_len, H);
    }

    uint8_t len_block[16];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)pt_len * 8;
    for (int i = 0; i < 8; ++i) {
        len_block[i] = (uint8_t)(aad_bits >> (56 - i * 8));
        len_block[8 + i] = (uint8_t)(ct_bits >> (56 - i * 8));
    }
    ghash_update(Y, len_block, 16, H);

    for (int i = 0; i < 16; ++i) {
        tag[i] = Y[i] ^ tag_mask[i];
    }
}

static int aes_gcm_decrypt_generic(const uint8_t* key, int key_bits,
                                   const uint8_t iv[12],
                                   const uint8_t* aad, size_t aad_len,
                                   const uint8_t* ct, size_t ct_len,
                                   const uint8_t tag[16],
                                   uint8_t* pt) {
    aes_ctx_t ctx;
    aes_key_init(&ctx, key, key_bits);

    uint8_t zero[16] = {0};
    uint8_t H[16];
    aes_encrypt_block(&ctx, zero, H);

    uint8_t J0[16] = {0};
    memcpy(J0, iv, 12);
    J0[15] = 1;

    uint8_t tag_mask[16];
    aes_encrypt_block(&ctx, J0, tag_mask);

    uint8_t Y[16] = {0};
    if (aad_len > 0) {
        ghash_update(Y, aad, aad_len, H);
    }
    if (ct_len > 0) {
        ghash_update(Y, ct, ct_len, H);
    }

    uint8_t len_block[16];
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits = (uint64_t)ct_len * 8;
    for (int i = 0; i < 8; ++i) {
        len_block[i] = (uint8_t)(aad_bits >> (56 - i * 8));
        len_block[8 + i] = (uint8_t)(ct_bits >> (56 - i * 8));
    }
    ghash_update(Y, len_block, 16, H);

    uint8_t expected_tag[16];
    for (int i = 0; i < 16; ++i) {
        expected_tag[i] = Y[i] ^ tag_mask[i];
    }

    /* Constant-time tag verification */
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= (expected_tag[i] ^ tag[i]);
    }
    if (diff != 0) {
        if (pt && ct_len > 0) memset(pt, 0, ct_len);
        return -1;
    }

    /* Decrypt ciphertext */
    uint8_t Ctr[16];
    memcpy(Ctr, J0, 16);

    size_t remaining = ct_len;
    const uint8_t* c = ct;
    uint8_t* p = pt;
    while (remaining >= 16) {
        inc32(Ctr);
        uint8_t mask[16];
        aes_encrypt_block(&ctx, Ctr, mask);
        for (int i = 0; i < 16; ++i) p[i] = c[i] ^ mask[i];
        p += 16;
        c += 16;
        remaining -= 16;
    }
    if (remaining > 0) {
        inc32(Ctr);
        uint8_t mask[16];
        aes_encrypt_block(&ctx, Ctr, mask);
        for (size_t i = 0; i < remaining; ++i) p[i] = c[i] ^ mask[i];
    }

    return 0;
}

void aes128_gcm_encrypt(const uint8_t key[16],
                        const uint8_t iv[12],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* plaintext, size_t pt_len,
                        uint8_t* ciphertext,
                        uint8_t tag[16]) {
    aes_gcm_encrypt_generic(key, 128, iv, aad, aad_len, plaintext, pt_len, ciphertext, tag);
}

int aes128_gcm_decrypt(const uint8_t key[16],
                       const uint8_t iv[12],
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* ciphertext, size_t ct_len,
                       const uint8_t tag[16],
                       uint8_t* plaintext) {
    return aes_gcm_decrypt_generic(key, 128, iv, aad, aad_len, ciphertext, ct_len, tag, plaintext);
}

void aes256_gcm_encrypt(const uint8_t key[32],
                        const uint8_t iv[12],
                        const uint8_t* aad, size_t aad_len,
                        const uint8_t* plaintext, size_t pt_len,
                        uint8_t* ciphertext,
                        uint8_t tag[16]) {
    aes_gcm_encrypt_generic(key, 256, iv, aad, aad_len, plaintext, pt_len, ciphertext, tag);
}

int aes256_gcm_decrypt(const uint8_t key[32],
                       const uint8_t iv[12],
                       const uint8_t* aad, size_t aad_len,
                       const uint8_t* ciphertext, size_t ct_len,
                       const uint8_t tag[16],
                       uint8_t* plaintext) {
    return aes_gcm_decrypt_generic(key, 256, iv, aad, aad_len, ciphertext, ct_len, tag, plaintext);
}
