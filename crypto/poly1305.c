/*****************************************************************************/
/*                                                                           */
/*                                poly1305.c                                 */
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

#include "poly1305.h"
#include <string.h>

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

void poly1305_init(poly1305_ctx* ctx, const uint8_t key[POLY1305_KEY_SIZE]) {
    /* Clamp r */
    ctx->r[0] = (load32_le(key + 0)) & 0x3ffffff;
    ctx->r[1] = (load32_le(key + 3) >> 2) & 0x3ffff03;
    ctx->r[2] = (load32_le(key + 6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (load32_le(key + 9) >> 6) & 0x3f03fff;
    ctx->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;

    /* h = 0 */
    ctx->h[0] = 0;
    ctx->h[1] = 0;
    ctx->h[2] = 0;
    ctx->h[3] = 0;
    ctx->h[4] = 0;

    /* save pad */
    ctx->pad[0] = load32_le(key + 16);
    ctx->pad[1] = load32_le(key + 20);
    ctx->pad[2] = load32_le(key + 24);
    ctx->pad[3] = load32_le(key + 28);

    ctx->leftover = 0;
    ctx->final = 0;
}

static void poly1305_blocks(poly1305_ctx* ctx, const uint8_t* m, size_t bytes) {
    const uint32_t hibit = (ctx->final) ? 0 : ((uint32_t)1 << 24);
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];

    while (bytes >= 16) {
        /* h += m[i] */
        h0 += (load32_le(m + 0)) & 0x3ffffff;
        h1 += (load32_le(m + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(m + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(m + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(m + 12) >> 8) | hibit;

        /* h *= r */
        uint64_t d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
        uint64_t d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
        uint64_t d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
        uint64_t d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
        uint64_t d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

        /* carry propagation */
        uint32_t c;
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff; d1 += c;
        c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff; d2 += c;
        c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff; d3 += c;
        c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff; d4 += c;
        c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff; h0 += c * 5;
        c = (h0 >> 26);           h0 = h0 & 0x3ffffff;           h1 += c;

        m += 16;
        bytes -= 16;
    }

    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2; ctx->h[3] = h3; ctx->h[4] = h4;
}

void poly1305_update(poly1305_ctx* ctx, const uint8_t* m, size_t bytes) {
    if (ctx->leftover) {
        size_t want = 16 - ctx->leftover;
        if (want > bytes) want = bytes;
        for (size_t i = 0; i < want; ++i) ctx->buffer[ctx->leftover + i] = m[i];
        bytes -= want;
        m += want;
        ctx->leftover += want;
        if (ctx->leftover < 16) return;
        poly1305_blocks(ctx, ctx->buffer, 16);
        ctx->leftover = 0;
    }

    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        poly1305_blocks(ctx, m, want);
        m += want;
        bytes -= want;
    }

    if (bytes) {
        for (size_t i = 0; i < bytes; ++i) ctx->buffer[ctx->leftover + i] = m[i];
        ctx->leftover += bytes;
    }
}

void poly1305_finish(poly1305_ctx* ctx, uint8_t mac[POLY1305_TAG_SIZE]) {
    if (ctx->leftover) {
        size_t i = ctx->leftover;
        ctx->buffer[i++] = 1;
        for (; i < 16; ++i) ctx->buffer[i] = 0;
        ctx->final = 1;
        poly1305_blocks(ctx, ctx->buffer, 16);
    }

    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t c;

    c = h1 >> 26; h1 &= 0x3ffffff; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffff; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;

    /* compute h + -p */
    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);

    /* select h if h < p, or g if h >= p */
    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    /* h = h % 2^128 */
    h0 = ((h0)       | (h1 << 26)) & 0xffffffff;
    h1 = ((h1 >> 6)  | (h2 << 20)) & 0xffffffff;
    h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff;
    h3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffff;

    /* mac = (h + pad) % 2^128 */
    uint64_t f0 = (uint64_t)h0 + ctx->pad[0];
    uint64_t f1 = (uint64_t)h1 + ctx->pad[1] + (f0 >> 32);
    uint64_t f2 = (uint64_t)h2 + ctx->pad[2] + (f1 >> 32);
    uint64_t f3 = (uint64_t)h3 + ctx->pad[3] + (f2 >> 32);

    store32_le(mac + 0, (uint32_t)f0);
    store32_le(mac + 4, (uint32_t)f1);
    store32_le(mac + 8, (uint32_t)f2);
    store32_le(mac + 12, (uint32_t)f3);
}

void poly1305_auth(uint8_t mac[POLY1305_TAG_SIZE], const uint8_t* m, size_t bytes, const uint8_t key[POLY1305_KEY_SIZE]) {
    poly1305_ctx ctx;
    poly1305_init(&ctx, key);
    poly1305_update(&ctx, m, bytes);
    poly1305_finish(&ctx, mac);
}

int poly1305_verify(const uint8_t mac1[POLY1305_TAG_SIZE], const uint8_t mac2[POLY1305_TAG_SIZE]) {
    uint8_t diff = 0;
    for (int i = 0; i < POLY1305_TAG_SIZE; ++i) {
        diff |= (mac1[i] ^ mac2[i]);
    }
    return (diff == 0) ? 0 : -1;
}
