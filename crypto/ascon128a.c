/*****************************************************************************/
/*                                                                           */
/*                                ascon128a.c                                */
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

#include "ascon128a.h"
#include <string.h>

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static uint64_t load64_be(const uint8_t* p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  | ((uint64_t)p[7]);
}

static void store64_be(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v);
}

typedef struct {
    uint64_t x0, x1, x2, x3, x4;
} ascon_state;

static const uint8_t ASCON_RC[12] = {
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b
};

static void ascon_round(ascon_state* s, uint8_t rc) {
    uint64_t t0, t1, t2, t3, t4;

    /* Constant addition */
    s->x2 ^= rc;

    /* Substitution layer (S-box) */
    s->x0 ^= s->x4; s->x4 ^= s->x3; s->x2 ^= s->x1;
    t0 = ~s->x0; t1 = ~s->x1; t2 = ~s->x2; t3 = ~s->x3; t4 = ~s->x4;
    t0 &= s->x1; t1 &= s->x2; t2 &= s->x3; t3 &= s->x4; t4 &= s->x0;
    s->x0 ^= t1; s->x1 ^= t2; s->x2 ^= t3; s->x3 ^= t4; s->x4 ^= t0;
    s->x1 ^= s->x0; s->x0 ^= s->x4; s->x3 ^= s->x2; s->x2 = ~s->x2;

    /* Linear diffusion layer */
    s->x0 ^= ROTR64(s->x0, 19) ^ ROTR64(s->x0, 28);
    s->x1 ^= ROTR64(s->x1, 61) ^ ROTR64(s->x1, 39);
    s->x2 ^= ROTR64(s->x2, 1)  ^ ROTR64(s->x2, 6);
    s->x3 ^= ROTR64(s->x3, 10) ^ ROTR64(s->x3, 17);
    s->x4 ^= ROTR64(s->x4, 7)  ^ ROTR64(s->x4, 41);
}

static void ascon_permute(ascon_state* s, int rounds) {
    for (int i = 12 - rounds; i < 12; ++i) {
        ascon_round(s, ASCON_RC[i]);
    }
}

void ascon128a_encrypt(const uint8_t key[ASCON128A_KEY_SIZE],
                       const uint8_t nonce[ASCON128A_NONCE_SIZE],
                       const uint8_t* ad, size_t ad_len,
                       const uint8_t* pt, size_t pt_len,
                       uint8_t* ct,
                       uint8_t tag[ASCON128A_TAG_SIZE]) {
    ascon_state s;
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);
    uint64_t n0 = load64_be(nonce);
    uint64_t n1 = load64_be(nonce + 8);

    /* Initialization: IV for ASCON-128a is 0x80800c0800000000ULL */
    s.x0 = 0x80800c0800000000ULL;
    s.x1 = k0;
    s.x2 = k1;
    s.x3 = n0;
    s.x4 = n1;
    ascon_permute(&s, 12);
    s.x3 ^= k0;
    s.x4 ^= k1;

    /* Associated Data */
    if (ad_len > 0) {
        while (ad_len >= 16) {
            s.x0 ^= load64_be(ad);
            s.x1 ^= load64_be(ad + 8);
            ascon_permute(&s, 8);
            ad += 16;
            ad_len -= 16;
        }
        uint8_t pad[16];
        memset(pad, 0, 16);
        memcpy(pad, ad, ad_len);
        pad[ad_len] = 0x80;
        s.x0 ^= load64_be(pad);
        s.x1 ^= load64_be(pad + 8);
        ascon_permute(&s, 8);
    }
    /* Domain separation */
    s.x4 ^= 1;

    /* Plaintext / Ciphertext */
    while (pt_len >= 16) {
        s.x0 ^= load64_be(pt);
        s.x1 ^= load64_be(pt + 8);
        store64_be(ct, s.x0);
        store64_be(ct + 8, s.x1);
        ascon_permute(&s, 8);
        pt += 16;
        ct += 16;
        pt_len -= 16;
    }
    uint8_t pad[16];
    memset(pad, 0, 16);
    memcpy(pad, pt, pt_len);
    pad[pt_len] = 0x80;
    s.x0 ^= load64_be(pad);
    s.x1 ^= load64_be(pad + 8);
    uint8_t c_pad[16];
    store64_be(c_pad, s.x0);
    store64_be(c_pad + 8, s.x1);
    memcpy(ct, c_pad, pt_len);

    /* Finalization */
    s.x1 ^= k0;
    s.x2 ^= k1;
    ascon_permute(&s, 12);
    s.x3 ^= k0;
    s.x4 ^= k1;
    store64_be(tag, s.x3);
    store64_be(tag + 8, s.x4);
}

int ascon128a_decrypt(const uint8_t key[ASCON128A_KEY_SIZE],
                      const uint8_t nonce[ASCON128A_NONCE_SIZE],
                      const uint8_t* ad, size_t ad_len,
                      const uint8_t* ct, size_t ct_len,
                      const uint8_t tag[ASCON128A_TAG_SIZE],
                      uint8_t* pt) {
    ascon_state s;
    uint64_t k0 = load64_be(key);
    uint64_t k1 = load64_be(key + 8);
    uint64_t n0 = load64_be(nonce);
    uint64_t n1 = load64_be(nonce + 8);

    /* Initialization */
    s.x0 = 0x80800c0800000000ULL;
    s.x1 = k0;
    s.x2 = k1;
    s.x3 = n0;
    s.x4 = n1;
    ascon_permute(&s, 12);
    s.x3 ^= k0;
    s.x4 ^= k1;

    /* Associated Data */
    if (ad_len > 0) {
        while (ad_len >= 16) {
            s.x0 ^= load64_be(ad);
            s.x1 ^= load64_be(ad + 8);
            ascon_permute(&s, 8);
            ad += 16;
            ad_len -= 16;
        }
        uint8_t pad[16];
        memset(pad, 0, 16);
        memcpy(pad, ad, ad_len);
        pad[ad_len] = 0x80;
        s.x0 ^= load64_be(pad);
        s.x1 ^= load64_be(pad + 8);
        ascon_permute(&s, 8);
    }
    /* Domain separation */
    s.x4 ^= 1;

    /* Ciphertext / Plaintext */
    size_t rem = ct_len;
    while (rem >= 16) {
        uint64_t c0 = load64_be(ct);
        uint64_t c1 = load64_be(ct + 8);
        store64_be(pt, s.x0 ^ c0);
        store64_be(pt + 8, s.x1 ^ c1);
        s.x0 = c0;
        s.x1 = c1;
        ascon_permute(&s, 8);
        ct += 16;
        pt += 16;
        rem -= 16;
    }
    uint8_t c_pad[16];
    memset(c_pad, 0, 16);
    memcpy(c_pad, ct, rem);
    uint8_t s_pad[16];
    store64_be(s_pad, s.x0);
    store64_be(s_pad + 8, s.x1);
    for (size_t i = 0; i < rem; ++i) {
        pt[i] = c_pad[i] ^ s_pad[i];
        s_pad[i] = c_pad[i];
    }
    s_pad[rem] ^= 0x80;
    s.x0 = load64_be(s_pad);
    s.x1 = load64_be(s_pad + 8);

    /* Finalization */
    s.x1 ^= k0;
    s.x2 ^= k1;
    ascon_permute(&s, 12);
    s.x3 ^= k0;
    s.x4 ^= k1;

    uint8_t expected_tag[16];
    store64_be(expected_tag, s.x3);
    store64_be(expected_tag + 8, s.x4);

    /* Constant-time tag comparison */
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= (tag[i] ^ expected_tag[i]);
    }
    if (diff != 0) {
        memset(pt - (ct_len - rem), 0, ct_len);
        return -1;
    }
    return 0;
}
