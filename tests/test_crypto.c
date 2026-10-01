/*
 * test_crypto.c - Unit tests for backupd-tyl cryptographic primitives
 *
 * (C) 2026 Antigravity / Gemini (Google DeepMind)
 * Part of backupd-tyl (Backupd - Thirty Years Later)
 * Requested and Commissioned by: Andre Kajita (kajita@univap.br)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "crypto/sha256.h"
#include "crypto/x25519.h"
#include "crypto/ascon128a.h"
#include "crypto/speck.h"
#include "crypto/poly1305.h"
#include "crypto/chacha20poly1305.h"
#include "crypto/aes_gcm.h"
#include "crypto/tyl_crypto.h"

int main(void) {
    printf("Testing Crypto Primitives for backupd-tyl...\n");
    printf("  Engine: %s\n", tyl_crypto_engine_desc());

    /* 1. SHA-256 */
    uint8_t hash[32];
    sha256_hash((const uint8_t*)"hello world", 11, hash);
    char hex[65];
    tyl_crypto_bin2hex(hash, 32, hex);
    printf("  SHA-256('hello world') = %s\n", hex);
    assert(strcmp(hex, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9") == 0);
    printf("  [PASS] SHA-256\n");

    /* 2. X25519 */
    uint8_t a_pub[32], a_priv[32];
    uint8_t b_pub[32], b_priv[32];
    assert(x25519_keygen(a_pub, a_priv) == 0);
    assert(x25519_keygen(b_pub, b_priv) == 0);

    uint8_t a_shared[32], b_shared[32];
    assert(x25519_shared_secret(a_shared, a_priv, b_pub) == 0);
    assert(x25519_shared_secret(b_shared, b_priv, a_pub) == 0);
    assert(memcmp(a_shared, b_shared, 32) == 0);
    printf("  [PASS] X25519 Ephemeral Key Exchange\n");

    /* 3. ASCON-128a */
    uint8_t key16[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
    uint8_t nonce16[16] = {15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0};
    const char* msg = "Testing ASCON-128a AEAD lightweight encryption for backupd-tyl";
    size_t msg_len = strlen(msg);
    uint8_t ct[128];
    uint8_t tag[16];
    uint8_t pt[128];
    ascon128a_encrypt(key16, nonce16, (const uint8_t*)"header", 6, (const uint8_t*)msg, msg_len, ct, tag);
    assert(ascon128a_decrypt(key16, nonce16, (const uint8_t*)"header", 6, ct, msg_len, tag, pt) == 0);
    assert(memcmp(pt, msg, msg_len) == 0);
    /* Tamper tag check */
    tag[0] ^= 1;
    assert(ascon128a_decrypt(key16, nonce16, (const uint8_t*)"header", 6, ct, msg_len, tag, pt) != 0);
    printf("  [PASS] ASCON-128a AEAD\n");

    /* 4. Speck-Poly1305 */
    speck_poly1305_encrypt(key16, nonce16, (const uint8_t*)"ad", 2, (const uint8_t*)msg, msg_len, ct, tag);
    assert(speck_poly1305_decrypt(key16, nonce16, (const uint8_t*)"ad", 2, ct, msg_len, tag, pt) == 0);
    assert(memcmp(pt, msg, msg_len) == 0);
    tag[0] ^= 1;
    assert(speck_poly1305_decrypt(key16, nonce16, (const uint8_t*)"ad", 2, ct, msg_len, tag, pt) != 0);
    printf("  [PASS] Speck-128/128-Poly1305 AEAD\n");

    /* 5. ChaCha20-Poly1305 */
    uint8_t key32[32] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31};
    uint8_t nonce12[12] = {1,2,3,4,5,6,7,8,9,10,11,12};
    chacha20_poly1305_encrypt(key32, nonce12, (const uint8_t*)"auth", 4, (const uint8_t*)msg, msg_len, ct, tag);
    assert(chacha20_poly1305_decrypt(key32, nonce12, (const uint8_t*)"auth", 4, ct, msg_len, tag, pt) == 0);
    assert(memcmp(pt, msg, msg_len) == 0);
    tag[0] ^= 1;
    assert(chacha20_poly1305_decrypt(key32, nonce12, (const uint8_t*)"auth", 4, ct, msg_len, tag, pt) != 0);
    printf("  [PASS] ChaCha20-Poly1305 AEAD\n");

    /* 6. HChaCha20 & XChaCha20-Poly1305 (IETF test vector) */
    uint8_t h_key[32];
    for (int i = 0; i < 32; ++i) h_key[i] = (uint8_t)i;
    uint8_t h_nonce[16] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27
    };
    uint8_t h_out[32];
    hchacha20(h_key, h_nonce, h_out);
    char h_hex[65];
    for (int i = 0; i < 32; ++i) sprintf(h_hex + i * 2, "%02x", h_out[i]);
    assert(strcmp(h_hex, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc") == 0);
    printf("  [PASS] HChaCha20 Subkey PRF (IETF vector)\n");

    uint8_t xnonce24[24] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27,
        1, 2, 3, 4, 5, 6, 7, 8
    };
    xchacha20_poly1305_encrypt(key32, xnonce24, (const uint8_t*)"ad", 2, (const uint8_t*)msg, msg_len, ct, tag);
    assert(xchacha20_poly1305_decrypt(key32, xnonce24, (const uint8_t*)"ad", 2, ct, msg_len, tag, pt) == 0);
    assert(memcmp(pt, msg, msg_len) == 0);
    tag[0] ^= 1;
    assert(xchacha20_poly1305_decrypt(key32, xnonce24, (const uint8_t*)"ad", 2, ct, msg_len, tag, pt) != 0);
    printf("  [PASS] XChaCha20-Poly1305 (24-byte extended nonce)\n");

    /* 7. AES-128-GCM (NIST SP 800-38D Test Vectors) */
    uint8_t zero_key128[16] = {0};
    uint8_t zero_iv[12] = {0};
    uint8_t gcm_tag[16];
    aes128_gcm_encrypt(zero_key128, zero_iv, NULL, 0, NULL, 0, NULL, gcm_tag);
    char tag_hex[33];
    for (int i = 0; i < 16; ++i) sprintf(tag_hex + i * 2, "%02x", gcm_tag[i]);
    assert(strcmp(tag_hex, "58e2fccefa7e3061367f1d57a4e7455a") == 0);

    /* NIST Test Case 2: 16-byte zero PT */
    uint8_t zero_pt[16] = {0};
    uint8_t gcm_ct[16] = {0};
    aes128_gcm_encrypt(zero_key128, zero_iv, NULL, 0, zero_pt, 16, gcm_ct, gcm_tag);
    char ct_hex[33];
    for (int i = 0; i < 16; ++i) {
        sprintf(ct_hex + i * 2, "%02x", gcm_ct[i]);
        sprintf(tag_hex + i * 2, "%02x", gcm_tag[i]);
    }
    assert(strcmp(ct_hex, "0388dace60b6a392f328c2b971b2fe78") == 0);
    assert(strcmp(tag_hex, "ab6e47d42cec13bdf53a67b21257bddf") == 0);
    assert(aes128_gcm_decrypt(zero_key128, zero_iv, NULL, 0, gcm_ct, 16, gcm_tag, pt) == 0);
    assert(memcmp(pt, zero_pt, 16) == 0);
    gcm_tag[0] ^= 1;
    assert(aes128_gcm_decrypt(zero_key128, zero_iv, NULL, 0, gcm_ct, 16, gcm_tag, pt) != 0);
    printf("  [PASS] AES-128-GCM (NIST SP 800-38D vectors 1 & 2)\n");

    /* 8. AES-256-GCM (NIST SP 800-38D Test Vector) */
    uint8_t zero_key256[32] = {0};
    aes256_gcm_encrypt(zero_key256, zero_iv, NULL, 0, NULL, 0, NULL, gcm_tag);
    for (int i = 0; i < 16; ++i) sprintf(tag_hex + i * 2, "%02x", gcm_tag[i]);
    assert(strcmp(tag_hex, "530f8afbc74536b9a963b4f1c4cb738b") == 0);

    /* Encrypt & Decrypt sample message with AES-256-GCM */
    aes256_gcm_encrypt(key32, zero_iv, (const uint8_t*)"aad", 3, (const uint8_t*)msg, msg_len, ct, tag);
    assert(aes256_gcm_decrypt(key32, zero_iv, (const uint8_t*)"aad", 3, ct, msg_len, tag, pt) == 0);
    assert(memcmp(pt, msg, msg_len) == 0);
    tag[0] ^= 1;
    assert(aes256_gcm_decrypt(key32, zero_iv, (const uint8_t*)"aad", 3, ct, msg_len, tag, pt) != 0);
    printf("  [PASS] AES-256-GCM (NIST SP 800-38D vector & verification)\n");

    /* 9. Session Handshake Simulation Across All 6 Ciphers */
    int test_ciphers[] = {
        TYL_CIPHER_AES256GCM,
        TYL_CIPHER_AES128GCM,
        TYL_CIPHER_CHACHA20,
        TYL_CIPHER_XCHACHA20,
        TYL_CIPHER_ASCON128A,
        TYL_CIPHER_SPECK128
    };
    int num_ciphers = sizeof(test_ciphers) / sizeof(test_ciphers[0]);

    tyl_session_t client_sess, server_sess;
    for (int i = 0; i < num_ciphers; ++i) {
        int cid = test_ciphers[i];
        assert(tyl_crypto_session_init(&client_sess, TYL_ROLE_CLIENT) == 0);
        assert(tyl_crypto_session_init(&server_sess, TYL_ROLE_SERVER) == 0);

        assert(tyl_crypto_derive_keys(&client_sess, server_sess.pub_key, cid) == 0);
        assert(tyl_crypto_derive_keys(&server_sess, client_sess.pub_key, cid) == 0);

        uint8_t frame[256];
        size_t frame_len = 0;
        const char* client_msg = "BACKUP_DATA_STREAM_CHUNK_VERIFICATION";
        assert(tyl_crypto_encrypt_frame(&client_sess, (const uint8_t*)client_msg, strlen(client_msg), frame, sizeof(frame), &frame_len) == 0);

        size_t out_pt_len = 0;
        assert(tyl_crypto_decrypt_frame(&server_sess, frame, frame_len, pt, sizeof(pt), &out_pt_len) == 0);
        assert(out_pt_len == strlen(client_msg));
        assert(memcmp(pt, client_msg, out_pt_len) == 0);

        /* Tamper detection check */
        frame[frame_len - 1] ^= 0x55;
        assert(tyl_crypto_decrypt_frame(&server_sess, frame, frame_len, pt, sizeof(pt), &out_pt_len) != 0);

        printf("  [PASS] Session Framing: %s\n", tyl_crypto_cipher_name(cid));
    }

    /* 10. Password verify */
    assert(tyl_crypto_verify_password("SecretPass123", "SecretPass123") == 0);
    assert(tyl_crypto_verify_password("SecretPass123", "WrongPass") != 0);
    assert(tyl_crypto_verify_password(NULL, NULL) == 0);
    assert(tyl_crypto_verify_password("", "") == 0);
    printf("  [PASS] Timing-safe Password Verification\n");

    printf("\nAll crypto tests passed successfully!\n");
    return 0;
}
