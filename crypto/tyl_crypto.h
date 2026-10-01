/*****************************************************************************/
/*                                                                           */
/*                               tyl_crypto.h                                */
/*                                                                           */
/*                Unified TLS-Style Crypto Session Layer                     */
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

#ifndef TYL_CRYPTO_H
#define TYL_CRYPTO_H

#include <stdint.h>
#include <stddef.h>
#include "x25519.h"
#include "ascon128a.h"
#include "speck.h"
#include "chacha20poly1305.h"
#include "aes_gcm.h"

#define TYL_CIPHER_UNKNOWN   0
#define TYL_CIPHER_ASCON128A 1
#define TYL_CIPHER_SPECK128  2
#define TYL_CIPHER_CHACHA20  3
#define TYL_CIPHER_AES256GCM 4
#define TYL_CIPHER_AES128GCM 5
#define TYL_CIPHER_XCHACHA20 6

#define TYL_TAG_SIZE         16
#define TYL_MAX_FRAME_PAYLOAD 65519

/* Baseline requirement for external system OpenSSL (OpenSSL 1.1.1 LTS) */
#define TYL_OPENSSL_MIN_VERSION_NUMBER 0x10101000L
#define TYL_OPENSSL_MIN_VERSION_TEXT   "OpenSSL 1.1.1"

/* Human-readable crypto engine description (System vs Bundled copy) */
const char* tyl_crypto_engine_desc(void);

typedef enum {
    TYL_ROLE_CLIENT = 1,
    TYL_ROLE_SERVER = 2
} tyl_role_t;

typedef struct {
    tyl_role_t role;
    int        cipher_id;

    /* Ephemeral keypair and peer public key */
    uint8_t    priv_key[X25519_KEY_SIZE];
    uint8_t    pub_key[X25519_KEY_SIZE];
    uint8_t    peer_pub_key[X25519_KEY_SIZE];
    uint8_t    shared_secret[X25519_KEY_SIZE];

    /* Derived symmetric keys (up to 32 bytes) */
    uint8_t    c2s_key[32];
    uint8_t    s2c_key[32];

    /* Base nonces / IVs (up to 32 bytes) */
    uint8_t    c2s_iv[32];
    uint8_t    s2c_iv[32];

    /* Directional message sequence counters */
    uint64_t   send_seq;
    uint64_t   recv_seq;
} tyl_session_t;

/* Check if compiled with system OpenSSL / libcrypto hardware acceleration */
int tyl_crypto_has_system_openssl(void);

/* Initialize session and generate ephemeral X25519 keypair */
int tyl_crypto_session_init(tyl_session_t* s, tyl_role_t role);

/* Parse cipher name to ID */
int tyl_crypto_cipher_from_name(const char* name);

/* Return cipher name from ID */
const char* tyl_crypto_cipher_name(int cipher_id);

/* Complete key exchange and key derivation once peer public key is received */
int tyl_crypto_derive_keys(tyl_session_t* s, const uint8_t peer_pub[X25519_KEY_SIZE], int cipher_id);

/* Encrypt a payload into an AEAD frame buffer */
int tyl_crypto_encrypt_frame(tyl_session_t* s,
                            const uint8_t* plaintext, size_t pt_len,
                            uint8_t* frame_buf, size_t max_frame_len,
                            size_t* out_frame_len);

/* Decrypt an AEAD frame buffer into plaintext */
int tyl_crypto_decrypt_frame(tyl_session_t* s,
                            const uint8_t* frame_buf, size_t frame_len,
                            uint8_t* plaintext, size_t max_pt_len,
                            size_t* out_pt_len);

/* Send an encrypted frame directly over a socket fd */
int tyl_crypto_send_frame(tyl_session_t* s, int fd, const void* buf, size_t len);

/* Receive and decrypt a frame directly from a socket fd */
int tyl_crypto_recv_frame(tyl_session_t* s, int fd, void* buf, size_t max_len, size_t* out_len);

/* Constant-time memory comparison */
int tyl_crypto_constant_time_memcmp(const void* a, const void* b, size_t n);

/* Constant-time password verification */
int tyl_crypto_verify_password(const char* expected, const char* provided);

/* Hex encoding/decoding utilities */
void tyl_crypto_bin2hex(const uint8_t* bin, size_t len, char* hex);
int  tyl_crypto_hex2bin(const char* hex, uint8_t* bin, size_t max_len, size_t* out_len);

#endif /* TYL_CRYPTO_H */
