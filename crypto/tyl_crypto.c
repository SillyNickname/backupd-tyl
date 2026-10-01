/*****************************************************************************/
/*                                                                           */
/*                               tyl_crypto.c                                */
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

#include "tyl_crypto.h"
#include "sha256.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#ifdef TYL_USE_OPENSSL
#include <openssl/opensslv.h>
#include <openssl/evp.h>

/*
 * If the local system version of OpenSSL is older than the package baseline
 * (OpenSSL 1.1.1 LTS / 0x10101000L), automatically use the cryptographic
 * implementations included with the package instead of the outdated local library.
 */
#if !defined(OPENSSL_VERSION_NUMBER) || (OPENSSL_VERSION_NUMBER < TYL_OPENSSL_MIN_VERSION_NUMBER)
#undef TYL_USE_OPENSSL
#endif

#ifdef TYL_USE_OPENSSL
static int openssl_aead_encrypt(const EVP_CIPHER* cipher,
                                const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* pt, size_t pt_len,
                                uint8_t* ct, uint8_t tag[16]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0;
    int ok = 0;
    do {
        if (EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) != 1) break;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) break;
        if (aad && aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) break;
        }
        if (pt && pt_len > 0) {
            if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) break;
        }
        if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1) break;
        ok = 1;
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

static int openssl_aead_decrypt(const EVP_CIPHER* cipher,
                                const uint8_t* key, const uint8_t* nonce, size_t nonce_len,
                                const uint8_t* aad, size_t aad_len,
                                const uint8_t* ct, size_t ct_len,
                                const uint8_t tag[16], uint8_t* pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0;
    int ok = 0;
    do {
        if (EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)nonce_len, NULL) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)tag) != 1) break;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) break;
        if (aad && aad_len > 0) {
            if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1) break;
        }
        if (ct && ct_len > 0) {
            if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) break;
        }
        if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1) break;
        ok = 1;
    } while (0);
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}
#endif
#endif

int tyl_crypto_has_system_openssl(void) {
#ifdef TYL_USE_OPENSSL
    /* Ensure dynamic runtime library is also at least OpenSSL 1.1.1 */
    if (OpenSSL_version_num() < TYL_OPENSSL_MIN_VERSION_NUMBER) {
        return 0; /* Runtime library is older than package baseline */
    }
    return 1;
#else
    return 0;
#endif
}

const char* tyl_crypto_engine_desc(void) {
#ifdef TYL_USE_OPENSSL
    if (OpenSSL_version_num() >= TYL_OPENSSL_MIN_VERSION_NUMBER) {
        static char desc[128];
        snprintf(desc, sizeof(desc), "System OpenSSL libcrypto (%s, hardware-accelerated)", OpenSSL_version(OPENSSL_VERSION));
        return desc;
    } else {
        static char desc[128];
        snprintf(desc, sizeof(desc), "Local bundled copy (system libcrypto %s is older than package baseline %s)",
                 OpenSSL_version(OPENSSL_VERSION), TYL_OPENSSL_MIN_VERSION_TEXT);
        return desc;
    }
#else
    return "Local bundled copy (zero external dependencies)";
#endif
}

int tyl_crypto_session_init(tyl_session_t* s, tyl_role_t role) {
    if (!s) return -1;
    memset(s, 0, sizeof(*s));
    s->role = role;
    s->cipher_id = TYL_CIPHER_AES256GCM;
    s->send_seq = 0;
    s->recv_seq = 0;

    if (x25519_keygen(s->pub_key, s->priv_key) != 0) {
        return -1;
    }
    return 0;
}

int tyl_crypto_cipher_from_name(const char* name) {
    if (!name) return TYL_CIPHER_UNKNOWN;
    if (strcasecmp(name, "ascon") == 0 || strcasecmp(name, "ascon128a") == 0 || strcasecmp(name, "light") == 0) {
        return TYL_CIPHER_ASCON128A;
    }
    if (strcasecmp(name, "speck") == 0 || strcasecmp(name, "speck128") == 0 || strcasecmp(name, "speck-poly1305") == 0) {
        return TYL_CIPHER_SPECK128;
    }
    if (strcasecmp(name, "chacha20") == 0 || strcasecmp(name, "chacha20poly1305") == 0 || strcasecmp(name, "chacha") == 0) {
        return TYL_CIPHER_CHACHA20;
    }
    if (strcasecmp(name, "xchacha20") == 0 || strcasecmp(name, "xchacha20poly1305") == 0 || strcasecmp(name, "xchacha") == 0) {
        return TYL_CIPHER_XCHACHA20;
    }
    if (strcasecmp(name, "aes256") == 0 || strcasecmp(name, "aes256gcm") == 0 || strcasecmp(name, "aes-gcm") == 0 ||
        strcasecmp(name, "aes") == 0 || strcasecmp(name, "secure") == 0 || strcasecmp(name, "default") == 0) {
        return TYL_CIPHER_AES256GCM;
    }
    if (strcasecmp(name, "aes128") == 0 || strcasecmp(name, "aes128gcm") == 0) {
        return TYL_CIPHER_AES128GCM;
    }
    return TYL_CIPHER_UNKNOWN;
}

const char* tyl_crypto_cipher_name(int cipher_id) {
    switch (cipher_id) {
        case TYL_CIPHER_ASCON128A: return "ascon128a";
        case TYL_CIPHER_SPECK128:  return "speck128";
        case TYL_CIPHER_CHACHA20:  return "chacha20poly1305";
        case TYL_CIPHER_AES256GCM: return "aes256gcm";
        case TYL_CIPHER_AES128GCM: return "aes128gcm";
        case TYL_CIPHER_XCHACHA20: return "xchacha20poly1305";
        default:                   return "unknown";
    }
}

int tyl_crypto_derive_keys(tyl_session_t* s, const uint8_t peer_pub[X25519_KEY_SIZE], int cipher_id) {
    if (!s || !peer_pub) return -1;
    memcpy(s->peer_pub_key, peer_pub, X25519_KEY_SIZE);
    s->cipher_id = cipher_id;

    if (x25519_shared_secret(s->shared_secret, s->priv_key, peer_pub) != 0) {
        return -1;
    }

    /* Salt is formed by (client_pub || server_pub) */
    uint8_t salt[64];
    if (s->role == TYL_ROLE_CLIENT) {
        memcpy(salt, s->pub_key, 32);
        memcpy(salt + 32, peer_pub, 32);
    } else {
        memcpy(salt, peer_pub, 32);
        memcpy(salt + 32, s->pub_key, 32);
    }

    const char* info = "backupd-tyl session key derivation v1.0";
    uint8_t okm[128]; /* 32 bytes c2s_key, 32 bytes s2c_key, 32 bytes c2s_iv, 32 bytes s2c_iv */

    if (hkdf_sha256(salt, sizeof(salt), s->shared_secret, 32,
                    (const uint8_t*)info, strlen(info),
                    okm, sizeof(okm)) != 0) {
        return -1;
    }

    memcpy(s->c2s_key, okm, 32);
    memcpy(s->s2c_key, okm + 32, 32);
    memcpy(s->c2s_iv, okm + 64, 32);
    memcpy(s->s2c_iv, okm + 96, 32);

    return 0;
}

static void make_nonce(const uint8_t* base_iv, uint64_t seq, uint8_t* nonce, size_t nonce_len) {
    memcpy(nonce, base_iv, nonce_len);
    for (int i = 0; i < 8; ++i) {
        int idx = (int)nonce_len - 1 - i;
        if (idx >= 0) {
            nonce[idx] ^= (uint8_t)(seq >> (i * 8));
        }
    }
}

int tyl_crypto_encrypt_frame(tyl_session_t* s,
                            const uint8_t* plaintext, size_t pt_len,
                            uint8_t* frame_buf, size_t max_frame_len,
                            size_t* out_frame_len) {
    if (!s || pt_len > TYL_MAX_FRAME_PAYLOAD) return -1;
    size_t needed = 2 + pt_len + TYL_TAG_SIZE;
    if (max_frame_len < needed) return -1;

    const uint8_t* key = (s->role == TYL_ROLE_CLIENT) ? s->c2s_key : s->s2c_key;
    const uint8_t* base_iv = (s->role == TYL_ROLE_CLIENT) ? s->c2s_iv : s->s2c_iv;
    uint64_t seq = s->send_seq++;

    /* Frame header: 2 bytes payload length */
    frame_buf[0] = (uint8_t)((pt_len >> 8) & 0xFF);
    frame_buf[1] = (uint8_t)(pt_len & 0xFF);

    /* AAD: 8 bytes sequence number + 2 bytes length */
    uint8_t aad[10];
    for (int i = 0; i < 8; ++i) {
        aad[7 - i] = (uint8_t)((seq >> (i * 8)) & 0xFF);
    }
    aad[8] = frame_buf[0];
    aad[9] = frame_buf[1];

    uint8_t* ct = frame_buf + 2;
    uint8_t* tag = frame_buf + 2 + pt_len;

#ifdef TYL_USE_OPENSSL
    if (OpenSSL_version_num() >= TYL_OPENSSL_MIN_VERSION_NUMBER && s->cipher_id == TYL_CIPHER_AES256GCM) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        if (openssl_aead_encrypt(EVP_aes_256_gcm(), key, nonce, 12, aad, sizeof(aad), plaintext, pt_len, ct, tag) != 0) {
            return -1;
        }
    } else if (OpenSSL_version_num() >= TYL_OPENSSL_MIN_VERSION_NUMBER && s->cipher_id == TYL_CIPHER_AES128GCM) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        if (openssl_aead_encrypt(EVP_aes_128_gcm(), key, nonce, 12, aad, sizeof(aad), plaintext, pt_len, ct, tag) != 0) {
            return -1;
        }
    } else if (OpenSSL_version_num() >= TYL_OPENSSL_MIN_VERSION_NUMBER && s->cipher_id == TYL_CIPHER_CHACHA20) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        if (openssl_aead_encrypt(EVP_chacha20_poly1305(), key, nonce, 12, aad, sizeof(aad), plaintext, pt_len, ct, tag) != 0) {
            return -1;
        }
    } else
#endif
    if (s->cipher_id == TYL_CIPHER_AES256GCM) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        aes256_gcm_encrypt(key, nonce, aad, sizeof(aad), plaintext, pt_len, ct, tag);
    } else if (s->cipher_id == TYL_CIPHER_AES128GCM) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        aes128_gcm_encrypt(key, nonce, aad, sizeof(aad), plaintext, pt_len, ct, tag);
    } else if (s->cipher_id == TYL_CIPHER_CHACHA20) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad), plaintext, pt_len, ct, tag);
    } else if (s->cipher_id == TYL_CIPHER_XCHACHA20) {
        uint8_t nonce[24];
        make_nonce(base_iv, seq, nonce, 24);
        xchacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad), plaintext, pt_len, ct, tag);
    } else if (s->cipher_id == TYL_CIPHER_ASCON128A) {
        uint8_t nonce[16];
        make_nonce(base_iv, seq, nonce, 16);
        ascon128a_encrypt(key, nonce, aad, sizeof(aad), plaintext, pt_len, ct, tag);
    } else if (s->cipher_id == TYL_CIPHER_SPECK128) {
        uint8_t nonce[16];
        make_nonce(base_iv, seq, nonce, 16);
        speck_poly1305_encrypt(key, nonce, aad, sizeof(aad), plaintext, pt_len, ct, tag);
    } else {
        return -1;
    }

    if (out_frame_len) {
        *out_frame_len = needed;
    }
    return 0;
}

int tyl_crypto_decrypt_frame(tyl_session_t* s,
                            const uint8_t* frame_buf, size_t frame_len,
                            uint8_t* plaintext, size_t max_pt_len,
                            size_t* out_pt_len) {
    if (!s || !frame_buf || frame_len < 2 + TYL_TAG_SIZE) return -1;

    size_t pt_len = ((size_t)frame_buf[0] << 8) | (size_t)frame_buf[1];
    if (frame_len != 2 + pt_len + TYL_TAG_SIZE) return -1;
    if (max_pt_len < pt_len) return -1;

    const uint8_t* key = (s->role == TYL_ROLE_CLIENT) ? s->s2c_key : s->c2s_key;
    const uint8_t* base_iv = (s->role == TYL_ROLE_CLIENT) ? s->s2c_iv : s->c2s_iv;
    uint64_t seq = s->recv_seq++;

    /* AAD: 8 bytes sequence number + 2 bytes length */
    uint8_t aad[10];
    for (int i = 0; i < 8; ++i) {
        aad[7 - i] = (uint8_t)((seq >> (i * 8)) & 0xFF);
    }
    aad[8] = frame_buf[0];
    aad[9] = frame_buf[1];

    const uint8_t* ct = frame_buf + 2;
    const uint8_t* tag = frame_buf + 2 + pt_len;

    int res = -1;

#ifdef TYL_USE_OPENSSL
    if (OpenSSL_version_num() >= TYL_OPENSSL_MIN_VERSION_NUMBER && s->cipher_id == TYL_CIPHER_AES256GCM) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        res = openssl_aead_decrypt(EVP_aes_256_gcm(), key, nonce, 12, aad, sizeof(aad), ct, pt_len, tag, plaintext);
    } else if (OpenSSL_version_num() >= TYL_OPENSSL_MIN_VERSION_NUMBER && s->cipher_id == TYL_CIPHER_AES128GCM) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        res = openssl_aead_decrypt(EVP_aes_128_gcm(), key, nonce, 12, aad, sizeof(aad), ct, pt_len, tag, plaintext);
    } else if (OpenSSL_version_num() >= TYL_OPENSSL_MIN_VERSION_NUMBER && s->cipher_id == TYL_CIPHER_CHACHA20) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        res = openssl_aead_decrypt(EVP_chacha20_poly1305(), key, nonce, 12, aad, sizeof(aad), ct, pt_len, tag, plaintext);
    } else
#endif
    if (s->cipher_id == TYL_CIPHER_AES256GCM) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        res = aes256_gcm_decrypt(key, nonce, aad, sizeof(aad), ct, pt_len, tag, plaintext);
    } else if (s->cipher_id == TYL_CIPHER_AES128GCM) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        res = aes128_gcm_decrypt(key, nonce, aad, sizeof(aad), ct, pt_len, tag, plaintext);
    } else if (s->cipher_id == TYL_CIPHER_CHACHA20) {
        uint8_t nonce[12];
        make_nonce(base_iv, seq, nonce, 12);
        res = chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad), ct, pt_len, tag, plaintext);
    } else if (s->cipher_id == TYL_CIPHER_XCHACHA20) {
        uint8_t nonce[24];
        make_nonce(base_iv, seq, nonce, 24);
        res = xchacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad), ct, pt_len, tag, plaintext);
    } else if (s->cipher_id == TYL_CIPHER_ASCON128A) {
        uint8_t nonce[16];
        make_nonce(base_iv, seq, nonce, 16);
        res = ascon128a_decrypt(key, nonce, aad, sizeof(aad), ct, pt_len, tag, plaintext);
    } else if (s->cipher_id == TYL_CIPHER_SPECK128) {
        uint8_t nonce[16];
        make_nonce(base_iv, seq, nonce, 16);
        res = speck_poly1305_decrypt(key, nonce, aad, sizeof(aad), ct, pt_len, tag, plaintext);
    }

    if (res != 0) {
        return -1;
    }
    if (out_pt_len) {
        *out_pt_len = pt_len;
    }
    return 0;
}

static int write_exact(int fd, const void* buf, size_t len) {
    const uint8_t* p = (const uint8_t*)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

static int read_exact(int fd, void* buf, size_t len) {
    uint8_t* p = (uint8_t*)buf;
    size_t remaining = len;
    while (remaining > 0) {
        ssize_t n = read(fd, p, remaining);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        p += n;
        remaining -= (size_t)n;
    }
    return 0;
}

int tyl_crypto_send_frame(tyl_session_t* s, int fd, const void* buf, size_t len) {
    static uint8_t frame_buf[TYL_MAX_FRAME_PAYLOAD + 2 + TYL_TAG_SIZE];
    size_t frame_len = 0;
    if (tyl_crypto_encrypt_frame(s, (const uint8_t*)buf, len, frame_buf, sizeof(frame_buf), &frame_len) != 0) {
        return -1;
    }
    return write_exact(fd, frame_buf, frame_len);
}

int tyl_crypto_recv_frame(tyl_session_t* s, int fd, void* buf, size_t max_len, size_t* out_len) {
    uint8_t hdr[2];
    if (read_exact(fd, hdr, 2) != 0) {
        return -1;
    }
    size_t pt_len = ((size_t)hdr[0] << 8) | (size_t)hdr[1];
    if (pt_len > TYL_MAX_FRAME_PAYLOAD || pt_len > max_len) {
        return -1;
    }

    size_t rest_len = pt_len + TYL_TAG_SIZE;
    uint8_t* frame_buf = (uint8_t*)malloc(2 + rest_len);
    if (!frame_buf) return -1;
    frame_buf[0] = hdr[0];
    frame_buf[1] = hdr[1];

    if (read_exact(fd, frame_buf + 2, rest_len) != 0) {
        free(frame_buf);
        return -1;
    }

    int rc = tyl_crypto_decrypt_frame(s, frame_buf, 2 + rest_len, (uint8_t*)buf, max_len, out_len);
    free(frame_buf);
    return rc;
}

int tyl_crypto_constant_time_memcmp(const void* a, const void* b, size_t n) {
    const uint8_t* p1 = (const uint8_t*)a;
    const uint8_t* p2 = (const uint8_t*)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) {
        diff |= (p1[i] ^ p2[i]);
    }
    return (diff == 0) ? 0 : -1;
}

int tyl_crypto_verify_password(const char* expected, const char* provided) {
    if (!expected || expected[0] == '\0') {
        /* No password configured */
        return 0;
    }
    if (!provided) return -1;
    size_t len1 = strlen(expected);
    size_t len2 = strlen(provided);
    size_t max_len = (len1 > len2) ? len1 : len2;
    uint8_t diff = (uint8_t)(len1 ^ len2);
    for (size_t i = 0; i < max_len; ++i) {
        uint8_t c1 = (i < len1) ? (uint8_t)expected[i] : 0;
        uint8_t c2 = (i < len2) ? (uint8_t)provided[i] : 0;
        diff |= (c1 ^ c2);
    }
    return (diff == 0) ? 0 : -1;
}

void tyl_crypto_bin2hex(const uint8_t* bin, size_t len, char* hex) {
    static const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        hex[i * 2]     = hex_chars[(bin[i] >> 4) & 0x0F];
        hex[i * 2 + 1] = hex_chars[bin[i] & 0x0F];
    }
    hex[len * 2] = '\0';
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int tyl_crypto_hex2bin(const char* hex, uint8_t* bin, size_t max_len, size_t* out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t bin_len = hex_len / 2;
    if (bin_len > max_len) return -1;

    for (size_t i = 0; i < bin_len; ++i) {
        int h = hex_val(hex[i * 2]);
        int l = hex_val(hex[i * 2 + 1]);
        if (h < 0 || l < 0) return -1;
        bin[i] = (uint8_t)((h << 4) | l);
    }
    if (out_len) *out_len = bin_len;
    return 0;
}
