/*****************************************************************************/
/*                                                                           */
/*                                 x25519.h                                  */
/*                                                                           */
/*                  X25519 Elliptic-Curve Diffie-Hellman                     */
/*                               (RFC 7748)                                  */
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

#ifndef TYL_X25519_H
#define TYL_X25519_H

#include <stdint.h>
#include <stddef.h>

#define X25519_KEY_SIZE 32

/* Generate an ephemeral keypair: private key and public key */
int x25519_keygen(uint8_t public_key[X25519_KEY_SIZE],
                  uint8_t private_key[X25519_KEY_SIZE]);

/* Compute public key from private key */
void x25519_public_from_private(uint8_t public_key[X25519_KEY_SIZE],
                               const uint8_t private_key[X25519_KEY_SIZE]);

/* Compute shared secret = X25519(private_key, peer_public_key).
 * Returns 0 on success, -1 on invalid peer public key (e.g. all zeros).
 */
int x25519_shared_secret(uint8_t shared_secret[X25519_KEY_SIZE],
                         const uint8_t private_key[X25519_KEY_SIZE],
                         const uint8_t peer_public_key[X25519_KEY_SIZE]);

#endif /* TYL_X25519_H */
