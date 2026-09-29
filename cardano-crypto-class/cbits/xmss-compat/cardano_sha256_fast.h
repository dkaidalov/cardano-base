/*
 * One-shot SHA-256 with a run-time choice between the x86 SHA extensions
 * (SHA-NI) and libsodium's portable implementation. Used by
 * cbits/xmss-compat/openssl/sha.h for the XMSS reference implementation,
 * whose hashing is one SHA-256 call per hash and dominates its cost.
 */
#ifndef CARDANO_SHA256_FAST_H
#define CARDANO_SHA256_FAST_H

#include <stddef.h>
#include <stdint.h>

/* 1 if this CPU has SHA-NI (plus SSSE3 and SSE4.1), 0 otherwise. Cached. */
int cardano_sha256_shani_available(void);

/* SHA-256 of in[0..len) into out, with SHA-NI. Only call if available. */
void cardano_sha256_shani(uint8_t out[32], const uint8_t *in, size_t len);

/* SHA-256 of in[0..len) into out: SHA-NI if available, libsodium otherwise. */
void cardano_sha256_fast(uint8_t out[32], const uint8_t *in, size_t len);

/*
 * Midstates: the compression state after absorbing one or more complete
 * 64-byte blocks, to be reused for every message that starts with them.
 * cardano_sha256_mid_init absorbs prefix[0..prefixlen) (prefixlen a multiple
 * of 64); cardano_sha256_mid_finish hashes prefix || rest from a copy of that
 * state. Same run-time backend choice as cardano_sha256_fast.
 */
typedef struct {
  int shani;
  uint32_t st[8];
  size_t prefixlen;
  unsigned char sodium[104]; /* crypto_hash_sha256_state, opaque here */
} cardano_sha256_mid;

void cardano_sha256_mid_init(cardano_sha256_mid *mid, const uint8_t *prefix, size_t prefixlen);
void cardano_sha256_mid_finish(uint8_t out[32], const cardano_sha256_mid *mid,
                               const uint8_t *rest, size_t restlen);

#endif
