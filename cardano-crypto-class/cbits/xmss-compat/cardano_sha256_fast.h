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

#endif
