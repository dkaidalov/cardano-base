/*
 * Thin wrapper over mldsa-native (cbits/mldsa-native) for the ML-DSA-44
 * DSIGN instance in Cardano.Crypto.DSIGN.MLDSA44.
 *
 * The library is compiled for parameter set 44 only, with the randomized
 * API disabled (no RNG dependency). Signing is the deterministic variant of
 * FIPS 204 Algorithm 2 (rnd = 0^32) with an empty context string, and
 * verification is FIPS 204 Algorithm 3 with an empty context string.
 *
 * The in-memory sign key is the concatenation seed || sk || pk, so that
 * deriving the verification key and recovering the seed are plain copies.
 * The seed alone is what gets serialised; sk and pk are re-derived from it.
 */
#ifndef CARDANO_MLDSA44_H
#define CARDANO_MLDSA44_H

#include <stddef.h>
#include <stdint.h>

#define CARDANO_MLDSA44_SEEDBYTES 32
#define CARDANO_MLDSA44_PUBLICKEYBYTES 1312
#define CARDANO_MLDSA44_SECRETKEYBYTES 2560
#define CARDANO_MLDSA44_SIGBYTES 2420

#define CARDANO_MLDSA44_SIGNKEY_SEED_OFFSET 0
#define CARDANO_MLDSA44_SIGNKEY_SK_OFFSET CARDANO_MLDSA44_SEEDBYTES
#define CARDANO_MLDSA44_SIGNKEY_PK_OFFSET \
  (CARDANO_MLDSA44_SEEDBYTES + CARDANO_MLDSA44_SECRETKEYBYTES)
#define CARDANO_MLDSA44_SIGNKEYBYTES \
  (CARDANO_MLDSA44_SIGNKEY_PK_OFFSET + CARDANO_MLDSA44_PUBLICKEYBYTES)

/* Expand a 32-byte seed into seed || sk || pk. Returns 0 on success. */
int cardano_mldsa44_signkey_from_seed(
    uint8_t signkey[CARDANO_MLDSA44_SIGNKEYBYTES],
    const uint8_t seed[CARDANO_MLDSA44_SEEDBYTES]);

/* Deterministic ML-DSA-44 signature over m with empty context.
 * Returns 0 on success. */
int cardano_mldsa44_sign(uint8_t sig[CARDANO_MLDSA44_SIGBYTES],
                         const uint8_t *m, size_t mlen,
                         const uint8_t signkey[CARDANO_MLDSA44_SIGNKEYBYTES]);

/* ML-DSA-44 verification with empty context.
 * Returns 0 if the signature is valid, non-zero otherwise. */
int cardano_mldsa44_verify(const uint8_t sig[CARDANO_MLDSA44_SIGBYTES],
                           const uint8_t *m, size_t mlen,
                           const uint8_t pk[CARDANO_MLDSA44_PUBLICKEYBYTES]);

#endif /* CARDANO_MLDSA44_H */
