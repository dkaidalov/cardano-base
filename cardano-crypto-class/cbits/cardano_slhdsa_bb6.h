/*
 * Thin wrapper over the SPHINCS+ reference implementation
 * (cbits/sphincsplus-ref) built with the reduced-budget SLH-DSA parameter set
 * "bb-6" (cbits/sphincsplus-ref/params/params-cardano-bb6.h): n = 16, h = 9,
 * d = 1, FORS 11 x 2^14, w = 16, SHA2-simple. Sized for a signer that issues
 * up to 2^10 signatures per key, which is what a KES period needs.
 *
 * The 32-byte seed is expanded to the scheme's 48-byte seed with SHA-256.
 * Signing is the deterministic variant (FIPS 205: opt_rand = PK.seed).
 * The in-memory sign key is seed || sk || pk; only the seed is serialised.
 */
#ifndef CARDANO_SLHDSA_BB6_H
#define CARDANO_SLHDSA_BB6_H

#include <stddef.h>
#include <stdint.h>

#define CARDANO_SLHDSA_BB6_SEEDBYTES 32
#define CARDANO_SLHDSA_BB6_PUBLICKEYBYTES 32
#define CARDANO_SLHDSA_BB6_SECRETKEYBYTES 64
#define CARDANO_SLHDSA_BB6_SIGBYTES 3360

#define CARDANO_SLHDSA_BB6_SIGNKEY_SEED_OFFSET 0
#define CARDANO_SLHDSA_BB6_SIGNKEY_SK_OFFSET CARDANO_SLHDSA_BB6_SEEDBYTES
#define CARDANO_SLHDSA_BB6_SIGNKEY_PK_OFFSET \
  (CARDANO_SLHDSA_BB6_SEEDBYTES + CARDANO_SLHDSA_BB6_SECRETKEYBYTES)
#define CARDANO_SLHDSA_BB6_SIGNKEYBYTES \
  (CARDANO_SLHDSA_BB6_SIGNKEY_PK_OFFSET + CARDANO_SLHDSA_BB6_PUBLICKEYBYTES)

int cardano_slhdsa_bb6_signkey_from_seed(
    uint8_t signkey[CARDANO_SLHDSA_BB6_SIGNKEYBYTES],
    const uint8_t seed[CARDANO_SLHDSA_BB6_SEEDBYTES]);

int cardano_slhdsa_bb6_sign(uint8_t sig[CARDANO_SLHDSA_BB6_SIGBYTES],
                            const uint8_t *m, size_t mlen,
                            const uint8_t signkey[CARDANO_SLHDSA_BB6_SIGNKEYBYTES]);

int cardano_slhdsa_bb6_verify(const uint8_t sig[CARDANO_SLHDSA_BB6_SIGBYTES],
                              const uint8_t *m, size_t mlen,
                              const uint8_t pk[CARDANO_SLHDSA_BB6_PUBLICKEYBYTES]);

#endif /* CARDANO_SLHDSA_BB6_H */
