/*
 * Thin wrapper over PQClean's falcon-padded-512 (cbits/falcon-padded-512)
 * for the Falcon-512 DSIGN instance in Cardano.Crypto.DSIGN.Falcon512.
 *
 * Key generation is derived from a 32-byte seed (the seed is absorbed into
 * the SHAKE256 that drives PQClean's keygen). Signing is deterministic: the
 * 40-byte nonce and the 48-byte sampler seed are both derived from
 * SHAKE256(domain || sk || m). Falcon as specified draws both at random;
 * the deterministic derivation keeps the pure DSIGN API honest and does not
 * change signing or verification cost. Signatures use the padded,
 * fixed-length encoding (666 bytes).
 *
 * The in-memory sign key is seed || sk || pk; only the seed is serialised.
 */
#ifndef CARDANO_FALCON512_H
#define CARDANO_FALCON512_H

#include <stddef.h>
#include <stdint.h>

#define CARDANO_FALCON512_SEEDBYTES 32
#define CARDANO_FALCON512_PUBLICKEYBYTES 897
#define CARDANO_FALCON512_SECRETKEYBYTES 1281
#define CARDANO_FALCON512_SIGBYTES 666

#define CARDANO_FALCON512_SIGNKEY_SEED_OFFSET 0
#define CARDANO_FALCON512_SIGNKEY_SK_OFFSET CARDANO_FALCON512_SEEDBYTES
#define CARDANO_FALCON512_SIGNKEY_PK_OFFSET \
  (CARDANO_FALCON512_SEEDBYTES + CARDANO_FALCON512_SECRETKEYBYTES)
#define CARDANO_FALCON512_SIGNKEYBYTES \
  (CARDANO_FALCON512_SIGNKEY_PK_OFFSET + CARDANO_FALCON512_PUBLICKEYBYTES)

int cardano_falcon512_signkey_from_seed(
    uint8_t signkey[CARDANO_FALCON512_SIGNKEYBYTES],
    const uint8_t seed[CARDANO_FALCON512_SEEDBYTES]);

int cardano_falcon512_sign(uint8_t sig[CARDANO_FALCON512_SIGBYTES],
                           const uint8_t *m, size_t mlen,
                           const uint8_t signkey[CARDANO_FALCON512_SIGNKEYBYTES]);

int cardano_falcon512_verify(const uint8_t sig[CARDANO_FALCON512_SIGBYTES],
                             const uint8_t *m, size_t mlen,
                             const uint8_t pk[CARDANO_FALCON512_PUBLICKEYBYTES]);

#endif /* CARDANO_FALCON512_H */
