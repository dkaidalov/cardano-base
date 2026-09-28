/*
 * XMSS-SHA2_10_192 (RFC 8391, SP 800-208) over the XMSS reference
 * implementation (cbits/xmss-reference, BDS tree traversal), wrapped for the
 * BENCHMARK-ONLY stateful leaf Cardano.Crypto.DSIGN.XmssMock.
 *
 * XMSS is stateful: every signature consumes one of the 2^10 one-time keys,
 * and the reference keeps the next index and the BDS traversal state inside
 * the secret key, advancing them on each signature. This wrapper exposes
 * that as two signing entry points:
 *
 *   sign_advance: signs and advances the state in place (used by the
 *                 mlocked signDSIGNM);
 *   sign_copy:    signs on a copy of the state and leaves the key untouched
 *                 (used by the pure signDSIGN, which cannot return a new
 *                 key). Repeated calls REUSE the same one-time key. This is
 *                 what makes the scheme a mock: it exists to measure cost,
 *                 not to be deployed.
 *
 * A key yields 2^10 - 1 = 1023 signatures. The reference wipes the key in
 * memory when the index reaches 2^10 - 1 but does so before signing, so its
 * 1024th signature is invalid; this wrapper refuses it instead (return -2).
 * The in-memory sign key is seed || sk || pk; only the seed is serialised,
 * so a deserialised key restarts at index 0.
 */
#ifndef CARDANO_XMSS_MOCK_H
#define CARDANO_XMSS_MOCK_H

#include <stddef.h>
#include <stdint.h>

#define CARDANO_XMSS_MOCK_OID_STRING "XMSS-SHA2_10_192"
#define CARDANO_XMSS_MOCK_SEEDBYTES 32
#define CARDANO_XMSS_MOCK_PUBLICKEYBYTES 48
#define CARDANO_XMSS_MOCK_SECRETKEYBYTES 1053
#define CARDANO_XMSS_MOCK_SIGBYTES 1492
#define CARDANO_XMSS_MOCK_MAX_SIGNATURES 1023

#define CARDANO_XMSS_MOCK_SIGNKEY_SEED_OFFSET 0
#define CARDANO_XMSS_MOCK_SIGNKEY_SK_OFFSET CARDANO_XMSS_MOCK_SEEDBYTES
#define CARDANO_XMSS_MOCK_SIGNKEY_PK_OFFSET \
  (CARDANO_XMSS_MOCK_SEEDBYTES + CARDANO_XMSS_MOCK_SECRETKEYBYTES)
#define CARDANO_XMSS_MOCK_SIGNKEYBYTES \
  (CARDANO_XMSS_MOCK_SIGNKEY_PK_OFFSET + CARDANO_XMSS_MOCK_PUBLICKEYBYTES)

int cardano_xmss_mock_signkey_from_seed(
    uint8_t signkey[CARDANO_XMSS_MOCK_SIGNKEYBYTES],
    const uint8_t seed[CARDANO_XMSS_MOCK_SEEDBYTES]);

/* Signs and advances the one-time index and BDS state inside signkey.
 * Returns 0 on success, -2 when the key is exhausted, -1 otherwise. */
int cardano_xmss_mock_sign_advance(uint8_t sig[CARDANO_XMSS_MOCK_SIGBYTES],
                                   const uint8_t *m, size_t mlen,
                                   uint8_t signkey[CARDANO_XMSS_MOCK_SIGNKEYBYTES]);

/* Signs with the current one-time key on a copy of the state; signkey is
 * left unchanged. Same return values. */
int cardano_xmss_mock_sign_copy(uint8_t sig[CARDANO_XMSS_MOCK_SIGBYTES],
                                const uint8_t *m, size_t mlen,
                                const uint8_t signkey[CARDANO_XMSS_MOCK_SIGNKEYBYTES]);

int cardano_xmss_mock_verify(const uint8_t sig[CARDANO_XMSS_MOCK_SIGBYTES],
                             const uint8_t *m, size_t mlen,
                             const uint8_t pk[CARDANO_XMSS_MOCK_PUBLICKEYBYTES]);

#endif /* CARDANO_XMSS_MOCK_H */
