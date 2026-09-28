/*
 * See cardano_mldsa44.h. Compiled with
 *   -DMLD_CONFIG_PARAMETER_SET=44
 *   -DMLD_CONFIG_NAMESPACE_PREFIX=cardano_mld
 *   -DMLD_CONFIG_NO_RANDOMIZED_API
 * (see cardano-crypto-class.cabal), the same flags used for
 * cbits/mldsa-native/mldsa_native.c.
 */
#include <string.h>

#include "cardano_mldsa44.h"
#include "mldsa_native.h"

#if MLD_CONFIG_PARAMETER_SET != 44
#error "cardano_mldsa44.c must be compiled with MLD_CONFIG_PARAMETER_SET=44"
#endif

typedef char cardano_mldsa44_static_assert_seed
    [CARDANO_MLDSA44_SEEDBYTES == MLDSA_SEEDBYTES ? 1 : -1];
typedef char cardano_mldsa44_static_assert_pk
    [CARDANO_MLDSA44_PUBLICKEYBYTES == MLDSA44_PUBLICKEYBYTES ? 1 : -1];
typedef char cardano_mldsa44_static_assert_sk
    [CARDANO_MLDSA44_SECRETKEYBYTES == MLDSA44_SECRETKEYBYTES ? 1 : -1];
typedef char cardano_mldsa44_static_assert_sig
    [CARDANO_MLDSA44_SIGBYTES == MLDSA44_BYTES ? 1 : -1];

int cardano_mldsa44_signkey_from_seed(
    uint8_t signkey[CARDANO_MLDSA44_SIGNKEYBYTES],
    const uint8_t seed[CARDANO_MLDSA44_SEEDBYTES])
{
  /* seed may alias the destination's seed slot; copy via a temporary. */
  uint8_t tmp[CARDANO_MLDSA44_SEEDBYTES];
  int rc;
  memcpy(tmp, seed, CARDANO_MLDSA44_SEEDBYTES);
  memcpy(signkey + CARDANO_MLDSA44_SIGNKEY_SEED_OFFSET, tmp,
         CARDANO_MLDSA44_SEEDBYTES);
  rc = cardano_mld_keypair_internal(
      signkey + CARDANO_MLDSA44_SIGNKEY_PK_OFFSET,
      signkey + CARDANO_MLDSA44_SIGNKEY_SK_OFFSET, tmp);
  memset(tmp, 0, sizeof tmp);
  return rc;
}

int cardano_mldsa44_sign(uint8_t sig[CARDANO_MLDSA44_SIGBYTES],
                         const uint8_t *m, size_t mlen,
                         const uint8_t signkey[CARDANO_MLDSA44_SIGNKEYBYTES])
{
  /* FIPS 204 Algorithm 2, deterministic variant: rnd = 0^32.
   * Pure ML-DSA domain separation prefix with empty context:
   * 0x00 || ctxlen (0x00). */
  static const uint8_t rnd[MLDSA_RNDBYTES] = {0};
  static const uint8_t pre[2] = {0x00, 0x00};
  return cardano_mld_signature_internal(
      sig, m, mlen, pre, sizeof pre, rnd,
      signkey + CARDANO_MLDSA44_SIGNKEY_SK_OFFSET, 0);
}

int cardano_mldsa44_verify(const uint8_t sig[CARDANO_MLDSA44_SIGBYTES],
                           const uint8_t *m, size_t mlen,
                           const uint8_t pk[CARDANO_MLDSA44_PUBLICKEYBYTES])
{
  return cardano_mld_verify(sig, m, mlen, NULL, 0, pk);
}
