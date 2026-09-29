/* See cardano_xmss_mock.h. */
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "cardano_xmss_mock.h"
#include "xmss-reference/params.h"
#include "xmss-reference/xmss_core.h"

/* The BDS core has no seeded key generation: xmss_core_keypair draws
 * SK_SEED || SK_PRF (2n bytes) and PUB_SEED (n bytes) from randombytes().
 * We provide randombytes() and, while a key is being generated on this
 * thread, serve those 3n bytes from the expanded seed instead of libsodium,
 * which makes key generation deterministic. Outside key generation the hook
 * falls through to libsodium. */
static __thread const uint8_t *seed_src = NULL;
static __thread size_t seed_src_left = 0;

void randombytes(unsigned char *x, unsigned long long xlen);
void randombytes(unsigned char *x, unsigned long long xlen)
{
  if (seed_src != NULL && (size_t)xlen <= seed_src_left) {
    memcpy(x, seed_src, (size_t)xlen);
    seed_src += xlen;
    seed_src_left -= (size_t)xlen;
    return;
  }
  randombytes_buf(x, (size_t)xlen);
}

static int get_params(xmss_params *params)
{
  uint32_t oid;
  if (xmss_str_to_oid(&oid, CARDANO_XMSS_MOCK_OID_STRING) != 0) return -1;
  if (xmss_parse_oid(params, oid) != 0) return -1;
  if (params->pk_bytes != CARDANO_XMSS_MOCK_PUBLICKEYBYTES ||
      params->sk_bytes != CARDANO_XMSS_MOCK_SECRETKEYBYTES ||
      params->sig_bytes != CARDANO_XMSS_MOCK_SIGBYTES ||
      params->n != 32) {
    return -1;
  }
  return 0;
}

/* seed96 = SHA256(0x00||seed) || SHA256(0x01||seed) || SHA256(0x02||seed):
 * SK_SEED || SK_PRF || PUB_SEED, n = 32 each. */
static void expand_seed(uint8_t out[96], const uint8_t seed[CARDANO_XMSS_MOCK_SEEDBYTES])
{
  uint8_t buf[1 + CARDANO_XMSS_MOCK_SEEDBYTES];
  memcpy(buf + 1, seed, CARDANO_XMSS_MOCK_SEEDBYTES);
  buf[0] = 0;
  crypto_hash_sha256(out, buf, sizeof buf);
  buf[0] = 1;
  crypto_hash_sha256(out + 32, buf, sizeof buf);
  buf[0] = 2;
  crypto_hash_sha256(out + 64, buf, sizeof buf);
  sodium_memzero(buf, sizeof buf);
}

int cardano_xmss_mock_signkey_from_seed(
    uint8_t signkey[CARDANO_XMSS_MOCK_SIGNKEYBYTES],
    const uint8_t seed[CARDANO_XMSS_MOCK_SEEDBYTES])
{
  xmss_params params;
  uint8_t tmp[CARDANO_XMSS_MOCK_SEEDBYTES];
  uint8_t seed96[96]; /* 3 * n */
  int rc;
  if (get_params(&params) != 0) return -1;
  memcpy(tmp, seed, sizeof tmp); /* seed may alias the destination */
  memcpy(signkey + CARDANO_XMSS_MOCK_SIGNKEY_SEED_OFFSET, tmp, sizeof tmp);
  expand_seed(seed96, tmp);
  seed_src = seed96;
  seed_src_left = sizeof seed96;
  rc = xmss_core_keypair(&params, signkey + CARDANO_XMSS_MOCK_SIGNKEY_PK_OFFSET,
                         signkey + CARDANO_XMSS_MOCK_SIGNKEY_SK_OFFSET);
  if (rc == 0 && seed_src_left != 0) rc = -1; /* the core drew fewer bytes than expected */
  seed_src = NULL;
  seed_src_left = 0;
  sodium_memzero(tmp, sizeof tmp);
  sodium_memzero(seed96, sizeof seed96);
  return rc;
}

static int sign_with(uint8_t *sig, const uint8_t *m, size_t mlen, uint8_t *sk)
{
  xmss_params params;
  unsigned long long smlen = 0;
  uint8_t *sm;
  uint32_t idx;
  int rc;
  if (get_params(&params) != 0) return -1;
  /* The reference wipes the key when idx == 2^h - 1 and then signs with the
   * wiped material, so that signature is invalid. Refuse it here. */
  idx = ((uint32_t)sk[0] << 24) | ((uint32_t)sk[1] << 16) | ((uint32_t)sk[2] << 8) | sk[3];
  if (idx >= CARDANO_XMSS_MOCK_MAX_SIGNATURES) return -2;
  sm = malloc(CARDANO_XMSS_MOCK_SIGBYTES + mlen);
  if (sm == NULL) return -1;
  rc = xmss_core_sign(&params, sk, sm, &smlen, m, (unsigned long long)mlen);
  if (rc == 0) {
    if (smlen != CARDANO_XMSS_MOCK_SIGBYTES + mlen) rc = -1;
    else memcpy(sig, sm, CARDANO_XMSS_MOCK_SIGBYTES);
  }
  sodium_memzero(sm, CARDANO_XMSS_MOCK_SIGBYTES + mlen);
  free(sm);
  return rc;
}

int cardano_xmss_mock_sign_advance(uint8_t sig[CARDANO_XMSS_MOCK_SIGBYTES],
                                   const uint8_t *m, size_t mlen,
                                   uint8_t signkey[CARDANO_XMSS_MOCK_SIGNKEYBYTES])
{
  return sign_with(sig, m, mlen, signkey + CARDANO_XMSS_MOCK_SIGNKEY_SK_OFFSET);
}

int cardano_xmss_mock_sign_copy(uint8_t sig[CARDANO_XMSS_MOCK_SIGBYTES],
                                const uint8_t *m, size_t mlen,
                                const uint8_t signkey[CARDANO_XMSS_MOCK_SIGNKEYBYTES])
{
  uint8_t sk[CARDANO_XMSS_MOCK_SECRETKEYBYTES];
  int rc;
  memcpy(sk, signkey + CARDANO_XMSS_MOCK_SIGNKEY_SK_OFFSET, sizeof sk);
  rc = sign_with(sig, m, mlen, sk);
  sodium_memzero(sk, sizeof sk);
  return rc;
}

int cardano_xmss_mock_verify(const uint8_t sig[CARDANO_XMSS_MOCK_SIGBYTES],
                             const uint8_t *m, size_t mlen,
                             const uint8_t pk[CARDANO_XMSS_MOCK_PUBLICKEYBYTES])
{
  xmss_params params;
  unsigned long long mlen_out = 0;
  uint8_t *sm, *mout;
  int rc;
  if (get_params(&params) != 0) return -1;
  sm = malloc(CARDANO_XMSS_MOCK_SIGBYTES + mlen);
  mout = malloc(CARDANO_XMSS_MOCK_SIGBYTES + mlen);
  if (sm == NULL || mout == NULL) { free(sm); free(mout); return -1; }
  memcpy(sm, sig, CARDANO_XMSS_MOCK_SIGBYTES);
  memcpy(sm + CARDANO_XMSS_MOCK_SIGBYTES, m, mlen);
  rc = xmss_core_sign_open(&params, mout, &mlen_out, sm, CARDANO_XMSS_MOCK_SIGBYTES + mlen, pk);
  if (rc == 0 && (mlen_out != mlen || memcmp(mout, m, mlen) != 0)) rc = -1;
  free(sm);
  free(mout);
  return rc;
}
