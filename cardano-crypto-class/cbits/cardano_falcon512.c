/*
 * See cardano_falcon512.h. The key encoding, signing loop and verification
 * follow PQClean's pqclean.c for falcon-padded-512, with the two
 * randombytes() calls replaced by seed-derived values, so that pqclean.c
 * itself (and PQClean's randombytes) need not be compiled.
 */
#include <string.h>

#include "cardano_falcon512.h"
#include "api.h"
#include "inner.h"

#define LOGN 9
#define N 512
#define NONCELEN 40
#define SAMPLER_SEEDLEN 48

#if defined(CARDANO_FALCON512_AVX2)
#define F(name) PQCLEAN_FALCONPADDED512_AVX2_##name
#else
#define F(name) PQCLEAN_FALCONPADDED512_CLEAN_##name
#endif

typedef char cardano_falcon512_static_assert_pk
    [CARDANO_FALCON512_PUBLICKEYBYTES == F(CRYPTO_PUBLICKEYBYTES) ? 1 : -1];
typedef char cardano_falcon512_static_assert_sk
    [CARDANO_FALCON512_SECRETKEYBYTES == F(CRYPTO_SECRETKEYBYTES) ? 1 : -1];
typedef char cardano_falcon512_static_assert_sig
    [CARDANO_FALCON512_SIGBYTES == F(CRYPTO_BYTES) ? 1 : -1];

static const uint8_t det_domain[] = "cardano-falcon512-deterministic-v1";

/* Key pair from a seed: PQClean's crypto_sign_keypair with the 48 random
 * bytes replaced by our 32-byte seed as the SHAKE256 input. */
static int keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t *seed)
{
  union {
    uint8_t b[FALCON_KEYGEN_TEMP_9];
    uint64_t dummy_u64;
    fpr dummy_fpr;
  } tmp;
  int8_t f[N], g[N], Fp[N];
  uint16_t h[N];
  inner_shake256_context rng;
  size_t u, v;

  inner_shake256_init(&rng);
  inner_shake256_inject(&rng, seed, CARDANO_FALCON512_SEEDBYTES);
  inner_shake256_flip(&rng);
  F(keygen)(&rng, f, g, Fp, NULL, h, LOGN, tmp.b);
  inner_shake256_ctx_release(&rng);

  sk[0] = 0x50 + LOGN;
  u = 1;
  v = F(trim_i8_encode)(sk + u, F(CRYPTO_SECRETKEYBYTES) - u, f, LOGN, F(max_fg_bits)[LOGN]);
  if (v == 0) return -1;
  u += v;
  v = F(trim_i8_encode)(sk + u, F(CRYPTO_SECRETKEYBYTES) - u, g, LOGN, F(max_fg_bits)[LOGN]);
  if (v == 0) return -1;
  u += v;
  v = F(trim_i8_encode)(sk + u, F(CRYPTO_SECRETKEYBYTES) - u, Fp, LOGN, F(max_FG_bits)[LOGN]);
  if (v == 0) return -1;
  u += v;
  if (u != F(CRYPTO_SECRETKEYBYTES)) return -1;

  pk[0] = 0x00 + LOGN;
  v = F(modq_encode)(pk + 1, F(CRYPTO_PUBLICKEYBYTES) - 1, h, LOGN);
  if (v != F(CRYPTO_PUBLICKEYBYTES) - 1) return -1;
  return 0;
}

int cardano_falcon512_signkey_from_seed(
    uint8_t signkey[CARDANO_FALCON512_SIGNKEYBYTES],
    const uint8_t seed[CARDANO_FALCON512_SEEDBYTES])
{
  uint8_t tmp[CARDANO_FALCON512_SEEDBYTES];
  int rc;
  memcpy(tmp, seed, sizeof tmp); /* seed may alias the destination */
  memcpy(signkey + CARDANO_FALCON512_SIGNKEY_SEED_OFFSET, tmp, sizeof tmp);
  rc = keypair_from_seed(signkey + CARDANO_FALCON512_SIGNKEY_PK_OFFSET,
                         signkey + CARDANO_FALCON512_SIGNKEY_SK_OFFSET, tmp);
  memset(tmp, 0, sizeof tmp);
  return rc;
}

/* PQClean's do_sign with nonce and sampler seed derived from (sk, m). */
static int do_sign(uint8_t *nonce, uint8_t *sigbuf, size_t sigbuflen,
                   const uint8_t *m, size_t mlen, const uint8_t *sk)
{
  union {
    uint8_t b[72 * N];
    uint64_t dummy_u64;
    fpr dummy_fpr;
  } tmp;
  int8_t f[N], g[N], Fp[N], G[N];
  struct {
    int16_t sig[N];
    uint16_t hm[N];
  } r;
  uint8_t derived[NONCELEN + SAMPLER_SEEDLEN];
  inner_shake256_context sc;
  size_t u, v;

  if (sk[0] != 0x50 + LOGN) return -1;
  u = 1;
  v = F(trim_i8_decode)(f, LOGN, F(max_fg_bits)[LOGN], sk + u, F(CRYPTO_SECRETKEYBYTES) - u);
  if (v == 0) return -1;
  u += v;
  v = F(trim_i8_decode)(g, LOGN, F(max_fg_bits)[LOGN], sk + u, F(CRYPTO_SECRETKEYBYTES) - u);
  if (v == 0) return -1;
  u += v;
  v = F(trim_i8_decode)(Fp, LOGN, F(max_FG_bits)[LOGN], sk + u, F(CRYPTO_SECRETKEYBYTES) - u);
  if (v == 0) return -1;
  u += v;
  if (u != F(CRYPTO_SECRETKEYBYTES)) return -1;
  if (!F(complete_private)(G, f, g, Fp, LOGN, tmp.b)) return -1;

  /* nonce || sampler seed = SHAKE256(domain || sk || m) */
  inner_shake256_init(&sc);
  inner_shake256_inject(&sc, det_domain, sizeof det_domain);
  inner_shake256_inject(&sc, sk, F(CRYPTO_SECRETKEYBYTES));
  inner_shake256_inject(&sc, m, mlen);
  inner_shake256_flip(&sc);
  inner_shake256_extract(&sc, derived, sizeof derived);
  inner_shake256_ctx_release(&sc);
  memcpy(nonce, derived, NONCELEN);

  /* Hash nonce + message into a vector. */
  inner_shake256_init(&sc);
  inner_shake256_inject(&sc, nonce, NONCELEN);
  inner_shake256_inject(&sc, m, mlen);
  inner_shake256_flip(&sc);
  F(hash_to_point_ct)(&sc, r.hm, LOGN, tmp.b);
  inner_shake256_ctx_release(&sc);

  /* Sampler RNG. */
  inner_shake256_init(&sc);
  inner_shake256_inject(&sc, derived + NONCELEN, SAMPLER_SEEDLEN);
  inner_shake256_flip(&sc);
  memset(derived, 0, sizeof derived);

  for (;;) {
    F(sign_dyn)(r.sig, &sc, f, g, Fp, G, r.hm, LOGN, tmp.b);
    v = F(comp_encode)(sigbuf, sigbuflen, r.sig, LOGN);
    if (v != 0) {
      inner_shake256_ctx_release(&sc);
      memset(sigbuf + v, 0, sigbuflen - v);
      return 0;
    }
  }
}

int cardano_falcon512_sign(uint8_t sig[CARDANO_FALCON512_SIGBYTES],
                           const uint8_t *m, size_t mlen,
                           const uint8_t signkey[CARDANO_FALCON512_SIGNKEYBYTES])
{
  size_t vlen = F(CRYPTO_BYTES) - NONCELEN - 1;
  if (do_sign(sig + 1, sig + 1 + NONCELEN, vlen, m, mlen,
              signkey + CARDANO_FALCON512_SIGNKEY_SK_OFFSET) < 0) {
    return -1;
  }
  sig[0] = 0x30 + LOGN;
  return 0;
}

/* PQClean's do_verify, unchanged in substance. */
static int do_verify(const uint8_t *nonce, const uint8_t *sigbuf, size_t sigbuflen,
                     const uint8_t *m, size_t mlen, const uint8_t *pk)
{
  union {
    uint8_t b[2 * N];
    uint64_t dummy_u64;
    fpr dummy_fpr;
  } tmp;
  uint16_t h[N], hm[N];
  int16_t sig[N];
  inner_shake256_context sc;
  size_t v;

  if (pk[0] != 0x00 + LOGN) return -1;
  if (F(modq_decode)(h, LOGN, pk + 1, F(CRYPTO_PUBLICKEYBYTES) - 1)
      != F(CRYPTO_PUBLICKEYBYTES) - 1) {
    return -1;
  }
  F(to_ntt_monty)(h, LOGN);

  if (sigbuflen == 0) return -1;
  v = F(comp_decode)(sig, LOGN, sigbuf, sigbuflen);
  if (v == 0) return -1;
  if (v != sigbuflen) {
    if (sigbuflen == F(CRYPTO_BYTES) - NONCELEN - 1) {
      while (v < sigbuflen) {
        if (sigbuf[v++] != 0) return -1;
      }
    } else {
      return -1;
    }
  }

  inner_shake256_init(&sc);
  inner_shake256_inject(&sc, nonce, NONCELEN);
  inner_shake256_inject(&sc, m, mlen);
  inner_shake256_flip(&sc);
  F(hash_to_point_ct)(&sc, hm, LOGN, tmp.b);
  inner_shake256_ctx_release(&sc);

  if (!F(verify_raw)(hm, sig, h, LOGN, tmp.b)) return -1;
  return 0;
}

int cardano_falcon512_verify(const uint8_t sig[CARDANO_FALCON512_SIGBYTES],
                             const uint8_t *m, size_t mlen,
                             const uint8_t pk[CARDANO_FALCON512_PUBLICKEYBYTES])
{
  if (sig[0] != 0x30 + LOGN) return -1;
  return do_verify(sig + 1, sig + 1 + NONCELEN, F(CRYPTO_BYTES) - 1 - NONCELEN, m, mlen, pk);
}
