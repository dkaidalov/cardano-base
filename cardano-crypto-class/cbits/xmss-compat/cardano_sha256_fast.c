/* See cardano_sha256_fast.h. The compression function follows the layout of
 * the public-domain SHA-NI examples (Intel, J. Walton): state kept as the
 * ABEF and CDGH lane pairs the sha256rnds2 instruction expects, message
 * schedule computed four words at a time with sha256msg1/sha256msg2. */
#include <string.h>

#include <sodium.h>

#include "cardano_sha256_fast.h"

#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
#define CARDANO_HAVE_SHANI_CODE 1
#include <cpuid.h>
#include <immintrin.h>
#else
#define CARDANO_HAVE_SHANI_CODE 0
#endif

int cardano_sha256_shani_available(void)
{
#if CARDANO_HAVE_SHANI_CODE
  static int cached = -1;
  if (cached < 0) {
    unsigned a, b, c, d;
    int ok = 0;
    if (__get_cpuid(1, &a, &b, &c, &d)) {
      int ssse3 = (c >> 9) & 1, sse41 = (c >> 19) & 1;
      if (ssse3 && sse41 && __get_cpuid_count(7, 0, &a, &b, &c, &d)) {
        ok = (b >> 29) & 1; /* SHA */
      }
    }
    cached = ok;
  }
  return cached;
#else
  return 0;
#endif
}

#if CARDANO_HAVE_SHANI_CODE

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

__attribute__((target("sha,sse4.1,ssse3")))
static void sha256_shani_blocks(uint32_t state[8], const uint8_t *data, size_t nblocks)
{
  const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);
  __m128i STATE0, STATE1, TMP, ABEF_SAVE, CDGH_SAVE, MSG, W[4];
  int i;

  TMP = _mm_loadu_si128((const __m128i *)&state[0]);
  STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);
  TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
  STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
  STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
  STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */

  while (nblocks--) {
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    for (i = 0; i < 4; i++) {
      W[i] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(data + 16 * i)), MASK);
    }
    for (i = 0; i < 16; i++) {
      MSG = _mm_add_epi32(W[i & 3], _mm_loadu_si128((const __m128i *)&K[4 * i]));
      STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
      MSG = _mm_shuffle_epi32(MSG, 0x0E);
      STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
      if (i < 12) {
        /* W[i+4] = msg2(msg1(W[i], W[i+1]) + (W[i+2], W[i+3] shifted by one word), W[i+3]) */
        TMP = _mm_alignr_epi8(W[(i + 3) & 3], W[(i + 2) & 3], 4);
        W[i & 3] = _mm_sha256msg2_epu32(
            _mm_add_epi32(_mm_sha256msg1_epu32(W[i & 3], W[(i + 1) & 3]), TMP), W[(i + 3) & 3]);
      }
    }

    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);
    data += 64;
  }

  TMP = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
  STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    /* DCHG */
  STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); /* DCBA */
  STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    /* ABEF -> HGFE */
  _mm_storeu_si128((__m128i *)&state[0], STATE0);
  _mm_storeu_si128((__m128i *)&state[4], STATE1);
}

static const uint32_t IV[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                               0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

/* Absorb in[0..len) into state (already holding `done` bytes' worth of
 * complete blocks), pad for a total length of done + len, and write out. */
static void sha256_shani_finish(uint8_t out[32], uint32_t state[8], size_t done,
                                const uint8_t *in, size_t len)
{
  uint8_t last[128];
  size_t full = len & ~(size_t)63, rem = len - full, padlen;
  uint64_t bits = (uint64_t)(done + len) * 8;
  int i;

  if (full) sha256_shani_blocks(state, in, full / 64);
  memcpy(last, in + full, rem);
  last[rem] = 0x80;
  padlen = (rem < 56) ? 64 : 128;
  memset(last + rem + 1, 0, padlen - rem - 1 - 8);
  for (i = 0; i < 8; i++) last[padlen - 1 - i] = (uint8_t)(bits >> (8 * i));
  sha256_shani_blocks(state, last, padlen / 64);
  for (i = 0; i < 8; i++) {
    out[4 * i] = (uint8_t)(state[i] >> 24);
    out[4 * i + 1] = (uint8_t)(state[i] >> 16);
    out[4 * i + 2] = (uint8_t)(state[i] >> 8);
    out[4 * i + 3] = (uint8_t)state[i];
  }
}

void cardano_sha256_shani(uint8_t out[32], const uint8_t *in, size_t len)
{
  uint32_t state[8];
  memcpy(state, IV, sizeof state);
  sha256_shani_finish(out, state, 0, in, len);
}

#else /* !CARDANO_HAVE_SHANI_CODE */

void cardano_sha256_shani(uint8_t out[32], const uint8_t *in, size_t len)
{
  crypto_hash_sha256(out, in, (unsigned long long)len);
}

#endif

void cardano_sha256_fast(uint8_t out[32], const uint8_t *in, size_t len)
{
  if (cardano_sha256_shani_available()) {
    cardano_sha256_shani(out, in, len);
  } else {
    crypto_hash_sha256(out, in, (unsigned long long)len);
  }
}

typedef char cardano_sha256_mid_static_assert
    [sizeof(crypto_hash_sha256_state) <= 104 ? 1 : -1];

void cardano_sha256_mid_init(cardano_sha256_mid *mid, const uint8_t *prefix, size_t prefixlen)
{
  mid->prefixlen = prefixlen;
  mid->shani = cardano_sha256_shani_available();
#if CARDANO_HAVE_SHANI_CODE
  if (mid->shani) {
    memcpy(mid->st, IV, sizeof mid->st);
    if (prefixlen) sha256_shani_blocks(mid->st, prefix, prefixlen / 64);
    return;
  }
#endif
  {
    crypto_hash_sha256_state st;
    crypto_hash_sha256_init(&st);
    crypto_hash_sha256_update(&st, prefix, (unsigned long long)prefixlen);
    memcpy(mid->sodium, &st, sizeof st);
  }
}

void cardano_sha256_mid_finish(uint8_t out[32], const cardano_sha256_mid *mid,
                               const uint8_t *rest, size_t restlen)
{
#if CARDANO_HAVE_SHANI_CODE
  if (mid->shani) {
    uint32_t state[8];
    memcpy(state, mid->st, sizeof state);
    sha256_shani_finish(out, state, mid->prefixlen, rest, restlen);
    return;
  }
#endif
  {
    crypto_hash_sha256_state st;
    memcpy(&st, mid->sodium, sizeof st);
    crypto_hash_sha256_update(&st, rest, (unsigned long long)restlen);
    crypto_hash_sha256_final(&st, out);
  }
}
