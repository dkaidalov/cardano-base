/*
 * Stand-in for <openssl/sha.h> used by cbits/xmss-reference/hash.c: the two
 * one-shot functions it calls, implemented over libsodium, so that
 * cardano-crypto-class does not depend on OpenSSL. This directory is only on
 * the include path of this library's C sources.
 *
 * With CARDANO_XMSS_SHANI defined (the pq-native-backends flag), SHA256()
 * goes through cardano_sha256_fast(), which uses the x86 SHA extensions when
 * the CPU has them and libsodium otherwise. The XMSS reference makes one
 * SHA-256 call per hash, so this is where most of its time goes.
 */
#ifndef CARDANO_XMSS_COMPAT_OPENSSL_SHA_H
#define CARDANO_XMSS_COMPAT_OPENSSL_SHA_H

#include <stddef.h>
#include <sodium.h>

#if defined(CARDANO_XMSS_SHANI)
#include "cardano_sha256_fast.h"
#endif

static inline unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
#if defined(CARDANO_XMSS_SHANI)
  cardano_sha256_fast(md, d, n);
#else
  crypto_hash_sha256(md, d, (unsigned long long)n);
#endif
  return md;
}

static inline unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md)
{
  crypto_hash_sha512(md, d, (unsigned long long)n);
  return md;
}

#endif
