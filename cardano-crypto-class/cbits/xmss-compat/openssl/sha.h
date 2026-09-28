/*
 * Stand-in for <openssl/sha.h> used by cbits/xmss-reference/hash.c: the two
 * one-shot functions it calls, implemented over libsodium, so that
 * cardano-crypto-class does not depend on OpenSSL. This directory is only on
 * the include path of this library's C sources.
 */
#ifndef CARDANO_XMSS_COMPAT_OPENSSL_SHA_H
#define CARDANO_XMSS_COMPAT_OPENSSL_SHA_H

#include <stddef.h>
#include <sodium.h>

static inline unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md)
{
  crypto_hash_sha256(md, d, (unsigned long long)n);
  return md;
}

static inline unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md)
{
  crypto_hash_sha512(md, d, (unsigned long long)n);
  return md;
}

#endif
