/*
 * Reduced-budget SLH-DSA parameter set "bb-6" (Fluhrer-Dang 2024, Appendix C,
 * 2^10 signatures per key): n = 16, h = 9, d = 1, FORS 11 trees of height 14,
 * w = 16, SHA2-simple. Signature 3360 bytes. Added for cardano-crypto-class;
 * not part of upstream sphincsplus. Everything below SPX_WOTS_W is copied
 * from params-sphincs-sha2-128f.h.
 */
#ifndef SPX_PARAMS_H
#define SPX_PARAMS_H

#define SPX_NAMESPACE(s) cardano_slh_bb6_##s

/* sha2.h declares these without SPX_NAMESPACE; every translation unit
 * includes params.h before sha2.h, so renaming them here keeps the library's
 * SHA-2 symbols out of the global namespace. */
#define sha256_inc_init SPX_NAMESPACE(sha256_inc_init)
#define sha256_inc_blocks SPX_NAMESPACE(sha256_inc_blocks)
#define sha256_inc_finalize SPX_NAMESPACE(sha256_inc_finalize)
#define sha256 SPX_NAMESPACE(sha256)
#define sha512_inc_init SPX_NAMESPACE(sha512_inc_init)
#define sha512_inc_blocks SPX_NAMESPACE(sha512_inc_blocks)
#define sha512_inc_finalize SPX_NAMESPACE(sha512_inc_finalize)
#define sha512 SPX_NAMESPACE(sha512)

/* Hash output length in bytes. */
#define SPX_N 16
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 9
/* Number of subtree layer. */
#define SPX_D 1
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 14
#define SPX_FORS_TREES 11
/* Winternitz parameter, */
#define SPX_WOTS_W 16

#define SPX_SHA512 0  /* Use SHA-256 for all hashes */

#define SPX_ADDR_BYTES 32

#if SPX_WOTS_W == 256
    #define SPX_WOTS_LOGW 8
#elif SPX_WOTS_W == 16
    #define SPX_WOTS_LOGW 4
#else
    #error SPX_WOTS_W assumed 16 or 256
#endif

#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)

#if SPX_WOTS_W == 256
    #if SPX_N <= 1
        #define SPX_WOTS_LEN2 1
    #elif SPX_N <= 256
        #define SPX_WOTS_LEN2 2
    #else
        #error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
    #endif
#elif SPX_WOTS_W == 16
    #if SPX_N <= 8
        #define SPX_WOTS_LEN2 2
    #elif SPX_N <= 136
        #define SPX_WOTS_LEN2 3
    #elif SPX_N <= 256
        #define SPX_WOTS_LEN2 4
    #else
        #error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
    #endif
#endif

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
    #error SPX_D should always divide SPX_FULL_HEIGHT
#endif

#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES +\
                   SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

#include "../sha2_offsets.h"

#endif
